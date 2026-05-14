"""
Expansion engine — feedback-driven loop fuzzing on confirmed crash frames.

Takes a .bin crash artifact as SEED, identifies which protocol fields
to mutate, generates variants using multiple strategies, and re-injects.
New crashes become new seeds (breadth-first expansion). Runs until budget
(max frame count) is exhausted.

This is the AFL-style "mutate → feedback → expand" loop, applied to
already-confirmed interesting protocol fields.

Mutation strategies (per field):
  1. random        — random bytes for the field
  2. increment     — seed_value + 1,2,3,...,N
  3. boundary_arith — seed_value ± 1,2,4,8,16,32,64,128
  4. bit_flip      — flip each bit of the field value
  5. byte_boundary — 0x00,0x01,0x7F,0x80,0xFE,0xFF per byte
  6. havoc         — random bytes at random frame offsets (model-agnostic)
  7. sweep         — exhaustive sweep 0..2^(width*8)-1 (for small fields)

Field location (frame-aware):
  For known frame types (AssocReq, Auth, HE-IE AssocReq), the engine
  parses the frame and locates the exact byte offsets of protocol fields.
  Falls back to havoc (model-agnostic) for unknown frame types.
"""
from __future__ import annotations

import os
import random
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterator, List, Optional, Tuple


# ── Frame field descriptors ────────────────────────────────────────────────────

@dataclass
class FieldDescriptor:
    """Describes a mutable protocol field within a raw 802.11 frame."""
    name:          str
    offset:        int         # byte offset within frame
    width:         int         # field width in bytes
    seed_value:    int = 0     # original value from crash frame
    max_value:     int = 0     # 2^(width*8) - 1
    byteorder:     str = 'little'  # or 'big'

    def __post_init__(self):
        if not self.max_value:
            self.max_value = (1 << (self.width * 8)) - 1

    def read(self, frame: bytes) -> int:
        if self.offset + self.width > len(frame):
            return 0
        return int.from_bytes(frame[self.offset:self.offset+self.width],
                               self.byteorder)

    def write(self, frame: bytearray, value: int) -> bytearray:
        value = value & self.max_value
        frame[self.offset:self.offset+self.width] = \
            value.to_bytes(self.width, self.byteorder)
        return frame


# ── Frame parsing — locate fields in crash frames ─────────────────────────────

def _fc_parse(data: bytes) -> Tuple[int, int]:
    """Return (type, subtype) from FC bytes."""
    if len(data) < 2:
        return -1, -1
    fc = struct.unpack_from('<H', data, 0)[0]
    return (fc >> 2) & 0x3, (fc >> 4) & 0xF


def _find_ie(data: bytes, target_tag: int, frame_body_start: int = 28) -> Optional[int]:
    """Return byte offset of IE with given tag in frame. None if not found."""
    i = frame_body_start
    while i < len(data) - 1:
        tag    = data[i]
        length = data[i + 1]
        actual = min(length, len(data) - i - 2)
        if tag == target_tag:
            return i
        i += 2 + actual
        if actual < length:
            break
    return None


def locate_fields(frame: bytes) -> List[FieldDescriptor]:
    """
    Parse crash frame and return list of FieldDescriptors for mutable fields.

    Supported frame types:
      AssocReq (0/0):   RSN IE version, group_cipher, pairwise_count,
                        akm_count, rsn_caps, IE length byte
      ReassocReq (0/2): same, body starts 10B later
      Auth (0/11):      auth_algo [2B], auth_seq [2B]
      HE IE AssocReq:   HE IE body bytes

    Falls back to empty list (triggers havoc mode) for unknown types.
    """
    fields = []
    ftype, fsub = _fc_parse(frame)

    # ── AssocReq / ReassocReq ─────────────────────────────────────────────────
    if ftype == 0 and fsub in (0, 2):
        # body = 24(dot11) + 2(capinfo) + 2(listenint) [+ 10(reassoc)] + IEs
        body_start = 24 + 4 + (10 if fsub == 2 else 0)

        # RSN IE (tag=48)
        rsn_off = _find_ie(frame, 48, body_start)
        if rsn_off is not None:
            ie_len_off = rsn_off + 1         # the IE length byte
            body_off   = rsn_off + 2         # first byte of IE body

            # IE length field itself (claiming more = over-read)
            fields.append(FieldDescriptor(
                name='RSN IE length', offset=ie_len_off, width=1,
                seed_value=frame[ie_len_off] if ie_len_off < len(frame) else 0,
                byteorder='little',
            ))

            # RSN version [2B] at body_off+0
            if body_off + 2 <= len(frame):
                fields.append(FieldDescriptor(
                    name='RSN version', offset=body_off, width=2,
                    seed_value=struct.unpack_from('<H', frame, body_off)[0],
                    byteorder='little',
                ))

            # Group cipher OUI[3] + type[1] at body_off+2
            if body_off + 6 <= len(frame):
                fields.append(FieldDescriptor(
                    name='RSN group_cipher', offset=body_off+2, width=4,
                    seed_value=struct.unpack_from('>I', frame, body_off+2)[0],
                    byteorder='big',
                ))

            # Pairwise count [2B] at body_off+6
            if body_off + 8 <= len(frame):
                fields.append(FieldDescriptor(
                    name='RSN pairwise_count', offset=body_off+6, width=2,
                    seed_value=struct.unpack_from('<H', frame, body_off+6)[0],
                ))

            # AKM count [2B] at body_off+6+2+4*pc
            offset = body_off + 6
            if offset + 2 <= len(frame):
                pc = struct.unpack_from('<H', frame, offset)[0]
                offset += 2 + pc * 4
                if offset + 2 <= len(frame):
                    fields.append(FieldDescriptor(
                        name='RSN akm_count', offset=offset, width=2,
                        seed_value=struct.unpack_from('<H', frame, offset)[0],
                    ))
                    offset += 2 + struct.unpack_from('<H', frame, offset)[0] * 4
                    # RSN caps [2B]
                    if offset + 2 <= len(frame):
                        fields.append(FieldDescriptor(
                            name='RSN caps', offset=offset, width=2,
                            seed_value=struct.unpack_from('<H', frame, offset)[0],
                        ))

        # HT Capabilities IE (tag=45)
        ht_off = _find_ie(frame, 45, body_start)
        if ht_off is not None and ht_off + 4 <= len(frame):
            fields.append(FieldDescriptor(
                name='HT cap_info',     offset=ht_off+2, width=2,
                seed_value=struct.unpack_from('<H', frame, ht_off+2)[0],
            ))
            fields.append(FieldDescriptor(
                name='HT IE length',    offset=ht_off+1, width=1,
                seed_value=frame[ht_off+1],
            ))

        # HE Extension IE (tag=255)
        he_off = _find_ie(frame, 255, body_start)
        if he_off is not None and he_off + 3 <= len(frame):
            fields.append(FieldDescriptor(
                name='HE ext_id',   offset=he_off+2, width=1,
                seed_value=frame[he_off+2],
            ))
            fields.append(FieldDescriptor(
                name='HE IE length', offset=he_off+1, width=1,
                seed_value=frame[he_off+1],
            ))

    # ── Auth frame ────────────────────────────────────────────────────────────
    elif ftype == 0 and fsub == 11:
        body = 24  # dot11 header
        if body + 6 <= len(frame):
            fields.append(FieldDescriptor(
                name='Auth algo', offset=body, width=2,
                seed_value=struct.unpack_from('<H', frame, body)[0],
            ))
            fields.append(FieldDescriptor(
                name='Auth seq', offset=body+2, width=2,
                seed_value=struct.unpack_from('<H', frame, body+2)[0],
            ))
            fields.append(FieldDescriptor(
                name='Auth status', offset=body+4, width=2,
                seed_value=struct.unpack_from('<H', frame, body+4)[0],
            ))

    # ── Deauth/Disassoc ───────────────────────────────────────────────────────
    elif ftype == 0 and fsub in (10, 12):
        body = 24
        if body + 2 <= len(frame):
            fields.append(FieldDescriptor(
                name='Reason code', offset=body, width=2,
                seed_value=struct.unpack_from('<H', frame, body)[0],
            ))

    return fields


# ── Variant generators ────────────────────────────────────────────────────────

class Strategy(Enum):
    RANDOM          = 'random'
    INCREMENT       = 'increment'
    BOUNDARY_ARITH  = 'boundary_arith'
    BIT_FLIP        = 'bit_flip'
    BYTE_BOUNDARY   = 'byte_boundary'
    HAVOC           = 'havoc'
    SWEEP           = 'sweep'


def _variants_for_field(seed: bytes, fd: FieldDescriptor,
                         strategy: Strategy, budget: int) -> Iterator[bytes]:
    """Yield mutated frame variants for a specific field."""
    orig_val = fd.read(seed)

    if strategy == Strategy.INCREMENT:
        for i in range(1, budget + 1):
            f = bytearray(seed)
            fd.write(f, (orig_val + i) & fd.max_value)
            yield bytes(f)

    elif strategy == Strategy.BOUNDARY_ARITH:
        deltas = [1, 2, 4, 8, 16, 32, 64, 128, 256,
                  -1, -2, -4, -8, -16, -32, -64, -128]
        for delta in deltas[:budget]:
            f = bytearray(seed)
            fd.write(f, (orig_val + delta) & fd.max_value)
            yield bytes(f)

    elif strategy == Strategy.BIT_FLIP:
        bits = fd.width * 8
        for bit in range(min(bits, budget)):
            f = bytearray(seed)
            fd.write(f, orig_val ^ (1 << bit))
            yield bytes(f)

    elif strategy == Strategy.BYTE_BOUNDARY:
        boundary_bytes = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
        count = 0
        for byte_pos in range(fd.width):
            for val in boundary_bytes:
                if count >= budget:
                    return
                f = bytearray(seed)
                abs_off = fd.offset + byte_pos
                if abs_off < len(f):
                    f[abs_off] = val
                    yield bytes(f)
                    count += 1

    elif strategy == Strategy.RANDOM:
        for _ in range(budget):
            f = bytearray(seed)
            fd.write(f, random.randint(0, fd.max_value))
            yield bytes(f)

    elif strategy == Strategy.SWEEP:
        # Exhaustive: iterate all possible values for the field
        limit = min(fd.max_value + 1, budget)
        for v in range(limit):
            f = bytearray(seed)
            fd.write(f, v)
            yield bytes(f)


def _variants_havoc(seed: bytes, budget: int) -> Iterator[bytes]:
    """
    Model-agnostic mutations: random changes to random frame bytes.
    Works on any frame type without field knowledge.
    Applies 1-4 mutations per variant.
    """
    n = len(seed)
    if n < 2:
        return
    for _ in range(budget):
        f    = bytearray(seed)
        muts = random.randint(1, min(4, n))
        for _ in range(muts):
            op = random.randint(0, 4)
            pos = random.randint(0, n - 1)
            if op == 0:                          # random byte
                f[pos] = random.randint(0, 255)
            elif op == 1:                        # boundary byte
                f[pos] = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFF])
            elif op == 2:                        # bit flip
                f[pos] ^= (1 << random.randint(0, 7))
            elif op == 3:                        # increment
                f[pos] = (f[pos] + 1) & 0xFF
            else:                                # decrement
                f[pos] = (f[pos] - 1) & 0xFF
        yield bytes(f)


# ── Expansion engine ──────────────────────────────────────────────────────────

@dataclass
class ExpansionResult:
    """One expansion run result."""
    seed_path:     str
    total_injected: int
    new_crashes:   List[str]    # paths to new .bin files
    strategies:    List[str]    # strategies used
    fields_tested: List[str]    # field names tested


class ExpansionEngine:
    """
    Feedback-driven expansion loop.

    Algorithm:
      seeds = [crash_bin_path, ...]
      while seeds and budget > 0:
          seed = seeds.pop(0)
          variants = generate_variants(seed, field_strategies)
          for variant in variants:
              inject(variant)
              if disconnect:
                  save_crash() → new_crash_path
                  seeds.append(new_crash_path)   ← BFS expansion
              budget -= 1

    Terminates when: budget exhausted OR no more seeds.

    Args:
        station:          wifi-framework Supplicant station.
        seed_paths:       List of .bin crash file paths to expand from.
        budget:           Max total frames to inject across all seeds.
        strategies:       List of Strategy enums to apply (default: all except SWEEP).
        per_seed_budget:  Max frames per seed (to avoid spending all budget on one seed).
        inter_frame_s:    Delay between injections (default 0.05s).
        crash_dir:        Where to save new crash frames.
    """

    def __init__(self, station, seed_paths: List[str],
                 budget: int = 500,
                 strategies: List[Strategy] = None,
                 per_seed_budget: int = 80,
                 inter_frame_s: float = 0.05,
                 crash_dir: str = '/tmp'):

        self.station         = station
        self.seed_paths      = list(seed_paths)
        self.budget          = budget
        self.per_seed_budget = per_seed_budget
        self.inter_frame_s   = inter_frame_s
        self.crash_dir       = crash_dir
        self.strategies      = strategies or [
            Strategy.BOUNDARY_ARITH,
            Strategy.BIT_FLIP,
            Strategy.BYTE_BOUNDARY,
            Strategy.RANDOM,
            Strategy.HAVOC,
            Strategy.INCREMENT,
        ]
        self._injected       = 0
        self._new_crashes:   List[str] = []
        self._fingerprints:  set = set()   # dedup by (frame_hash) to avoid saving duplicates

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> List[ExpansionResult]:
        """Run expansion on all seeds. Returns list of per-seed results."""
        from dependencies.libwifi.wifi import log, STATUS

        seeds   = list(self.seed_paths)
        results = []

        log(STATUS, f'[expander] Starting. seeds={len(seeds)} budget={self.budget} '
            f'strategies={[s.value for s in self.strategies]}', color='cyan')

        while seeds and self._injected < self.budget:
            seed_path = seeds.pop(0)
            seed_data = self._load_bin(seed_path)
            if seed_data is None:
                continue

            log(STATUS, f'[expander] Seed: {os.path.basename(seed_path)} '
                f'({len(seed_data)}B)', color='orange')

            fields     = locate_fields(seed_data)
            new_for_seed = []
            strategies_used = []
            fields_tested   = []

            # Field-aware strategies on each known field
            field_budget = max(10, self.per_seed_budget // max(len(fields), 1))
            for fd in fields:
                if self._injected >= self.budget:
                    break
                for strategy in self.strategies:
                    if strategy == Strategy.HAVOC:
                        continue  # havoc runs separately
                    if self._injected >= self.budget:
                        break
                    gen = _variants_for_field(seed_data, fd, strategy,
                                              min(field_budget, self.budget - self._injected))
                    crashes = self._inject_loop(gen, f'{fd.name}:{strategy.value}')
                    if crashes:
                        new_for_seed.extend(crashes)
                        strategies_used.append(f'{fd.name}:{strategy.value}')
                    if fd.name not in fields_tested:
                        fields_tested.append(fd.name)

            # Havoc always runs (model-agnostic, catches things field-aware misses)
            if Strategy.HAVOC in self.strategies and self._injected < self.budget:
                havoc_budget = min(self.per_seed_budget // 2,
                                   self.budget - self._injected)
                gen     = _variants_havoc(seed_data, havoc_budget)
                crashes = self._inject_loop(gen, 'havoc')
                if crashes:
                    new_for_seed.extend(crashes)
                    strategies_used.append('havoc')

            # New crashes → seeds for next BFS round
            for cp in new_for_seed:
                if cp not in seeds:
                    seeds.insert(0, cp)   # BFS: front-of-queue

            results.append(ExpansionResult(
                seed_path=seed_path,
                total_injected=self._injected,
                new_crashes=new_for_seed,
                strategies=strategies_used,
                fields_tested=fields_tested,
            ))
            self._new_crashes.extend(new_for_seed)

            log(STATUS, f'[expander] Seed done. New crashes: {len(new_for_seed)}  '
                f'Total injected: {self._injected}', color='cyan')

        return results

    # ── Injection with alive check ─────────────────────────────────────────────

    def _inject_loop(self, variants: Iterator[bytes], label: str) -> List[str]:
        """Inject each variant, check alive, save crashes. Return crash paths."""
        from scapy.layers.dot11 import Dot11
        from dependencies.libwifi.wifi import log, STATUS

        crashes = []
        for i, frame_bytes in enumerate(variants):
            if self._injected >= self.budget:
                break

            # Dedup: skip if we've seen this exact frame before
            fp = hash(frame_bytes)
            if fp in self._fingerprints:
                continue
            self._fingerprints.add(fp)

            # Inject
            try:
                frame = Dot11(frame_bytes)
            except Exception:
                continue

            self.station.inject_mon(frame)
            self._injected += 1
            time.sleep(self.inter_frame_s)

            # Alive check every 5 injections
            if i % 5 == 0:
                alive = self._is_alive()
                if not alive:
                    cp = self._save_crash(frame_bytes, label, i)
                    if cp:
                        crashes.append(cp)
                        log(STATUS, f'  [expander] NEW CRASH: {os.path.basename(cp)} '
                            f'label={label}', color='red')
                    # Wait for reconnect
                    time.sleep(3)

        return crashes

    def _is_alive(self) -> bool:
        try:
            resp = self.station.wpaspy_command('STATUS')
            return 'wpa_state=COMPLETED' in resp
        except Exception:
            return False

    def _save_crash(self, frame: bytes, label: str, idx: int) -> Optional[str]:
        ts    = datetime.now().strftime('%Y%m%d_%H%M%S')
        lbl   = label.replace(':', '_').replace(' ', '_')[:50]
        path  = os.path.join(self.crash_dir,
                              f'wifi_expand_crash_{ts}_{lbl}_{idx}.bin')
        try:
            with open(path, 'wb') as f:
                f.write(frame)
            return path
        except Exception:
            return None

    def _load_bin(self, path: str) -> Optional[bytes]:
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if b'\n---\n' in data:
                data = data.split(b'\n---\n', 1)[0]
            return data if len(data) >= 10 else None
        except Exception:
            return None

    # ── Summary ────────────────────────────────────────────────────────────────

    def summary(self) -> str:
        lines = [
            f'[expander] ═══ EXPANSION SUMMARY ═══',
            f'  Total injected  : {self._injected}',
            f'  New crashes     : {len(self._new_crashes)}',
        ]
        for cp in self._new_crashes:
            lines.append(f'    {cp}')
        return '\n'.join(lines)
