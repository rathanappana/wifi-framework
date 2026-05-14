"""
Havoc mutation engine — apply multiple simultaneous frame corruptions.

AFL-style "havoc mode": randomly chains 2-8 mutations per frame.
Each mutation is drawn from a weighted pool based on frame type.

Why this matters:
  Single mutations test clean boundary handling.
  Stacked mutations collapse parser assumptions:
    - Malformed RSN + duplicated HE IE + bad FC flags
    - Truncated HT + corrupted AKM count + invalid sequence
  These interactions trigger bugs that single mutations miss.

Key functions:
  apply_havoc(frame_bytes, n_mutations=None) → bytes
  mutate_ie_stack(ie_bytes, n_ops=3)         → bytes
  splice(frame_a, frame_b)                   → bytes
  bit_walk(data, offset, width)              → bytes
  dictionary_insert(data, pos)               → bytes

Designed to wrap existing campaign phase frames:
  # In campaign._inj():
  if havoc_mode:
      frame_bytes = apply_havoc(frame_bytes, n_mutations=random.randint(2,6))
"""
from __future__ import annotations

import os
import random
import struct
from typing import List, Optional


# ── Protocol dictionary (known magic values for Wi-Fi parsers) ─────────────────

WIFI_DICT = [
    b'\xff\xff',                    # max 2B
    b'\x00\x00',                    # zero 2B
    b'\x7f\xff',                    # signed max
    b'\x80\x00',                    # signed overflow
    b'\xdd',                        # vendor IE tag
    b'\x00\x0f\xac',               # RSN OUI
    b'\x00\x50\xf2',               # Microsoft OUI
    b'\x00\x90\x4c',               # Broadcom OUI
    b'\xff\xff\xff\xff',            # max 4B
    b'\xaa\xaa\x03',               # LLC SNAP start
    b'\x08\x00',                    # IPv4 ethertype
    b'\x88\x8e',                    # EAPOL ethertype
    b'\x01\x00',                    # RSN version=256
    b'\xff\x00',                    # RSN version=255
    b'\x30',                        # RSN IE tag
    b'\x2d',                        # HT cap IE tag (=45)
    b'\xbf',                        # VHT cap IE tag (=191)
    b'\xff\x23',                    # HE cap IE tag+extid
    b'\x00' * 8,                    # 8 zero bytes
    b'\xff' * 8,                    # 8 ff bytes
    b'\xde\xad\xbe\xef',           # known garbage
    b'\x80\x00\x00\x00',           # high bit set 4B
]

# IE tags that carry security-critical parsers
CRITICAL_IE_TAGS = [0, 1, 3, 45, 48, 61, 127, 191, 221, 255]


# ── Byte-level mutations ────────────────────────────────────────────────────────

def _repeat_chunk(data: bytes, chunk_size: int = None, repeats: int = None) -> bytes:
    """Repeat a random chunk N times — targets memcpy bugs, parser loops."""
    if len(data) < 4:
        return data
    chunk_size  = chunk_size or random.randint(1, min(8, len(data)))
    repeats     = repeats    or random.randint(2, 16)
    start       = random.randint(0, len(data) - chunk_size)
    chunk       = data[start:start + chunk_size]
    insert_pos  = random.randint(0, len(data))
    return data[:insert_pos] + chunk * repeats + data[insert_pos:]


def _length_expand(data: bytes, target_size: int = None) -> bytes:
    """Pad data to large size — targets allocation failures, skb bugs."""
    target = target_size or random.choice([512, 1024, 2048, 4096])
    if len(data) >= target:
        return data
    pad = random.choice([b'\x00', b'\xff', b'\xaa', b'\x41'])
    return data + pad * (target - len(data))


def _splice(data_a: bytes, data_b: bytes, ratio: float = None,
            protect: int = 24) -> bytes:
    """
    Combine first part of data_a with second part of data_b.
    protect: min splice point (never splice before addr fields end).
    Dot11 header = 24B (FC+Dur+addr1+addr2+addr3+SC) → protect=24
    preserves source/dest MACs from addr corruption.
    """
    ratio    = ratio or random.uniform(0.2, 0.8)
    split_a  = max(protect, int(len(data_a) * ratio))
    split_b  = max(protect, int(len(data_b) * (1 - ratio)))
    if split_a >= len(data_a) or split_b >= len(data_b):
        return data_a
    return data_a[:split_a] + data_b[split_b:]


def _bit_walk(data: bytes, start: int = None, width: int = None) -> bytes:
    """Flip bits across a range — targets flag parsers, capability masks."""
    if not data:
        return data
    n_bits = random.randint(1, min(8, len(data)))
    result = bytearray(data)
    for _ in range(n_bits):
        pos = random.randint(0, len(result) - 1)
        bit = 1 << random.randint(0, 7)
        result[pos] ^= bit
    return bytes(result)


def _dictionary_insert(data: bytes, pos: int = None) -> bytes:
    """Insert known protocol magic bytes — targets vendor/RSN parsers."""
    magic = random.choice(WIFI_DICT)
    pos   = pos if pos is not None else random.randint(0, len(data))
    return data[:pos] + magic + data[pos:]


def _alignment_shift(data: bytes) -> bytes:
    """Shift data by 1-4 bytes — targets alignment-sensitive parsers."""
    shift = random.randint(1, 4)
    pad   = random.choice([b'\x00', b'\xff'])
    return pad * shift + data[:-shift] if len(data) > shift else data


def _chunk_delete(data: bytes) -> bytes:
    """Delete a random chunk — creates truncation mid-frame."""
    if len(data) < 4:
        return data
    size  = random.randint(1, max(1, len(data) // 4))
    start = random.randint(0, len(data) - size)
    return data[:start] + data[start + size:]


def _entropy_collapse(data: bytes, pos: int = None, size: int = None) -> bytes:
    """Replace a region with all-zeros or all-ones — entropy collapse."""
    if len(data) < 2:
        return data
    size  = size or random.randint(1, max(1, len(data) // 2))
    pos   = pos  or random.randint(0, max(0, len(data) - size))
    fill  = random.choice([b'\x00', b'\xff'])
    return data[:pos] + fill * size + data[pos + size:]


def _random_byte(data: bytes) -> bytes:
    """Replace random byte with random value."""
    if not data:
        return data
    result = bytearray(data)
    pos = random.randint(0, len(result) - 1)
    result[pos] = random.randint(0, 255)
    return bytes(result)


def _boundary_byte(data: bytes) -> bytes:
    """Replace random byte with boundary value (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF)."""
    if not data:
        return data
    result = bytearray(data)
    pos = random.randint(0, len(result) - 1)
    result[pos] = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
    return bytes(result)


# ── IE stack mutations ─────────────────────────────────────────────────────────

def _parse_ies(ie_bytes: bytes) -> List[bytes]:
    """Parse IE chain into list of raw IE bytes (tag+len+body)."""
    ies = []
    i = 0
    while i < len(ie_bytes) - 1:
        tag    = ie_bytes[i]
        length = ie_bytes[i + 1]
        actual = min(length, len(ie_bytes) - i - 2)
        ies.append(ie_bytes[i:i + 2 + actual])
        i += 2 + actual
        if actual < length:
            break
    return ies


def _serialize_ies(ies: List[bytes]) -> bytes:
    return b''.join(ies)


def _corrupt_ie_length(ie: bytes) -> bytes:
    """Mutate the IE length byte."""
    if len(ie) < 2:
        return ie
    ie_mut = bytearray(ie)
    choice = random.randint(0, 4)
    if choice == 0:
        ie_mut[1] = 0xFF   # max claim
    elif choice == 1:
        ie_mut[1] = 0x00   # zero length
    elif choice == 2:
        ie_mut[1] = max(0, ie_mut[1] - random.randint(1, 4))  # under-claim
    elif choice == 3:
        ie_mut[1] = min(255, ie_mut[1] + random.randint(1, 16))  # over-claim
    else:
        ie_mut[1] = random.randint(0, 255)  # random
    return bytes(ie_mut)


def _corrupt_ie_body(ie: bytes) -> bytes:
    """Apply random mutation to IE body bytes."""
    if len(ie) <= 2:
        return ie
    body  = bytearray(ie[2:])
    if not body:
        return ie
    pos   = random.randint(0, len(body) - 1)
    body[pos] = random.choice([0x00, 0xFF, 0x7F, 0x80, random.randint(0, 255)])
    return ie[:2] + bytes(body)


def mutate_ie_stack(ie_bytes: bytes, n_ops: int = 3) -> bytes:
    """
    Apply N random mutations to an IE chain.

    Operations:
      duplicate_ie   — insert copy of random IE (tests "one IE per type" assumption)
      shuffle_order  — reorder IEs randomly (tests ordering assumption)
      corrupt_length — mutate IE length field (over-read/under-read)
      truncate_middle — delete middle IE (creates gap)
      insert_random  — insert garbage bytes between IEs
      corrupt_body   — mutate IE body bytes
      add_unknown_ie — append IE with unknown tag (tests unknown IE handling)
      remove_ie      — delete a random IE

    Args:
        ie_bytes: Raw IE chain bytes
        n_ops:    Number of operations to apply

    Returns:
        Mutated IE chain bytes
    """
    ies = _parse_ies(ie_bytes)
    if not ies:
        return ie_bytes

    for _ in range(n_ops):
        if not ies:
            break
        op = random.randint(0, 7)

        if op == 0 and len(ies) > 1:   # duplicate random IE
            idx = random.randint(0, len(ies) - 1)
            ies.insert(random.randint(0, len(ies)), ies[idx])

        elif op == 1:                    # shuffle order
            random.shuffle(ies)

        elif op == 2:                    # corrupt length
            idx = random.randint(0, len(ies) - 1)
            ies[idx] = _corrupt_ie_length(ies[idx])

        elif op == 3 and len(ies) > 2:  # truncate middle IE
            mid = len(ies) // 2
            ies.pop(mid)

        elif op == 4:                    # insert garbage between IEs
            pos = random.randint(0, len(ies))
            size = random.randint(1, 8)
            garbage = bytes([random.randint(0, 255) for _ in range(size)])
            ies.insert(pos, garbage)

        elif op == 5:                    # corrupt body
            idx = random.randint(0, len(ies) - 1)
            ies[idx] = _corrupt_ie_body(ies[idx])

        elif op == 6:                    # add unknown IE
            tag  = random.choice([0xDD, 0xFE, random.randint(100, 200)])
            size = random.randint(0, 20)
            body = bytes([random.randint(0, 255) for _ in range(size)])
            ies.append(bytes([tag, size]) + body)

        elif op == 7 and len(ies) > 1:  # remove IE
            idx = random.randint(0, len(ies) - 1)
            ies.pop(idx)

    return _serialize_ies(ies)


# ── Frame-level havoc ─────────────────────────────────────────────────────────

# Weighted mutation pool: (weight, function)
# Higher weight = selected more often
_FRAME_MUTATORS = [
    (30, _random_byte),
    (25, _boundary_byte),
    (20, _bit_walk),
    (15, _dictionary_insert),
    (10, _repeat_chunk),
    (8,  _entropy_collapse),
    (5,  _chunk_delete),
    (3,  _alignment_shift),
]

_WEIGHTS = [w for w, _ in _FRAME_MUTATORS]
_FUNCS   = [f for _, f in _FRAME_MUTATORS]


def apply_havoc(frame_bytes: bytes,
                n_mutations: int = None,
                ie_offset: int = None,
                spare_header: int = 24) -> bytes:
    """
    Apply N random mutations to a raw 802.11 frame.

    Does NOT mutate the 802.11 header (first spare_header bytes)
    because that would break routing to AP. Mutates:
      - FC flags after addr fields (from offset 1-2)
      - QoS/body bytes after header
      - IE chain (if ie_offset provided)

    Args:
        frame_bytes:    Raw 802.11 frame bytes
        n_mutations:    Number of mutations to apply (default: random 2-6)
        ie_offset:      Byte offset where IE chain starts in frame (optional)
        spare_header:   Protected prefix length (default: 24 = Dot11 header)

    Returns:
        Mutated frame bytes
    """
    if not frame_bytes or len(frame_bytes) <= spare_header:
        return frame_bytes

    n = n_mutations or random.randint(2, 6)
    result = bytearray(frame_bytes)

    for _ in range(n):
        fn = random.choices(_FUNCS, weights=_WEIGHTS, k=1)[0]

        if ie_offset and ie_offset < len(result) and random.random() < 0.4:
            # 40% chance: mutate IE chain specifically
            ie_part = mutate_ie_stack(bytes(result[ie_offset:]), n_ops=1)
            result   = result[:ie_offset] + bytearray(ie_part)
        else:
            # Mutate body (after header)
            body    = fn(bytes(result[spare_header:]))
            result  = result[:spare_header] + bytearray(body)

    # Also randomly flip a FC flag bit (low probability)
    if random.random() < 0.15 and len(result) > 1:
        # FCfield is byte 1 of Dot11 frame
        flag_bit = 1 << random.randint(2, 7)  # skip type/subtype bits
        result[1] ^= flag_bit

    return bytes(result)


# ── Splice corpus ─────────────────────────────────────────────────────────────

class SpliceMutator:
    """
    Splice mutations between a corpus of frames.

    Takes the interesting part of one frame and combines with another.
    AFL's splice mutation is one of its most effective strategies.

    Usage:
        sm = SpliceMutator()
        sm.add('/tmp/wifi_fuzz_crash_*.bin')
        variant = sm.splice(base_frame_bytes)
    """

    def __init__(self):
        self._corpus: List[bytes] = []

    def add_file(self, path: str) -> bool:
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if b'\n---\n' in data:
                data = data.split(b'\n---\n', 1)[0]
            if len(data) >= 10:
                self._corpus.append(data)
                return True
        except Exception:
            pass
        return False

    def add_bytes(self, data: bytes) -> None:
        if len(data) >= 10:
            self._corpus.append(data)

    def load_crash_dir(self, directory: str = '/tmp') -> int:
        import glob
        count = 0
        for p in glob.glob(f'{directory}/wifi_fuzz_crash_*.bin') + \
                 glob.glob(f'{directory}/wifi_expand_crash_*.bin'):
            if self.add_file(p):
                count += 1
        return count

    def splice(self, base: bytes, ratio: float = None) -> bytes:
        """Splice base with random corpus member."""
        if not self._corpus:
            return base
        donor = random.choice(self._corpus)
        return _splice(base, donor, ratio)

    def corpus_size(self) -> int:
        return len(self._corpus)


# ── Integration helpers ────────────────────────────────────────────────────────

def havoc_frame(raw_frame: bytes, intensity: int = 3,
                splice_corpus: Optional[SpliceMutator] = None,
                ie_offset: int = None) -> bytes:
    """
    Main entry point: apply havoc mutations to a complete 802.11 frame.

    Args:
        raw_frame:      Input frame bytes
        intensity:      1=light(2 muts), 2=medium(4 muts), 3=heavy(6 muts)
        splice_corpus:  Optional SpliceMutator for cross-frame splice
        ie_offset:      IE chain start byte (for targeted IE mutations)

    Returns:
        Mutated frame bytes, same general structure
    """
    n = {1: random.randint(1, 3), 2: random.randint(3, 5),
         3: random.randint(4, 8)}.get(intensity, 4)

    result = raw_frame

    # Optional splice step
    if splice_corpus and splice_corpus.corpus_size() > 0 and random.random() < 0.3:
        result = splice_corpus.splice(result)

    # Apply frame-level havoc
    result = apply_havoc(result, n_mutations=n, ie_offset=ie_offset)

    return result


def havoc_ie_chain_only(ie_bytes: bytes, intensity: int = 3) -> bytes:
    """
    Apply recursive IE stack mutations. Use this when you have the IE
    chain extracted from a management frame body.

    Args:
        ie_bytes:  Raw IE chain bytes (tag+len+body repeating)
        intensity: 1=light(1 op), 2=medium(3 ops), 3=heavy(6 ops)

    Returns:
        Mutated IE chain bytes
    """
    n = {1: 1, 2: 3, 3: 6}.get(intensity, 3)
    return mutate_ie_stack(ie_bytes, n_ops=n)
