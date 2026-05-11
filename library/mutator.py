import os
import random
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable

from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap
from scapy.packet import Raw

log = logging.getLogger(__name__)

# ── IE tag constants ──────────────────────────────────────────────────────────

IE_SSID             = 0
IE_SUPPORTED_RATES  = 1
IE_DS_PARAM         = 3
IE_COUNTRY          = 7
IE_HT_CAPABILITIES  = 45
IE_RSN              = 48
IE_EXT_SUPP_RATES   = 50
IE_HT_OPERATION     = 61
IE_EXT_CAPABILITIES = 127
IE_VHT_CAPABILITIES = 191
IE_VHT_OPERATION    = 192
IE_VENDOR_SPECIFIC  = 221
IE_EXTENSION        = 255   # HE / 802.11ax element

# IEs whose duplication or removal triggers deep parser paths
CRITICAL_IES = frozenset({
    IE_RSN, IE_HT_CAPABILITIES, IE_VHT_CAPABILITIES, IE_EXTENSION, IE_SUPPORTED_RATES
})


# ── Raw IE TLV helpers ────────────────────────────────────────────────────────

def parse_ies(data: bytes) -> list:
    """Parse IE TLVs. Returns list of (tag: int, value: bytes)."""
    ies = []
    i = 0
    while i + 1 < len(data):
        tag = data[i]
        length = data[i + 1]
        value = data[i + 2: i + 2 + length]
        ies.append((tag, bytes(value)))
        i += 2 + length
    return ies


def build_ies(ies: list) -> bytes:
    """Serialize (tag, value) list back to raw bytes."""
    out = b''
    for tag, value in ies:
        v = bytes(value)[:255]
        out += bytes([tag, len(v)]) + v
    return out


def mgmt_ie_offset(frame) -> Optional[int]:
    """
    Return byte offset where IEs start inside raw frame bytes.
    Uses the tail-alignment property: Dot11Elt bytes are always at the end
    of management frames, so offset = total_len - ie_portion_len.
    Returns None if frame has no IEs or is not management.
    """
    if not frame.haslayer(Dot11) or frame[Dot11].type != 0:
        return None
    if not frame.haslayer(Dot11Elt):
        return None
    raw = bytes(frame)
    ie_portion = bytes(frame[Dot11Elt])
    offset = len(raw) - len(ie_portion)
    return offset if offset >= 0 else None


# ── Individual mutation strategies ────────────────────────────────────────────

def _bitflip(data: bytes, n: int = 1) -> bytes:
    if not data:
        return data
    arr = bytearray(data)
    for _ in range(n):
        arr[random.randrange(len(arr))] ^= (1 << random.randrange(8))
    return bytes(arr)


def mutate_bitflip(raw: bytes, ie_offset: int) -> bytes:
    """Flip 1-4 random bits anywhere in frame body after fixed headers."""
    if ie_offset >= len(raw):
        return raw
    body = bytearray(raw[ie_offset:])
    if not body:
        return raw
    for _ in range(random.randint(1, 4)):
        body[random.randrange(len(body))] ^= (1 << random.randrange(8))
    return raw[:ie_offset] + bytes(body)


def mutate_ie_length(raw: bytes, ie_offset: int) -> bytes:
    """Set one IE's length byte to an invalid value (overread/underread)."""
    ies = parse_ies(raw[ie_offset:])
    if not ies:
        return raw
    idx = random.randrange(len(ies))
    bad_len = random.choice([0, 1, 64, 128, 254, 255])
    arr = bytearray(raw)
    pos = ie_offset
    for i, (tag, value) in enumerate(ies):
        if i == idx:
            arr[pos + 1] = bad_len
            return bytes(arr)
        pos += 2 + len(value)
    return raw


def mutate_ie_overflow(raw: bytes, ie_offset: int) -> bytes:
    """Set IE length > actual value bytes — classic heap overread trigger."""
    ies = parse_ies(raw[ie_offset:])
    if not ies:
        return raw
    idx = random.randrange(len(ies))
    arr = bytearray(raw)
    pos = ie_offset
    for i, (tag, value) in enumerate(ies):
        if i == idx:
            overflow = min(255, len(value) + random.randint(1, 64))
            arr[pos + 1] = overflow
            return bytes(arr)
        pos += 2 + len(value)
    return raw


def mutate_ie_body(raw: bytes, ie_offset: int) -> bytes:
    """Corrupt bytes inside a random IE's value field."""
    ies = parse_ies(raw[ie_offset:])
    targets = [(i, t, v) for i, (t, v) in enumerate(ies) if v]
    if not targets:
        return raw
    idx, tag, value = random.choice(targets)
    corrupted = _bitflip(value, random.randint(1, max(1, len(value) // 2)))
    ies[idx] = (tag, corrupted)
    return raw[:ie_offset] + build_ies(ies)


def mutate_ie_remove(raw: bytes, ie_offset: int) -> bytes:
    """Remove a critical IE to test missing-element handling."""
    ies = parse_ies(raw[ie_offset:])
    if not ies:
        return raw
    critical = [i for i, (t, v) in enumerate(ies) if t in CRITICAL_IES]
    idx = random.choice(critical) if critical else random.randrange(len(ies))
    new_ies = [ie for i, ie in enumerate(ies) if i != idx]
    return raw[:ie_offset] + build_ies(new_ies)


def mutate_ie_duplicate(raw: bytes, ie_offset: int) -> bytes:
    """Duplicate a critical IE to trigger parser ambiguity bugs."""
    ies = parse_ies(raw[ie_offset:])
    if not ies:
        return raw
    critical = [(i, t, v) for i, (t, v) in enumerate(ies) if t in CRITICAL_IES]
    if not critical:
        idx = random.randrange(len(ies))
        tag, value = ies[idx]
    else:
        idx, tag, value = random.choice(critical)
    ies.insert(idx + 1, (tag, value))
    return raw[:ie_offset] + build_ies(ies)


def mutate_ie_add_unknown(raw: bytes, ie_offset: int) -> bytes:
    """Inject a malformed unknown IE at a random position."""
    ies = parse_ies(raw[ie_offset:])
    bad_tag = random.choice([200, 202, 210, 215, 220, 240, 250])
    bad_val = os.urandom(random.choice([0, 1, 8, 32, 100]))
    ies.insert(random.randint(0, len(ies)), (bad_tag, bad_val))
    return raw[:ie_offset] + build_ies(ies)


def mutate_ie_reorder(raw: bytes, ie_offset: int) -> bytes:
    """Shuffle IE order — tests parsers that assume fixed IE ordering."""
    ies = parse_ies(raw[ie_offset:])
    if len(ies) < 2:
        return raw
    random.shuffle(ies)
    return raw[:ie_offset] + build_ies(ies)


def mutate_capabilities(raw: bytes, ie_offset: int) -> bytes:
    """Flip bits in the capability field (2 bytes immediately before IEs)."""
    if ie_offset < 2:
        return raw
    arr = bytearray(raw)
    cap = ie_offset - 2
    arr[cap]     ^= (1 << random.randrange(8))
    arr[cap + 1] ^= (1 << random.randrange(8))
    return bytes(arr)


def mutate_rsn_body(raw: bytes, ie_offset: int) -> bytes:
    """
    Targeted RSN IE corruption: invalid version, zero pairwise count,
    or mangled PMKID list. Reaches deeper WPA parser states.
    """
    ies = parse_ies(raw[ie_offset:])
    rsn_ies = [(i, v) for i, (t, v) in enumerate(ies) if t == IE_RSN]
    if not rsn_ies:
        return raw
    idx, value = random.choice(rsn_ies)
    if not value:
        return raw
    arr = bytearray(value)
    mutation = random.choice(['version', 'pairwise_count', 'akm_count', 'pmkid', 'caps'])
    if mutation == 'version' and len(arr) >= 2:
        # Invalid RSN version (valid = 1)
        arr[0], arr[1] = random.randint(2, 255), 0
    elif mutation == 'pairwise_count' and len(arr) >= 8:
        # Set pairwise cipher count to 0 or very large
        arr[6] = random.choice([0, 255])
        arr[7] = 0
    elif mutation == 'akm_count' and len(arr) >= 12:
        arr[10] = random.choice([0, 255])
        arr[11] = 0
    elif mutation == 'pmkid' and len(arr) >= 2:
        # Append a fake PMKID count + garbage PMKID
        arr += bytes([1, 0]) + os.urandom(16)
    elif mutation == 'caps' and len(arr) >= 2:
        arr[-2] ^= 0xFF
        arr[-1] ^= 0xFF
    ies[idx] = (IE_RSN, bytes(arr))
    return raw[:ie_offset] + build_ies(ies)


# ── Strategy registry ─────────────────────────────────────────────────────────

STRATEGIES: dict = {
    'bitflip':        mutate_bitflip,
    'ie_length':      mutate_ie_length,
    'ie_overflow':    mutate_ie_overflow,
    'ie_body':        mutate_ie_body,
    'ie_remove':      mutate_ie_remove,
    'ie_duplicate':   mutate_ie_duplicate,
    'ie_add_unknown': mutate_ie_add_unknown,
    'ie_reorder':     mutate_ie_reorder,
    'capabilities':   mutate_capabilities,
    'rsn_body':       mutate_rsn_body,
}

DEFAULT_STRATEGIES = list(STRATEGIES.keys())


# ── Config + FrameMutator ─────────────────────────────────────────────────────

@dataclass
class MutationConfig:
    enabled_strategies: list = None      # None = all strategies
    mutations_per_frame: int = 1         # strategies applied per mutated frame
    drop_probability: float = 0.0        # 0.0–1.0 chance to drop frame entirely
    mutate_tx: bool = True               # mutate outbound frames
    mutate_rx: bool = False              # mutate inbound frames (rarely needed)
    subtype_filter: set = None           # None = all mgmt subtypes; set of ints to restrict

    def __post_init__(self):
        if self.enabled_strategies is None:
            self.enabled_strategies = DEFAULT_STRATEGIES


class FrameMutator:
    """
    Central mutation engine. Attach to Daemon.tx_hook and/or Daemon.rx_hook.

    Usage:
        mutator = FrameMutator()
        station.tx_hook = mutator.tx_hook
        station.rx_hook = mutator.rx_hook   # optional
    """

    def __init__(self, config: MutationConfig = None):
        self.config = config or MutationConfig()
        self.stats = {'seen': 0, 'mutated': 0, 'dropped': 0, 'skipped': 0}

    def _mutate_frame(self, frame):
        """Apply configured strategies to one frame. Returns mutated frame or None."""
        self.stats['seen'] += 1

        if self.config.drop_probability > 0.0:
            if random.random() < self.config.drop_probability:
                self.stats['dropped'] += 1
                return None

        if not frame.haslayer(Dot11) or frame[Dot11].type != 0:
            self.stats['skipped'] += 1
            return frame

        if self.config.subtype_filter is not None:
            if frame[Dot11].subtype not in self.config.subtype_filter:
                self.stats['skipped'] += 1
                return frame

        ie_offset = mgmt_ie_offset(frame)
        if ie_offset is None:
            self.stats['skipped'] += 1
            return frame

        raw = bytes(frame)
        if ie_offset >= len(raw):
            self.stats['skipped'] += 1
            return frame

        active = [s for s in self.config.enabled_strategies if s in STRATEGIES]
        if not active:
            return frame

        chosen = random.choices(active, k=self.config.mutations_per_frame)
        mutated = raw
        for name in chosen:
            try:
                mutated = STRATEGIES[name](mutated, ie_offset=ie_offset)
            except Exception as exc:
                log.debug(f"mutator strategy '{name}' failed: {exc}")

        self.stats['mutated'] += 1

        # Reconstruct scapy frame from mutated raw bytes
        try:
            if frame.haslayer(RadioTap):
                from scapy.layers.dot11 import RadioTap as RT
                return RT(mutated)
            return Dot11(mutated)
        except Exception:
            return frame

    def tx_hook(self, frame, iface: str):
        """Plug into Daemon.tx_hook. Mutates outbound management frames."""
        if not self.config.mutate_tx:
            return frame
        return self._mutate_frame(frame)

    def rx_hook(self, frame, iface: str):
        """Plug into Daemon.rx_hook. Mutates inbound management frames."""
        if not self.config.mutate_rx:
            return frame
        return self._mutate_frame(frame)

    def summary(self) -> str:
        s = self.stats
        return (f"seen={s['seen']} mutated={s['mutated']} "
                f"dropped={s['dropped']} skipped={s['skipped']}")
