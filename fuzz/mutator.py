"""
Four-level mutation engine for 802.11 protocol fuzzing.

Mutation levels (in order of abstraction):

  Level 1 — Byte mutation
    Operates on raw bytes. Mirrors owfuzz's VALUE_* strategies.
    Functions: byte_mutate(), all_byte_mutations()

  Level 2 — Field mutation
    Operates on typed integer fields. Produces boundary/corner-case values.
    Functions: field_boundary_values(), mutate_field(), pack_le(), pack_be()

  Level 3 — IE (Information Element) structural mutation
    Corrupts IE tag/length/body relationships to trigger parser bugs.
    Functions: ie_build(), ie_wrong_length(), ie_truncated(), ie_extended_body(),
               ie_zero_length(), ie_max_length_claim(), ie_extended_tag(),
               ie_all_mutations()

  Level 4 — Sequence mutation (FSM-level)
    Describes protocol state machine violations (reorder, replay, skip).
    Classes: SequenceMutation
    Constants: EAPOL_SEQUENCE_MUTATIONS, POST_AUTH_SEQUENCE_MUTATIONS

Design principles:
  - All functions are pure (return new bytes, never modify input).
  - Mutations are composable — apply one then feed result to another.
  - Deterministic when seed is given (reproducibility for crash triage).
  - No wifi-framework or Scapy imports — usable standalone.
"""
from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, List, Optional, Tuple


# ── Level 1: Byte mutation ────────────────────────────────────────────────────

class ByteStrategy(Enum):
    """
    Byte-level mutation strategies.

    Mirrors owfuzz's VALUE_* enum plus additional patterns.

    ZERO     — fill with 0x00 (tests null-byte handling, zero-length logic)
    ONE      — fill with 0xFF (tests max-value handling, all-bits-set parsers)
    RANDOM   — uniform random per byte (general crash discovery)
    CONST    — every byte = same random value (pattern detection bypass)
    BIT_FLIP — flip 1–3 random bits (targeted single-bit error injection)
    XOR_AA   — XOR each byte with 0xAA (alternating 10101010 pattern)
    XOR_55   — XOR each byte with 0x55 (alternating 01010101 pattern)
    BOUNDARY — cycle through {0x00,0xFF,0x7F,0x80,0x01,0xFE,0x40,0xC0}
    INCR     — 0,1,2,...255,0,1,... (sequential, detects ring-buffer bugs)
    ALT      — 0x00,0xFF,0x00,0xFF (alternating extremes)
    """
    zero     = 'zero'
    one      = 'one'
    random   = 'random'
    const    = 'const'
    bit_flip = 'bit_flip'
    xor_aa   = 'xor_aa'
    xor_55   = 'xor_55'
    boundary = 'boundary'
    incr     = 'incr'
    alt      = 'alt'
    """
    we can add more strategies here as needed, e.g., patterns of 0x00/0xFF with random bits in between,
    splice
    dictionary insert
    repeated chunks
    length explosion
    entropy collapse
    bit walking
    UTF confusion
    integer smashing
    compression patterns
    alignment shifts
    """


def byte_mutate(length: int, strategy: ByteStrategy, seed: Optional[int] = None) -> bytes:
    """
    Generate mutated bytes of given length using the specified strategy.

    Args:
        length:   Number of bytes to generate. Must be >= 1.
        strategy: Which ByteStrategy to apply.
        seed:     Optional RNG seed for deterministic/reproducible output.

    Returns:
        Mutated bytes of exactly `length` bytes.

    Example:
        >>> byte_mutate(4, ByteStrategy.BOUNDARY)
        b'\\x00\\xff\\x7f\\x80'
        >>> byte_mutate(8, ByteStrategy.INCR)
        b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07'
    """
    if length < 1:
        raise ValueError('length must be >= 1')

    rng = random.Random(seed)

    if strategy == ByteStrategy.zero:
        return b'\x00' * length
    elif strategy == ByteStrategy.one:
        return b'\xff' * length
    elif strategy == ByteStrategy.random:
        return bytes(rng.randint(0, 255) for _ in range(length))
    elif strategy == ByteStrategy.const:
        val = rng.randint(0, 255)
        return bytes([val] * length)
    elif strategy == ByteStrategy.bit_flip:
        buf = bytearray(b'\x00' * length)
        for _ in range(rng.randint(1, 3)):
            pos = rng.randrange(length)
            buf[pos] ^= (1 << rng.randrange(8))
        return bytes(buf)
    elif strategy == ByteStrategy.xor_aa:
        return bytes(b ^ 0xAA for b in b'\x00' * length)
    elif strategy == ByteStrategy.xor_55:
        return bytes(b ^ 0x55 for b in b'\x00' * length)
    elif strategy == ByteStrategy.boundary:
        pattern = (0, 255, 127, 128, 1, 254, 64, 192)
        return bytes(pattern[i % len(pattern)] for i in range(length))
    elif strategy == ByteStrategy.incr:
        return bytes(i % 256 for i in range(length))
    elif strategy == ByteStrategy.alt:
        return bytes(0x00 if i % 2 == 0 else 0xFF for i in range(length))
    else:
        raise ValueError('Unknown ByteStrategy: ' + str(strategy))


def all_byte_mutations(length: int, seed: Optional[int] = None) -> Iterator[Tuple[ByteStrategy, bytes]]:
    """
    Yield (strategy, payload) for every ByteStrategy.

    Args:
        length: Payload length for each mutation.
        seed:   Optional RNG seed (same seed applied to each strategy).

    Yields:
        (ByteStrategy, bytes) — strategy name and mutated payload.
    """
    for s in ByteStrategy:
        yield s, byte_mutate(length, s, seed)


# ── Level 2: Field mutation ───────────────────────────────────────────────────

def field_boundary_values(width_bytes: int) -> List[int]:
    """
    Return interesting boundary integer values for a field of width_bytes.

    Designed to trigger:
      - Off-by-one errors: 0, 1, max, max-1
      - Sign confusion:    half (0x7F/0x7FFF), half+1 (0x80/0x8000)
      - Pattern bugs:      0x55, 0xAA
      - Length overflows:  0x100 (> 8-bit max), 0x0400 (common alloc size)

    Args:
        width_bytes: Field width in bytes (1, 2, or 4).

    Returns:
        Sorted list of unique values, all in [0, 2^(8*width_bytes) - 1].

    Example:
        >>> field_boundary_values(1)
        [0, 1, 85, 127, 128, 170, 254, 255]
        >>> field_boundary_values(2)
        [0, 1, 85, 170, 255, 256, 1024, 32767, 32768, 65279, 65534, 65535]
    """
    max_val = (1 << (8 * width_bytes)) - 1
    half    = max_val >> 1

    candidates = {
        0, 1, half, half + 1, max_val - 1, max_val,
        0x55 & max_val, 0xAA & max_val,
    }
    if width_bytes >= 2:
        candidates |= frozenset({256, 1024, 32768, 255})

    if width_bytes >= 4:
        candidates |= {2147483647, 2147483648}

    return sorted(v for v in candidates if v <= max_val)


def pack_le(val: int, width: int) -> bytes:
    """
    Pack integer val as little-endian bytes.

    Args:
        val:   Integer value (truncated to width bytes).
        width: Number of bytes (1, 2, or 4).

    Returns:
        Little-endian bytes.
    """
    return val.to_bytes(width, 'little')


def pack_be(val: int, width: int) -> bytes:
    """
    Pack integer val as big-endian bytes.

    Args:
        val:   Integer value (truncated to width bytes).
        width: Number of bytes.

    Returns:
        Big-endian bytes.
    """
    return val.to_bytes(width, 'big')


def mutate_field(val: int, width_bytes: int, seed: Optional[int] = None) -> Iterator[Tuple[str, int]]:
    """
    Yield (label, mutated_value) for all field-level mutations.

    Includes all boundary values from field_boundary_values() plus
    small ±1/±2 offsets around the original value.

    Args:
        val:         Original field value.
        width_bytes: Field width in bytes.
        seed:        Unused (reserved for future random field mutations).

    Yields:
        (description, mutated_integer) — human-readable label + mutated value.
    """
    max_val = (1 << (8 * width_bytes)) - 1
    boundaries = field_boundary_values(width_bytes)

    for bval in boundaries:
        yield 'boundary_0x' + format(bval, 'x'), bval

    for delta in (-2, -1, 1, 2):
        candidate = val + delta
        if 0 <= candidate <= max_val:
            yield 'offset_' + ('+d' if delta > 0 else str(delta)) + '_from_0x' + format(val, 'x'), candidate


# ── Level 3: IE structural mutation ──────────────────────────────────────────

def ie_build(tag: int, body: bytes) -> bytes:
    """
    Build a correctly-formed 802.11 Information Element.

    Format: [tag(1)] [length(1)] [body(length)]

    Args:
        tag:  IE tag number (0–255).
        body: IE body bytes (max 255 bytes).

    Returns:
        2 + len(body) bytes.

    Raises:
        ValueError if tag out of range or body > 255 bytes.
    """
    if not (0 <= tag <= 255):
        raise ValueError('IE tag must be 0-255, got ' + str(tag))
    if len(body) > 255:
        raise ValueError('IE body max 255 bytes, got ' + str(len(body)))
    return bytes([tag, len(body)]) + body


def ie_wrong_length(tag: int, body: bytes, claimed_len: Optional[int] = None) -> bytes:
    """
    Build IE where the length field does NOT match the actual body.

    Triggers over-read (claimed > actual) or under-read (claimed < actual)
    in IE parsers. The most common IE parsing vulnerability class.

    Args:
        tag:         IE tag number.
        body:        Actual IE body bytes (written verbatim after length field).
        claimed_len: Length value to write. Defaults to min(2*actual+1, 255).

    Returns:
        Malformed IE bytes.

    Example:
        >>> ie_wrong_length(0, b"net", claimed_len=255)
        b'\\x00\\xff net'  # SSID IE claiming 255 bytes but only 3 present
    """
    if claimed_len is None:
        claimed_len = min(2 * len(body) + 1, 255)
    return bytes([tag, claimed_len & 0xFF]) + body


def ie_truncated(tag: int, body: bytes, keep: int = None) -> bytes:
    """
    Build IE with body truncated but length claiming the full original size.

    Forces parser to read bytes past actual data into adjacent IEs or garbage.

    Args:
        tag:  IE tag number.
        body: Full intended IE body.
        keep: How many bytes of body to actually include (0 <= keep <= len(body)).

    Returns:
        Malformed IE: length = len(body), actual body = body[:keep].
    """
    if keep is None:
        keep = len(body) // 2
    return bytes([tag, len(body)]) + body[:keep]


def ie_extended_body(tag: int, body: bytes, extra: bytes) -> bytes:
    """
    Build IE with body extended beyond what the length field claims.

    The length field reflects only the original body. The extra bytes
    follow silently, misaligning subsequent IE parsing.

    Args:
        tag:   IE tag number.
        body:  Intended body (length field = len(body)).
        extra: Extra bytes appended after (invisible to length-respecting parsers).

    Returns:
        IE bytes with hidden extra data.
    """
    return bytes([tag, len(body)]) + body + extra


def ie_zero_length(tag: int) -> bytes:
    """
    Build IE with length=0 (empty body).

    Tests parser handling of zero-length IEs. Many parsers allocate
    memory based on length and may behave incorrectly at length=0.

    Args:
        tag: IE tag number.

    Returns:
        2-byte IE: [tag][0x00].
    """
    return bytes([tag, 0])


def ie_max_length_claim(tag: int, body_len: int = 16) -> bytes:
    """
    Build IE claiming length=255 (maximum) with a short body.

    Forces parser to over-read up to 255 bytes starting from the IE body,
    potentially reading into other IEs, frame padding, or uninitialized memory.

    Args:
        tag:      IE tag number.
        body_len: Actual body bytes to include (default 16).

    Returns:
        IE claiming 255 bytes but only body_len bytes present.
    """
    import os
    return bytes([tag, 255]) + os.urandom(body_len)


def ie_extended_tag(ext_id: int, body: bytes) -> bytes:
    """
    Build an Extended IE (tag=255) with a specific Extension ID.

    Used for 802.11ax IEs: HE Capabilities (ext_id=35), HE Operation (36),
    UORA Parameters (37), etc. Unknown ext_ids test the extension dispatcher.

    Format: [0xFF][1+len(body)][ext_id][body]

    Args:
        ext_id: Extension ID byte (0–255).
        body:   IE body bytes after the ext_id.

    Returns:
        Extended IE bytes.

    Example:
        >>> ie_extended_tag(200, b"\\xde\\xad")  # unknown extension
        b'\\xff\\x03\\xc8\\xde\\xad'
    """
    inner = bytes([ext_id]) + body
    return bytes([255, len(inner)]) + inner


def ie_all_mutations(tag: int, body: bytes, seed: Optional[int] = None) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, ie_bytes) for all structural IE mutations of one IE.

    Each mutation targets a different parser vulnerability class:
      correct          → baseline (no mutation, verifies parser accepts valid)
      zero_len         → length=0, tests null/empty handling
      wrong_len_2x     → claimed length = 2× actual, triggers overread
      wrong_len_255    → claimed length = 255, maximum overread
      wrong_len_1      → claimed length = 1, truncated read
      truncated_half   → body cut in half, length unchanged
      truncated_1      → body = 1 byte, length = original
      extended_8       → 8 extra bytes appended (misaligns next IE)
      max_claim        → 255 claimed, only 16 bytes present

    Args:
        tag:  IE tag number.
        body: Original correct IE body.
        seed: Unused (reserved).

    Yields:
        (label, mutated_ie_bytes)
    """
    yield 'correct',        ie_build(tag, body)
    yield 'zero_len',       ie_zero_length(tag)
    yield 'wrong_len_2x',   ie_wrong_length(tag, body, min(2 * len(body), 255))
    yield 'wrong_len_255',  ie_wrong_length(tag, body, 255)
    yield 'wrong_len_1',    ie_wrong_length(tag, body, 1)
    yield 'truncated_half', ie_truncated(tag, body, len(body) // 2)
    yield 'truncated_1',    ie_truncated(tag, body, 1)
    yield 'extended_8',     ie_extended_body(tag, body, b'\xde\xad\xbe\xef\xca\xfe\xba\xbe')
    yield 'max_claim',      ie_max_length_claim(tag, 16)

"""
def recursive_ie_mutations(ies, depth):

Then randomly:

mutate N IEs
duplicate them
shuffle order
partially truncate stacks
overlap lengths

This explodes coverage massively.
"""

# ── Level 4: Sequence mutation (FSM-level) ────────────────────────────────────

@dataclass
class SequenceMutation:
    """
    Describes a protocol state machine (FSM) level mutation.

    Unlike byte/field/IE mutations that corrupt frame content,
    sequence mutations violate the ORDER or PRESENCE of frames
    in the 802.11 connection protocol.

    Attributes:
        kind:        Type of mutation: "replay", "reorder", "skip", "early", "delay"
        target:      Frame type or handshake phase being targeted.
        count:       For replay: repetitions. For delay: seconds. Default 1.
        description: Human-readable description for logging.

    FSM violations target:
      - 4-way handshake state tracking (EAPOL)
      - Association state machine
      - Block Ack session management
      - SA Query PMF protocol
    """
    kind:        str
    target:      str
    count:       int = 1
    description: str = ''


EAPOL_SEQUENCE_MUTATIONS: List[SequenceMutation] = [
    SequenceMutation('replay', 'msg1',
        description='Replay EAPOL Message 1 five times (ANonce flood)'),
    SequenceMutation('replay', 'msg3',
        description='Replay EAPOL Message 3 (retransmit GTK install)'),
    SequenceMutation('skip',   'msg4',
        description='Skip EAPOL Message 4 — AP never confirms key install'),
    SequenceMutation('early',  'msg4',
        description='Send Msg4 before receiving Msg3 (out-of-order)'),
    SequenceMutation('delay',  'msg2', count=10,
        description='Delay Msg2 by 10s (trigger AP timeout + retry)'),
]

POST_AUTH_SEQUENCE_MUTATIONS: List[SequenceMutation] = [
    SequenceMutation('replay', 'assoc',
        description='Send Association Request 3x while already associated'),
]
