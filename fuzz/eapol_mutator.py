"""
Grammar-aware EAPOL Key frame mutations for post-connection fuzzing.

EAPOL Key frame layout (IEEE 802.1X-2020, Section 11.9):
  EAP version (1) + packet type (1) + body length (2)
  + descriptor type (1)
  + key_info (2)       ← bit field: key type, version, install, ack, MIC, secure, error, request, enc, smk
  + key_length (2)     ← PTK/GTK length
  + replay_counter (8) ← anti-replay monotonic counter
  + key_nonce (32)     ← ANonce / SNonce
  + key_iv (16)        ← EAPOL-Key IV (always zero in modern WPA)
  + key_rsc (8)        ← Receive Sequence Counter (GTK installs)
  + reserved (8)
  + key_mic (16 or 32) ← MIC over entire EAPOL Key frame
  + key_data_length (2) ← length of key_data field
  + key_data (variable) ← actual data (often encrypted GTK or RSNE)

Attack surface:
  - key_data_length > len(key_data) → over-read in WPA key parser
  - key_data_length = 65535 → integer truncation / allocation overflow
  - key_info.install on msg1 → AP installs key at wrong state
  - key_info.key_type=0 (group) with PTK nonce → state confusion
  - replay_counter < last seen → replay attack test
  - wrong descriptor type (non-2, non-254) → unhandled path
  - key_data with nested RSNE inside encrypted key_data → parser into parser

No scapy imports — pure struct, usable standalone for building bytes.
"""
from __future__ import annotations

import os
import struct
from typing import Iterator, List, Optional, Tuple

from fuzz.mutator import field_boundary_values, byte_mutate, ByteStrategy


# ── EAPOL Key info bit field ───────────────────────────────────────────────────

class KeyInfo:
    """
    EAPOL Key Info field (2 bytes, big-endian).

    Bit layout (LSB to MSB in spec, but packed BE):
      bits[2:0]  = key_descriptor_version (1=HMAC-MD5/RC4, 2=HMAC-SHA1-128/AES, 3=AES-SIV)
      bit[3]     = key_type (1=pairwise, 0=group)
      bits[5:4]  = reserved
      bit[6]     = install (set in msg3 to install PTK)
      bit[7]     = key_ack (AP sends this)
      bit[8]     = key_mic (frame has MIC)
      bit[9]     = secure (after PTK installed)
      bit[10]    = error
      bit[11]    = request
      bit[12]    = encrypted_key_data
      bit[13]    = smk_message
    """
    # Standard msg configurations
    MSG1 = 0x008A  # ACK + pairwise + ver2
    MSG2 = 0x010A  # MIC + pairwise + ver2
    MSG3 = 0x13CA  # install + ACK + MIC + secure + enc + pairwise + ver2
    MSG4 = 0x030A  # MIC + secure + pairwise + ver2

    @staticmethod
    def build(version=2, key_type=1, install=0, ack=0, mic=0,
              secure=0, error=0, request=0, enc=0, smk=0) -> int:
        return (version & 0x7) | ((key_type & 1) << 3) | \
               ((install & 1) << 6) | ((ack & 1) << 7) | \
               ((mic & 1) << 8) | ((secure & 1) << 9) | \
               ((error & 1) << 10) | ((request & 1) << 11) | \
               ((enc & 1) << 12) | ((smk & 1) << 13)


# ── EAPOL Key frame builder ────────────────────────────────────────────────────

def build_eapol_key(
    key_info:       int,
    key_length:     int   = 16,
    replay_counter: int   = 1,
    nonce:          bytes = None,
    key_iv:         bytes = None,
    key_rsc:        bytes = None,
    mic:            bytes = None,
    key_data:       bytes = b'',
    claimed_key_data_len: int = None,
    descriptor_type: int  = 2,
) -> bytes:
    """
    Build a raw EAPOL Key frame.

    Args:
        key_info:             KeyInfo 2-byte value.
        key_length:           PTK/GTK length field (not actual data length).
        replay_counter:       8-byte counter (as int).
        nonce:                32-byte nonce (random if None).
        key_iv:               16-byte IV (zeros if None).
        key_rsc:              8-byte RSC (zeros if None).
        mic:                  16-byte MIC (zeros if None, meaning invalid MIC).
        key_data:             Actual key data bytes.
        claimed_key_data_len: Override the key_data_length field (for over-read attacks).
        descriptor_type:      EAPOL-Key descriptor type (2=WPA2, 254=WPA1).

    Returns:
        Raw EAPOL Key frame bytes (including EAPOL header).
    """
    nonce   = nonce   or os.urandom(32)
    key_iv  = key_iv  or b'\x00' * 16
    key_rsc = key_rsc or b'\x00' * 8
    mic     = mic     or b'\x00' * 16

    # claimed length — default = actual length
    kd_len = claimed_key_data_len if claimed_key_data_len is not None else len(key_data)

    body = bytes([descriptor_type])
    body += struct.pack('>H', key_info)
    body += struct.pack('>H', key_length)
    body += struct.pack('>Q', replay_counter & 0xFFFFFFFFFFFFFFFF)
    body += nonce[:32].ljust(32, b'\x00')
    body += key_iv[:16].ljust(16, b'\x00')
    body += key_rsc[:8].ljust(8, b'\x00')
    body += b'\x00' * 8   # reserved
    body += mic[:16].ljust(16, b'\x00')
    body += struct.pack('>H', kd_len & 0xFFFF)
    body += key_data

    # EAPOL header: version=2, type=3 (EAPOL-Key), length=len(body)
    header = struct.pack('>BBH', 2, 3, len(body))
    return header + body


# ── EAPOL Key mutations ────────────────────────────────────────────────────────

def mutations_key_data_length(replay_counter: int = 1) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, eapol_bytes) for key_data_length field mutations.

    PRIMARY TARGET: over-read in wpa_supplicant/mac80211 WPA key parser.

    When key_data_length > len(actual_key_data), the parser reads past
    the actual data into adjacent memory. On kernel side (mac80211 + WPA),
    this can expose heap contents or trigger a fault.

    Mutations:
      - claimed_len = actual + N  (over-read by N bytes)
      - claimed_len = 65535       (maximum, huge over-read)
      - claimed_len = 0           (under-read, parser skips key_data)
      - claimed_len = 1           (one byte, even if key_data is larger)
      - actual_len = 0, claimed = 16  (no data but claims 16 bytes)
    """
    actual_data = os.urandom(16)  # typical WPA key data size

    for over in (1, 2, 4, 8, 16, 32, 64, 128, 255):
        frame = build_eapol_key(
            key_info=KeyInfo.MSG3, replay_counter=replay_counter,
            key_data=actual_data,
            claimed_key_data_len=len(actual_data) + over,
        )
        yield f'kd-len-over-{over}', frame

    # Maximum over-read
    frame = build_eapol_key(
        key_info=KeyInfo.MSG3, replay_counter=replay_counter,
        key_data=actual_data, claimed_key_data_len=65535,
    )
    yield 'kd-len-65535', frame

    # Under-read
    for under in (0, 1):
        frame = build_eapol_key(
            key_info=KeyInfo.MSG3, replay_counter=replay_counter,
            key_data=actual_data, claimed_key_data_len=under,
        )
        yield f'kd-len-{under}', frame

    # Empty data, non-zero claimed
    for claimed in (1, 16, 255, 65535):
        frame = build_eapol_key(
            key_info=KeyInfo.MSG3, replay_counter=replay_counter,
            key_data=b'', claimed_key_data_len=claimed,
        )
        yield f'kd-len-empty-data-claim-{claimed}', frame


def mutations_key_info(replay_counter: int = 1) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, eapol_bytes) for KeyInfo field mutations.

    KeyInfo bits control:
      - Which crypto algorithm to use (descriptor version bits)
      - Whether to install the key (install bit)
      - Whether frame has valid MIC (key_mic bit)
      - Whether key_data is encrypted (enc bit)

    Parser bugs when bits are unexpected:
      - install=1 on msg1 → AP tries to install key before handshake done
      - version=0 → undefined algorithm → unhandled code path
      - all bits set → parser confusion about frame type
      - key_type=0 (group) with unicast nonce → state confusion
    """
    nonce = os.urandom(32)
    kd    = os.urandom(16)

    for ki_val, label in [
        (KeyInfo.MSG1,              'std-msg1'),
        (KeyInfo.MSG3,              'std-msg3'),
        (KeyInfo.build(version=0),  'version-0-undefined'),
        (KeyInfo.build(version=1),  'version-1-hmac-md5'),
        (KeyInfo.build(version=3),  'version-3-aes-siv'),
        (KeyInfo.build(version=7),  'version-7-reserved'),
        (KeyInfo.build(install=1, ack=1, key_type=1),     'install-on-msg1'),
        (KeyInfo.build(key_type=0, mic=1, secure=1),      'group-key-type'),
        (KeyInfo.build(error=1, request=1),                'error-request'),
        (KeyInfo.build(enc=1, mic=0),                      'enc-no-mic'),
        (0x0000,                                           'all-zero'),
        (0xFFFF,                                           'all-ones'),
        (0x8000,                                           'smk-bit-only'),
    ]:
        frame = build_eapol_key(
            key_info=ki_val, replay_counter=replay_counter,
            nonce=nonce, key_data=kd,
        )
        yield f'key-info-{label}', frame


def mutations_replay_counter(last_counter: int = 5) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, eapol_bytes) for replay counter mutations.

    Replay counters used by AP to detect retransmits:
      - counter < last seen → should be rejected (replay attack test)
      - counter = 0 → initial state confusion
      - counter = 2^64-1 → wrap-around
      - rapid flood same counter → anti-replay state exhaustion
    """
    kd = os.urandom(16)

    for rc, label in [
        (0,                     'rc-zero'),
        (1,                     'rc-one'),
        (last_counter - 1,      'rc-below-last'),
        (last_counter,          'rc-same-as-last'),
        (last_counter + 1,      'rc-next'),
        (0xFFFFFFFFFFFFFFFF,    'rc-max'),
        (0xFFFFFFFFFFFFFFFE,    'rc-max-minus-1'),
    ]:
        frame = build_eapol_key(
            key_info=KeyInfo.MSG4, replay_counter=max(0, rc),
            key_data=kd,
        )
        yield f'replay-{label}', frame

    # Flood same counter 10×
    for i in range(10):
        frame = build_eapol_key(
            key_info=KeyInfo.MSG2, replay_counter=last_counter,
            key_data=os.urandom(16),
        )
        yield f'replay-flood-same-{i}', frame


def mutations_descriptor_type(replay_counter: int = 1) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, eapol_bytes) for descriptor type field mutations.

    Descriptor type = 2 (WPA2/IEEE 802.11i) or 254 (WPA1/RSN).
    Other values may hit unhandled switch/case in parser.
    """
    kd = os.urandom(16)

    for dt, label in [
        (0,   'dt-zero'),
        (1,   'dt-one'),
        (2,   'dt-wpa2'),
        (3,   'dt-three'),
        (127, 'dt-127'),
        (128, 'dt-128'),
        (253, 'dt-253'),
        (254, 'dt-wpa1'),
        (255, 'dt-255'),
    ]:
        frame = build_eapol_key(
            key_info=KeyInfo.MSG3, replay_counter=replay_counter,
            key_data=kd, descriptor_type=dt,
        )
        yield f'desc-type-{label}', frame


def mutations_key_data_content(replay_counter: int = 1) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, eapol_bytes) for key_data content mutations.

    key_data in msg3 is encrypted GTK + RSNE. Corrupting the structure
    tests the inner parser that runs AFTER decryption.

    Key mutations:
      - Nested RSN IE inside key_data (RSNE with wrong length)
      - key_data = all zeros (GTK decrypts to zeros → null key install)
      - key_data = all ones
      - key_data with garbage KDE header (wrong type, wrong length)
      - Empty key_data with claimed > 0 (already in key_data_length mutations)
    """
    # KDE (Key Data Encapsulation) structure: OUI(3) + data_type(1) + data
    KDE_GTK   = b'\x00\x0f\xac\x01'  # GTK KDE
    KDE_RSNIE = b'\x00\x0f\xac\x02'  # RSNIE KDE (for msg3)

    for kd, label in [
        (b'\x00' * 16,                            'kd-all-zeros'),
        (b'\xff' * 16,                            'kd-all-ones'),
        (b'\xde\xad\xbe\xef' * 4,                'kd-deadbeef'),
        (KDE_GTK + b'\x00' * 12,                  'kd-gtk-kde-short'),
        (KDE_GTK + b'\xff' * 32,                  'kd-gtk-kde-long'),
        # Nested RSNE with wrong length
        (bytes([48, 255]) + b'\x01\x00' + b'\x00' * 20, 'kd-nested-rsn-wrong-len'),
        # KDE with zero data_type
        (b'\x00\x0f\xac\x00' + b'\x00' * 8,      'kd-kde-zero-type'),
        # Empty
        (b'',                                      'kd-empty'),
        # 255 bytes
        (os.urandom(255),                          'kd-255-random'),
    ]:
        frame = build_eapol_key(
            key_info=KeyInfo.MSG3, replay_counter=replay_counter,
            key_data=kd,
        )
        yield f'key-data-{label}', frame


def all_eapol_mutations(replay_counter: int = 1) -> Iterator[Tuple[str, bytes]]:
    """
    Yield all EAPOL Key mutations in priority order.

    Priority:
      1. key_data_length — most likely to trigger over-read (highest CVE yield)
      2. key_info — state machine confusion
      3. descriptor_type — unhandled parser path
      4. replay_counter — anti-replay bypass
      5. key_data content — inner parser corruption
    """
    yield from mutations_key_data_length(replay_counter)
    yield from mutations_key_info(replay_counter)
    yield from mutations_descriptor_type(replay_counter)
    yield from mutations_replay_counter(replay_counter)
    yield from mutations_key_data_content(replay_counter)
