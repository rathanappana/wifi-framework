"""
Grammar-aware IE mutation generators for 802.11 fuzzing.

Generates field-valid-but-semantically-broken IEs by understanding
the exact byte layout of each IE type. Imports from fuzz.mutator
for primitive building blocks.
"""
from __future__ import annotations

import struct
from typing import Iterator, List, Optional, Tuple

from fuzz.mutator import (
    ie_build, ie_wrong_length, ie_truncated, ie_zero_length,
    ie_max_length_claim, ie_extended_tag,
    field_boundary_values, pack_le,
    byte_mutate, ByteStrategy,
)

# ── AKM suite selectors (OUI 00:0F:AC) ───────────────────────────────────────

AKM_8021X       = b'\x00\x0f\xac\x01'
AKM_PSK         = b'\x00\x0f\xac\x02'
AKM_FT_8021X    = b'\x00\x0f\xac\x03'
AKM_FT_PSK      = b'\x00\x0f\xac\x04'
AKM_8021X_SHA256 = b'\x00\x0f\xac\x05'
AKM_PSK_SHA256  = b'\x00\x0f\xac\x06'
AKM_SAE         = b'\x00\x0f\xac\x08'
AKM_OWE         = b'\x00\x0f\xac\x12'

# ── Cipher suite selectors ────────────────────────────────────────────────────

CIPHER_WEP40    = b'\x00\x0f\xac\x01'
CIPHER_TKIP     = b'\x00\x0f\xac\x02'
CIPHER_CCMP128  = b'\x00\x0f\xac\x04'
CIPHER_CCMP256  = b'\x00\x0f\xac\x0a'
CIPHER_GCMP128  = b'\x00\x0f\xac\x08'


# ── RSN IE builder + mutations ────────────────────────────────────────────────

def _build_rsn_body(
    version:      int,
    group_cipher: bytes,
    pairwise:     List[bytes],
    akms:         List[bytes],
    rsn_caps:     int,
    pmkid_count:  int = 0,
    pmkid_list:   bytes = b'',
) -> bytes:
    """
    Build an RSN IE body (without the tag/length wrapper).

    RSN IE body structure (IEEE 802.11-2020, Section 9.4.2.24):
      Version(2) + GroupCipher(4) + PairwiseCount(2) + PairwiseSuites(4n)
      + AKMCount(2) + AKMSuites(4m) + RSNCaps(2) + [PMKIDCount(2) + PMKIDs(16k)]

    Args:
        version:      RSN version (should be 1; other values trigger bugs).
        group_cipher: 4-byte group cipher suite selector.
        pairwise:     List of 4-byte pairwise cipher suite selectors.
        akms:         List of 4-byte AKM suite selectors.
        rsn_caps:     16-bit RSN Capabilities field.
        pmkid_count:  Number of PMKIDs in list.
        pmkid_list:   Raw PMKID bytes (pmkid_count * 16 bytes normally).

    Returns:
        RSN IE body bytes (to be wrapped with ie_build(48, body)).
    """
    body = struct.pack('<H', version)
    body += group_cipher
    body += struct.pack('<H', len(pairwise))
    for cipher in pairwise:
        body += cipher
    body += struct.pack('<H', len(akms))
    for akm in akms:
        body += akm
    body += struct.pack('<H', rsn_caps)
    if pmkid_count > 0 or pmkid_list:
        body += struct.pack('<H', pmkid_count)
        body += pmkid_list
    return body


def build_rsn_wpa2_psk() -> bytes:
    """Build a minimal valid RSN IE for WPA2-PSK (CCMP)."""
    body = _build_rsn_body(
        version=1, group_cipher=CIPHER_CCMP128,
        pairwise=[CIPHER_CCMP128], akms=[AKM_PSK], rsn_caps=0,
    )
    return ie_build(48, body)


def build_rsn_wpa2_eap() -> bytes:
    """Build a minimal valid RSN IE for WPA2-Enterprise (CCMP)."""
    body = _build_rsn_body(
        version=1, group_cipher=CIPHER_CCMP128,
        pairwise=[CIPHER_CCMP128], akms=[AKM_8021X], rsn_caps=0,
    )
    return ie_build(48, body)


def build_rsn_wpa3_sae() -> bytes:
    """Build a minimal valid RSN IE for WPA3-SAE (CCMP)."""
    body = _build_rsn_body(
        version=1, group_cipher=CIPHER_CCMP128,
        pairwise=[CIPHER_CCMP128], akms=[AKM_SAE],
        rsn_caps=0x00C0,  # MFP required + capable
    )
    return ie_build(48, body)


def mutations_rsn(base_akms: List[bytes] = None) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, ie_bytes) for all RSN IE field-level mutations.

    Mutations cover:
      - Version: all boundary values (0, 1, 2, 32767, 65535)
      - Group cipher: invalid suites, all-zeros, all-ones
      - Pairwise count: 0, 1, 255, 1023 — body stays at 1 suite
      - AKM count: 0, 255 — body stays at 1 AKM
      - RSN Caps: each bit individually, all-ones, all-zeros
      - PMKID count: 1, 255 with no actual PMKID data
      - Structural: truncated body, empty IE, wrong length field

    Args:
        base_akms: AKMs to use in baseline (default: [AKM_PSK]).

    Yields:
        (description, full_ie_bytes_including_tag_and_length)
    """
    if base_akms is None:
        base_akms = [AKM_PSK]

    # Baseline
    base_body = _build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128], base_akms, 0)
    yield 'rsn-baseline', ie_build(48, base_body)

    # Version mutations
    for v in field_boundary_values(2):
        body = _build_rsn_body(v, CIPHER_CCMP128, [CIPHER_CCMP128], base_akms, 0)
        yield f'rsn-version-{v}', ie_build(48, body)

    # Group cipher mutations
    for gc, label in [
        (b'\x00\x0f\xac\x02', 'group-tkip'),
        (b'\x00\x0f\xac\x01', 'group-wep40'),
        (b'\x00\x00\x00\x00', 'group-all-zeros'),
        (b'\xff\xff\xff\xff', 'group-all-ones'),
        (b'\xde\xad\xbe\x04', 'group-invalid-oui'),
    ]:
        body = _build_rsn_body(1, gc, [CIPHER_CCMP128], base_akms, 0)
        yield f'rsn-{label}', ie_build(48, body)

    # Pairwise count boundary (count field != actual suite count)
    for count in (1, 5, 255):
        raw = struct.pack('<H', 1) + CIPHER_CCMP128  # version+group
        raw += struct.pack('<H', 1) + CIPHER_CCMP128  # pairwise count=1, 1 suite
        # Overwrite pairwise count field with boundary value
        raw_list = bytearray(raw)
        struct.pack_into('<H', raw_list, 6, count)
        raw_list += struct.pack('<H', len(base_akms))
        for akm in base_akms:
            raw_list += akm
        raw_list += struct.pack('<H', 0)
        yield f'rsn-pairwise-count-{count}', ie_build(48, bytes(raw_list))

    # AKM count boundary
    for count in (1, 5, 255):
        body = bytearray(_build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128], base_akms, 0))
        # AKM count is at offset 10
        struct.pack_into('<H', body, 10, count)
        yield f'rsn-akm-count-{count}', ie_build(48, bytes(body))

    # AKM suite substitutions
    for akm_label, akm in [
        ('akm-8021x', AKM_8021X), ('akm-psk', AKM_PSK),
        ('akm-ft-8021x', AKM_FT_8021X), ('akm-ft-psk', AKM_FT_PSK),
        ('akm-sae', AKM_SAE), ('akm-owe', AKM_OWE),
        ('akm-zero-type', b'\x00\x0f\xac\x00'),
        ('akm-reserved-20', b'\x00\x0f\xac\x14'),
        ('akm-all-ones', b'\xff\xff\xff\xff'),
    ]:
        body = _build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128], [akm], 0)
        yield akm_label, ie_build(48, body)

    # RSN Caps: each bit individually
    for bit in range(16):
        caps = 1 << bit
        body = _build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128], base_akms, caps)
        yield f'rsn-caps-bit{bit}', ie_build(48, body)
    body = _build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128], base_akms, 65535)
    yield 'rsn-caps-all-ones', ie_build(48, body)

    # PMKID count with no actual PMKID data
    for pmkid_count in (1, 255):
        body = _build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128], base_akms, 0,
                               pmkid_count=pmkid_count, pmkid_list=b'')
        yield f'rsn-pmkid-count-{pmkid_count}', ie_build(48, body)

    # Structural mutations on baseline body
    yield 'ie-wrong-len-255',  ie_wrong_length(48, base_body, 255)
    yield 'ie-wrong-len-1',    ie_wrong_length(48, base_body, 1)
    yield 'ie-truncated-2',    ie_truncated(48, base_body, 2)
    yield 'ie-truncated-8',    ie_truncated(48, base_body, 8)
    yield 'ie-zero-len',       ie_zero_length(48)
    yield 'ie-max-claim',      ie_max_length_claim(48, 8)

    # Byte-level body mutations
    for strat in (ByteStrategy.random, ByteStrategy.boundary, ByteStrategy.xor_aa):
        body = byte_mutate(len(base_body), strat)[:255]
        yield f'rsn-body-{strat.value}', ie_build(48, body)


# ── HT Capabilities IE ───────────────────────────────────────────────────────

def build_ht_cap() -> bytes:
    """
    Build a valid HT Capabilities IE.

    HT Cap body is exactly 26 bytes (IEEE 802.11-2020, Section 9.4.2.56):
      HT Cap Info(2) + AMPDU Params(1) + Supported MCS(16) + HT Ext Cap(2)
      + Tx Beamforming(4) + ASEL(1) = 26 bytes
    """
    body = b'\x6e\x00' + b'\x00' * 24
    return ie_build(45, body)


def mutations_ht() -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, ie_bytes) for HT Capabilities IE mutations.

    Key mutations:
      - Wrong body length (spec requires exactly 26 bytes)
      - All capabilities set (all-ones in every field)
      - HT Cap Info field boundary values
      - Body byte-level strategies
    """
    base_body = build_ht_cap()[2:]  # strip tag + length

    yield 'ht-correct',       ie_build(45, base_body)
    yield 'ht-all-ones',      ie_build(45, b'\xff' * 26)
    yield 'ht-all-zeros',     ie_build(45, b'\x00' * 26)
    yield 'ht-wrong-len-4',   ie_wrong_length(45, base_body[:4], 255)
    yield 'ht-wrong-len-255', ie_wrong_length(45, base_body, 255)
    yield 'ht-truncated-1',   ie_truncated(45, base_body, 1)
    yield 'ht-zero-len',      ie_zero_length(45)
    yield 'ht-max-claim',     ie_max_length_claim(45, 4)

    # HT Cap Info field (first 2 bytes) boundary values
    for val in field_boundary_values(2):
        body = struct.pack('<H', val) + base_body[2:]
        yield f'ht-cap-info-0x{val:04x}', ie_build(45, body)


# ── VHT Capabilities IE ───────────────────────────────────────────────────────

def build_vht_cap() -> bytes:
    """
    Build a valid VHT Capabilities IE.

    VHT Cap body is exactly 12 bytes (IEEE 802.11-2020, Section 9.4.2.158):
      VHT Cap Info(4) + Supported VHT MCS and NSS(8) = 12 bytes
    """
    body = b'\x32\x00\x00\x00' + b'\xfe\xff\x00\x00\x00\x00\x00\x00'
    return ie_build(191, body)


def mutations_vht() -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, ie_bytes) for VHT Capabilities IE mutations.

    Key mutations:
      - Wrong body length (spec requires exactly 12 bytes)
      - All capabilities set
      - VHT Cap Info boundary values
    """
    base_body = build_vht_cap()[2:]

    yield 'vht-correct',       ie_build(191, base_body)
    yield 'vht-all-ones',      ie_build(191, b'\xff' * 12)
    yield 'vht-all-zeros',     ie_build(191, b'\x00' * 12)
    yield 'vht-wrong-len-4',   ie_wrong_length(191, base_body[:4], 255)
    yield 'vht-wrong-len-255', ie_wrong_length(191, base_body, 255)
    yield 'vht-truncated-1',   ie_truncated(191, base_body, 1)
    yield 'vht-zero-len',      ie_zero_length(191)

    # VHT Cap Info (first 4 bytes) boundary values
    for val in field_boundary_values(4):
        body = struct.pack('<I', val) + base_body[4:]
        yield f'vht-cap-info-0x{val:08x}', ie_build(191, body)


# ── HE Capabilities IE (802.11ax) ─────────────────────────────────────────────

def build_he_cap() -> bytes:
    """
    Build a minimal HE Capabilities Extended IE.

    Uses a realistic minimal body — exact structure is complex and AP-specific.
    Returns the raw IE bytes including tag=255, length, ext_id=35.
    """
    he_mac_cap  = b'\x09\x01\x00\x00\x00\x00'          # 6 bytes
    he_phy_cap  = b'\x00' * 11                           # 11 bytes
    he_mcs_nss  = b'\xff\xff\xff\xff'                    # 4 bytes (80 MHz only)
    body        = he_mac_cap + he_phy_cap + he_mcs_nss
    return ie_extended_tag(35, body)


def mutations_he() -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, ie_bytes) for HE Capabilities IE mutations.

    Since HE Cap is an Extended IE (tag=255), also fuzz:
      - ext_id itself (use unknown ext_ids)
      - Zero-length extended IE
    """
    he_body = build_he_cap()[3:]  # strip tag=255, length, ext_id=35

    yield 'he-correct',    build_he_cap()
    yield 'he-all-ones',   ie_extended_tag(35, b'\xff' * 22)
    yield 'he-all-zeros',  ie_extended_tag(35, b'\x00' * 22)
    yield 'he-zero-body',  ie_extended_tag(35, b'')
    yield 'he-max-body',   ie_extended_tag(35, b'\xcc' * 200)

    # Unknown extension IDs
    for ext_id in (0, 34, 36, 100, 127, 200, 255):
        yield f'he-unknown-extid-{ext_id}', ie_extended_tag(ext_id, b'\xde\xad\xde\xad\xde\xad\xde\xad')

    yield 'he-ext-zero-len', bytes([255, 0])


# ── Supported Rates IE ────────────────────────────────────────────────────────

def mutations_rates() -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, ie_bytes) for Supported Rates IE mutations.

    Key mutations:
      - Empty rates (length=0)
      - Single invalid rate (0x00, 0xFF)
      - 9 rates (exceeds 8-rate maximum per spec)
      - All rates = basic-rate bit set (0x80+rate)
    """
    valid_4  = bytes([0x82, 0x84, 0x8b, 0x96])
    valid_8  = bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])

    yield 'rates-correct-4',  ie_build(1, valid_4)
    yield 'rates-correct-8',  ie_build(1, valid_8)
    yield 'rates-zero-len',   ie_zero_length(1)
    yield 'rates-all-zeros',  ie_build(1, b'\x00' * 8)
    yield 'rates-all-ones',   ie_build(1, b'\xff' * 8)
    yield 'rates-9-rates',    ie_build(1, valid_8 + b'\x30')
    yield 'rates-wrong-len',  ie_wrong_length(1, valid_8, 255)
    yield 'rates-max-claim',  ie_max_length_claim(1, 4)


# ── Vendor Specific IE ────────────────────────────────────────────────────────

OUI_BROADCOM   = b'\x00\x90\x4c'
OUI_MICROSOFT  = b'\x00\x50\xf2'
OUI_QUALCOMM   = b'\x00\x17\xf2'
OUI_CISCO      = b'\x00\x40\x96'


def build_vendor_ie(oui: bytes, type_byte: int, body: bytes) -> bytes:
    """
    Build a Vendor Specific IE (tag=221).

    Format: [0xDD][length][OUI(3)][type(1)][body]

    Args:
        oui:       3-byte OUI identifying the vendor.
        type_byte: Vendor-specific type/sub-type byte.
        body:      Vendor-specific payload.

    Returns:
        Complete vendor IE bytes.
    """
    content = oui + bytes([type_byte]) + body
    return ie_build(221, content)


def mutations_vendor(target_oui: bytes = None) -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, ie_bytes) for Vendor Specific IE mutations.

    Mutations cover:
      - Target OUI (default Broadcom) all sub-types 0–31 + boundaries
      - Multiple known OUIs (Microsoft WMM, Qualcomm, Cisco)
      - Truncated body (no OUI, only 1-2 bytes)
      - Wrong length field on vendor IE

    Args:
        target_oui: Primary OUI to exhaustively mutate sub-types for.

    Yields:
        (description, vendor_ie_bytes)
    """
    if target_oui is None:
        target_oui = OUI_BROADCOM

    oui_name = {OUI_BROADCOM: 'brcm', OUI_MICROSOFT: 'msft',
                OUI_QUALCOMM: 'qcom', OUI_CISCO: 'cisco'}.get(target_oui, 'unk')

    # Target OUI sub-type sweep
    for subtype in (64, 127, 128, 200, 255):
        for body_len in (0, 1, 10, 255):
            body = byte_mutate(max(1, body_len), ByteStrategy.boundary) if body_len else b''
            label = f'vendor-{oui_name}-sub{subtype}-bodylen{body_len}'
            yield label, build_vendor_ie(target_oui, subtype, body[:body_len])

    # Known OUIs with random subtypes + bodies
    for oui, name in [(OUI_BROADCOM, 'brcm'), (OUI_MICROSOFT, 'msft'),
                      (OUI_QUALCOMM, 'qcom'), (OUI_CISCO, 'cisco')]:
        for subtype in (0, 1, 4, 8, 16, 64, 200):
            body_bytes = b'\xde\xad\xbe\xef\xde\xad\xbe\xef'
            yield f'vendor-{name}-sub{subtype}', build_vendor_ie(oui, subtype, body_bytes)

    # Truncated bodies (no complete OUI)
    for body, desc in [(b'', 'no-body'), (b'\x00', '1-byte'),
                       (b'\x00\x90', '2-byte-partial-oui'),
                       (b'\x00\x90\x4c', 'oui-only')]:
        ie_raw = bytes([221, len(body)]) + body
        yield f'vendor-truncated-{desc}', ie_raw

    # Structural
    full_body = target_oui + bytes([1]) + b'\xaa\xbb\xcc\xdd' * 2
    yield 'vendor-wrong-len-255', ie_wrong_length(221, full_body, 255)
    yield 'vendor-wrong-len-1',   ie_wrong_length(221, full_body, 1)
    yield 'vendor-zero-len',      ie_zero_length(221)


# ── Stacked malformed IE blob ─────────────────────────────────────────────────

def malformed_ie_stack(include_broadcom: bool = True, include_he: bool = False) -> bytes:
    """
    Build a sequence of malformed IEs designed to stress IE parsers.

    Stacks multiple malformed IEs in one blob. Parsers that iterate
    IEs linearly using [tag][len][skip len bytes] can lose sync and
    misinterpret subsequent IEs when length fields are wrong.

    Args:
        include_broadcom: Include Broadcom vendor IE (for brcmfmac targets).
        include_he:       Include HE Cap IE (for 802.11ax APs).

    Returns:
        Concatenated malformed IE bytes.
    """
    blob = b''
    # RSN IE claiming 255 bytes
    blob += ie_wrong_length(48, b'\xde\xad', 255)
    # SSID with max-length claim
    blob += ie_max_length_claim(0, 4)
    # HT cap claiming 255
    blob += ie_wrong_length(45, b'A' * 26, 255)
    # Zero-length supported rates
    blob += ie_zero_length(1)
    # Garbage unknown IE
    blob += ie_build(200, b'\xff\xff\xff\xff')
    # Extended IE with unknown ext_id
    blob += ie_extended_tag(200, b'\xff' * 8)

    if include_broadcom:
        blob += build_vendor_ie(OUI_BROADCOM, 255, b'\xba\xad\xf0\x0d' * 4)

    if include_he:
        blob += ie_extended_tag(35, b'\xff' * 22)

    return blob


# ── Invalid capability combinations ──────────────────────────────────────────

def mutations_capability_combos() -> Iterator[Tuple[str, bytes]]:
    """
    Yield (label, ie_blob) for semantically invalid IE combinations.

    These violate cross-field constraints the spec mandates but parsers
    may not validate. Each combo is a full IE blob for insertion into
    an AssocReq or ProbeResp fixed fields + IEs.

    Violations targeted:
      - HT IE present but HT bit NOT set in capability field → parser skips HT but IE exists
      - VHT IE without HT IE → VHT requires HT first (IEEE 802.11ac 9.4.2.158)
      - HE IE without VHT/HT IEs → HE requires both
      - WPA3 SAE AKM but MFP not required (RSN caps bit 6=0) → WPA3 mandates MFP
      - CCMP group cipher with TKIP pairwise → downgrade attack vector
      - Two RSN IEs with different AKMs → parser takes first or last?
      - RSN with PMKID list but zero PMKID count field
      - Supported rates claiming 802.11b only but HT caps present
    """
    rates_basic = ie_build(1, bytes([0x82, 0x84, 0x8b, 0x96]))       # 802.11b rates only
    rates_ht    = ie_build(1, bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]))
    ht_ie       = build_ht_cap()
    vht_ie      = build_vht_cap()
    he_ie       = build_he_cap()

    rsn_wpa2    = build_rsn_wpa2_psk()
    # WPA3 SAE without MFP-required (bit 6 = 0, bit 7 = 0)
    rsn_sae_no_mfp_body = _build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128],
                                           [AKM_SAE], rsn_caps=0x0000)
    rsn_sae_no_mfp = ie_build(48, rsn_sae_no_mfp_body)

    # TKIP pairwise with CCMP group (downgrade)
    rsn_tkip_pairwise_body = _build_rsn_body(1, CIPHER_CCMP128,
                                              [CIPHER_TKIP], [AKM_PSK], rsn_caps=0)
    rsn_tkip_pairwise = ie_build(48, rsn_tkip_pairwise_body)

    # Two conflicting RSN IEs
    rsn_wpa3_mfp_body = _build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128],
                                         [AKM_SAE], rsn_caps=0x00C0)
    rsn_wpa3_mfp = ie_build(48, rsn_wpa3_mfp_body)

    # RSN with PMKID count=1 but zero actual PMKID data
    rsn_fake_pmkid_body = _build_rsn_body(1, CIPHER_CCMP128, [CIPHER_CCMP128],
                                           [AKM_PSK], rsn_caps=0,
                                           pmkid_count=1, pmkid_list=b'')
    rsn_fake_pmkid = ie_build(48, rsn_fake_pmkid_body)

    combos = [
        # HT IE without HT capability bit in cap field
        ('ht-ie-no-ht-cap-bit',    rates_ht + rsn_wpa2 + ht_ie),
        # VHT without HT IE
        ('vht-without-ht',         rates_ht + rsn_wpa2 + vht_ie),
        # HE without VHT and HT
        ('he-without-vht-ht',      rates_ht + rsn_wpa2 + he_ie),
        # VHT + HE without HT
        ('vht-he-without-ht',      rates_ht + rsn_wpa2 + vht_ie + he_ie),
        # WPA3 SAE but MFP not required
        ('sae-no-mfp',             rates_ht + rsn_sae_no_mfp + ht_ie),
        # TKIP pairwise (downgrade combo)
        ('tkip-pairwise-ccmp-grp', rates_ht + rsn_tkip_pairwise),
        # Dual RSN IEs (WPA2 + WPA3 — parser picks which?)
        ('dual-rsn-wpa2-wpa3',     rates_ht + rsn_wpa2 + rsn_wpa3_mfp),
        # Dual RSN IEs reversed
        ('dual-rsn-wpa3-wpa2',     rates_ht + rsn_wpa3_mfp + rsn_wpa2),
        # Fake PMKID count
        ('rsn-fake-pmkid-count',   rates_ht + rsn_fake_pmkid),
        # 802.11b rates only but HT IE present (contradictory)
        ('b-only-rates-ht-ie',     rates_basic + rsn_wpa2 + ht_ie),
        # Full contradictory stack: b-rates + RSN-SAE-no-MFP + HE-without-HT
        ('full-contradiction',     rates_basic + rsn_sae_no_mfp + he_ie),
    ]

    for label, ie_blob in combos:
        yield f'cap-combo-{label}', ie_blob
