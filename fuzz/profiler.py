"""
AP capability extraction via beacon frame analysis.

Profiles the target AP before fuzzing to automatically tune
which mutation phases to run (HT/VHT/HE, PMF, vendor OUI, etc.).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt


class SecurityType(Enum):
    OPEN    = 'open'
    WPA     = 'wpa'
    WPA2    = 'wpa2'
    WPA3    = 'wpa3'
    UNKNOWN = 'unknown'


@dataclass
class APProfile:
    """
    Extracted capability profile of a target AP.

    Built from beacon frame IEs. Used by FuzzCampaign to decide
    which mutation phases to enable and which OUIs to target.

    Attributes:
        ssid:         AP SSID string.
        bssid:        AP BSSID MAC address.
        channel:      Operating channel (from DS Param IE or HT/VHT).
        security:     Detected WPA version.
        ht_cap:       True if HT Capabilities IE present.
        vht_cap:      True if VHT Capabilities IE present.
        he_cap:       True if HE Capabilities extended IE present.
        pmf_required: True if RSN caps indicate MFP required (bit 6).
        pmf_capable:  True if RSN caps indicate MFP capable (bit 7).
        vendor_ouis:  Set of 3-byte OUIs seen in vendor IEs.
        rsn_akms:     List of AKM suite bytes from RSN IE.
        raw_ies:      Raw bytes of all IEs from beacon.
    """
    ssid:         str                = ''
    bssid:        str                = ''
    channel:      int                = 0
    security:     SecurityType       = SecurityType.UNKNOWN
    ht_cap:       bool               = False
    vht_cap:      bool               = False
    he_cap:       bool               = False
    pmf_required: bool               = False
    pmf_capable:  bool               = False
    vendor_ouis:  Set[bytes]         = field(default_factory=set)
    rsn_akms:     List[bytes]        = field(default_factory=list)
    raw_ies:      bytes              = b''

    def __str__(self) -> str:
        caps = []
        if self.ht_cap:  caps.append('HT')
        if self.vht_cap: caps.append('VHT')
        if self.he_cap:  caps.append('HE')
        pmf = ('PMF-req' if self.pmf_required else
               'PMF-cap' if self.pmf_capable  else 'no-PMF')
        return (f"SSID={self.ssid!r} BSSID={self.bssid} ch={self.channel} "
                f"sec={self.security.value} caps={'+'.join(caps) or 'none'} "
                f"{pmf} ouis={len(self.vendor_ouis)}")


def profile_from_beacon(frame) -> APProfile:
    """
    Build an APProfile from a captured beacon frame.

    Parses all IEs and extracts capability indicators.

    Args:
        frame: Scapy packet containing Dot11Beacon.

    Returns:
        Populated APProfile.
    """
    profile = APProfile()

    if not frame.haslayer(Dot11):
        return profile

    profile.bssid = frame[Dot11].addr2 or ''

    # Walk all Dot11Elt layers
    ie_raw = b''
    layer = frame
    while layer:
        if isinstance(layer, Dot11Elt):
            tag  = layer.ID
            body = bytes(layer.info) if layer.info else b''
            ie_raw += bytes([tag, len(body)]) + body

            if tag == 0:   # SSID
                try:
                    profile.ssid = body.decode('utf-8', errors='replace')
                except Exception:
                    pass

            elif tag == 3:  # DS Parameter Set (channel)
                if body:
                    profile.channel = body[0]

            elif tag == 45:  # HT Capabilities
                profile.ht_cap = True

            elif tag == 48:  # RSN IE → WPA2 or WPA3
                _parse_rsn(profile, body)

            elif tag == 191: # VHT Capabilities
                profile.vht_cap = True

            elif tag == 221: # Vendor Specific
                if len(body) >= 3:
                    profile.vendor_ouis.add(bytes(body[:3]))
                    # WPA (Microsoft OUI) = WPA1
                    if body[:4] == b'\x00\x50\xf2\x01':
                        if profile.security == SecurityType.UNKNOWN:
                            profile.security = SecurityType.WPA

            elif tag == 255: # Extension element (HE = ext_id 35)
                if body and body[0] == 35:
                    profile.he_cap = True

        if hasattr(layer, 'payload') and layer.payload:
            layer = layer.payload
        else:
            break

    profile.raw_ies = ie_raw

    if profile.security == SecurityType.UNKNOWN and not profile.vendor_ouis:
        profile.security = SecurityType.OPEN

    return profile


def _parse_rsn(profile: APProfile, body: bytes) -> None:
    """Extract security type and PMF flags from RSN IE body."""
    if len(body) < 2:
        return

    offset = 0
    # Version (2)
    offset += 2
    # Group cipher (4)
    offset += 4
    # Pairwise count + suites
    if offset + 2 > len(body):
        return
    pc = struct.unpack_from('<H', body, offset)[0]
    offset += 2 + 4 * pc
    # AKM count + suites
    if offset + 2 > len(body):
        return
    ac = struct.unpack_from('<H', body, offset)[0]
    offset += 2
    akms = []
    for _ in range(ac):
        if offset + 4 > len(body):
            break
        akms.append(bytes(body[offset:offset+4]))
        offset += 4
    profile.rsn_akms = akms

    # Detect WPA3 via SAE AKM (00:0f:ac:08)
    SAE = b'\x00\x0f\xac\x08'
    if any(a == SAE for a in akms):
        profile.security = SecurityType.WPA3
    else:
        profile.security = SecurityType.WPA2

    # RSN Capabilities (2 bytes)
    if offset + 2 <= len(body):
        caps = struct.unpack_from('<H', body, offset)[0]
        profile.pmf_required = bool(caps & (1 << 6))
        profile.pmf_capable  = bool(caps & (1 << 7))


def sniff_and_profile(iface: str, target_ssid: str = None,
                      target_bssid: str = None, timeout: int = 15) -> Optional[APProfile]:
    """
    Sniff beacons on iface and return APProfile for matching AP.

    Args:
        iface:        Monitor-mode interface to sniff on.
        target_ssid:  Filter by SSID (optional).
        target_bssid: Filter by BSSID MAC (optional).
        timeout:      Max seconds to sniff (default 15).

    Returns:
        APProfile if matching beacon found, None on timeout.
    """
    result: list = []

    def _handler(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        p = profile_from_beacon(pkt)
        if target_bssid and p.bssid.lower() != target_bssid.lower():
            return
        if target_ssid and p.ssid != target_ssid:
            return
        result.append(p)

    sniff(iface=iface, prn=_handler, timeout=timeout,
          stop_filter=lambda _: len(result) > 0)

    return result[0] if result else None
