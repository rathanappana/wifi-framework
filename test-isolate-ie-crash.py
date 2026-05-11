"""
Isolated test for RSN IE mutations that triggered AP disconnect (reason=9).

During the full campaign ie-fuzzing phase, the AP disconnected with reason=9
between alive checks at frames [99] and [119]. Candidate frames:

  [102] rsn-assoc-ie-wrong-len-255   — RSN IE length=255, actual body << 255
  [103] rsn-reassoc-ie-wrong-len-255
  [110] rsn-assoc-ie-zero-len        — RSN IE length=0
  [111] rsn-reassoc-ie-zero-len
  [112] rsn-assoc-ie-max-claim       — RSN IE length=0xFF, body=2 bytes
  [113] rsn-reassoc-ie-max-claim
  [114] rsn-assoc-rsn-body-random
  [115] rsn-reassoc-rsn-body-random
  ...

check_interval=1 so every frame gets a liveness check. On disconnect,
save frame to /tmp/ie_crash_culprit_*.bin and stop.

Run:
  sudo python3 run.py wlan0 ie-crash-isolate --config ~/iith/iith_wpa.conf
"""
import struct, time

from dependencies.libwifi.wifi import log, STATUS
from library.testcase import Trigger, Action, Test
from fuzz.mutator import ie_build, ie_wrong_length, ie_truncated, ie_zero_length, ie_max_length_claim
from fuzz.ie_mutator import build_rsn_wpa2_psk, mutations_rsn
from fuzz.monitor import CrashMonitor


# ── Frame builder ─────────────────────────────────────────────────────────────

def _assoc_frame(station, ie_blob: bytes, is_reassoc: bool = False):
    """Build AssocReq or ReassocReq with given IE bytes."""
    from scapy.layers.dot11 import Dot11
    cap_info = struct.pack('<HH', 1073, 10)
    rates = ie_build(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
    subtype = 2 if is_reassoc else 0
    fixed = cap_info + (b'\x00' * 10 if is_reassoc else b'')
    p = Dot11(type=0, subtype=subtype, FCfield=0,
              addr1=station.bss, addr2=station.mac, addr3=station.bss)
    p = p / (fixed + rates + ie_blob)
    return p


class IeCrashIsolate(Test):
    """
    Inject only the candidate RSN IE mutations that caused reason=9 disconnect.
    check_interval=1 — liveness check after EVERY frame.

    On disconnect: saves culprit frame to /tmp/ie_crash_culprit_<ts>_<label>.bin
    """
    name = 'ie-crash-isolate'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '[ie-crash-isolate] Connected. Running isolation test.', color='cyan')

        mon = CrashMonitor(station, session_id='isolate_' + hex(int(time.time()))[2:],
                           check_interval=1)

        # Build candidate frames in exact campaign order
        base_rates = ie_build(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        rsn_correct = build_rsn_wpa2_psk()

        # Candidate RSN IE mutations (from mutations_rsn, the ones in window [100-146])
        candidates = [
            ('rsn-pmkid-count-255',   next(v for l, v in mutations_rsn() if l == 'rsn-pmkid-count-255')),
            ('ie-wrong-len-255',      ie_wrong_length(48, rsn_correct[2:], 255)),
            ('ie-wrong-len-1',        ie_wrong_length(48, rsn_correct[2:], 1)),
            ('ie-truncated-2',        ie_truncated(48, rsn_correct[2:], 2)),
            ('ie-truncated-8',        ie_truncated(48, rsn_correct[2:], 8)),
            ('ie-zero-len',           ie_zero_length(48)),
            ('ie-max-claim',          ie_max_length_claim(48, len(rsn_correct) - 2)),
            ('rsn-body-random',       next(v for l, v in mutations_rsn() if l == 'rsn-body-random')),
            ('rsn-body-boundary',     next(v for l, v in mutations_rsn() if l == 'rsn-body-boundary')),
            ('rsn-body-xor_aa',       next(v for l, v in mutations_rsn() if l == 'rsn-body-xor_aa')),
        ]

        found_culprit = False
        for label, rsn_ie in candidates:
            for is_reassoc in (False, True):
                kind = 'reassoc' if is_reassoc else 'assoc'
                full_label = f'{kind}-{label}'
                frame = _assoc_frame(station, rsn_ie, is_reassoc)

                from scapy.all import raw as scapy_raw
                mon.record_inject(scapy_raw(frame), 'ie-crash-isolate', full_label)
                station.inject_mon(frame)
                time.sleep(0.1)

                # check_interval=1 means should_check() always True
                alive = mon.is_alive()
                mon.log_alive_result(alive)

                log(STATUS, f'  [{full_label}] alive={alive}', color='green' if alive else 'red')

                if not alive:
                    crash_path = mon.save_crash()
                    log(STATUS, f'[ie-crash-isolate] CULPRIT: {full_label}', color='red')
                    log(STATUS, f'[ie-crash-isolate] Frame saved: {crash_path}', color='red')
                    found_culprit = True
                    break

                time.sleep(0.3)  # extra delay: let AP settle between frames

            if found_culprit:
                break

        if not found_culprit:
            log(STATUS, '[ie-crash-isolate] No disconnect. Culprit may be rates/malformed-ie-stack.',
                color='orange')
            log(STATUS, '[ie-crash-isolate] Log: ' + mon.logger.path, color='cyan')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=3)
