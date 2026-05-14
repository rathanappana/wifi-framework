"""
Havoc campaign — probabilistic mutation fuzzer mode.

Unlike ap-fuzz-campaign (deterministic, ~2000 frames),
this runs unlimited frames with stacked random mutations
until stopped or budget exhausted.

Each frame from the normal campaign phases gets 2-8 random
additional mutations applied before injection:
  - random byte replacements
  - bit flips
  - dictionary magic bytes
  - repeated chunks
  - IE stack corruption (duplicate/shuffle/truncate IEs)
  - splice with crash corpus

This is the "havoc mode" equivalent of AFL applied to Wi-Fi.

Run:
  sudo python3 run.py wlan0 havoc-campaign --config ~/iith/iith_wpa.conf
  sudo python3 run.py wlan0 havoc-campaign --config ~/iith/pi_supplicant.conf

Flags:
  --budget N      Max frames to inject (default: 10000, 0=unlimited)
  --intensity N   Havoc intensity 1-3 (default: 2, 3=most aggressive)
  --seed-corpus   Load crash files from /tmp/ as splice seeds
  --delay S       Inter-frame delay (default: 0.03)
"""
import os
import random
import struct
import time

from scapy.layers.dot11 import Dot11, Dot11QoS, Dot11Elt
from scapy.all import raw as scapy_raw

from dependencies.libwifi.wifi import log, STATUS
from dependencies.libwifi.crypto import encrypt_ccmp
from library.testcase import Trigger, Action, Test
from fuzz.profiler import sniff_and_profile, APProfile, SecurityType
from fuzz.monitor import CrashMonitor
from fuzz.feedback import FeedbackEngine, Signal
from fuzz.havoc import havoc_frame, havoc_ie_chain_only, SpliceMutator
from fuzz.mutator import (
    ie_build, ie_wrong_length, ie_zero_length, ie_max_length_claim,
    field_boundary_values,
)
from fuzz.ie_mutator import (
    mutations_rsn, mutations_ht, mutations_he, mutations_rates,
    build_rsn_wpa2_psk,
)


# ── Frame templates (seed frames for havoc mutation) ──────────────────────────

def _assoc_req(station, ie_bytes: bytes) -> bytes:
    """Build base AssocReq with given IEs."""
    rates = ie_build(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
    cap   = struct.pack('<HH', 1073, 10)
    dot11 = Dot11(type=0, subtype=0, FCfield=0,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss)
    return scapy_raw(dot11 / (cap + rates + ie_bytes))


def _qos_data(station, payload: bytes, seq: int, encrypt: bool = True) -> tuple:
    """Build QoS Data frame."""
    fc = 0x41 if encrypt else 0x01  # ToDS + Protected? : ToDS
    dot11 = Dot11(type=2, subtype=8, FCfield=fc,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss,
                  SC=(seq & 4095) << 4)
    dot11 /= Dot11QoS(TID=0) / payload
    if encrypt and station.tk:
        station.pn += 1
        return scapy_raw(encrypt_ccmp(dot11, station.tk, station.pn)), True
    return scapy_raw(dot11), False


def _mgmt(station, subtype: int, body: bytes) -> bytes:
    dot11 = Dot11(type=0, subtype=subtype, FCfield=0,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss)
    return scapy_raw(dot11 / body)


def _action(station, category: int, action: int, body: bytes = b'') -> bytes:
    return _mgmt(station, 13, bytes([category, action]) + body)


# ── Seed template generators ──────────────────────────────────────────────────

def _generate_seed_frames(station) -> list:
    """
    Generate diverse seed frames from all mutation categories.
    These become the starting points for havoc mutation.
    Returns list of (frame_bytes, ie_offset, label) tuples.
    """
    seeds = []
    body_start = 24 + 4  # Dot11(24) + CapInfo(2) + ListenInt(2)

    # RSN IE seeds (60 variants × 2 assoc/reassoc)
    for label, rsn_ie in mutations_rsn():
        seeds.append((_assoc_req(station, rsn_ie), body_start, f'rsn-{label}'))

    # HT IE seeds
    for label, ht_ie in mutations_ht():
        ie_blob = build_rsn_wpa2_psk() + ht_ie
        seeds.append((_assoc_req(station, ie_blob), body_start, f'ht-{label}'))

    # HE IE seeds
    for label, he_ie in mutations_he():
        ie_blob = build_rsn_wpa2_psk() + he_ie
        seeds.append((_assoc_req(station, ie_blob), body_start, f'he-{label}'))

    # Rates IE seeds
    for label, rates_ie in mutations_rates():
        ie_blob = rates_ie + build_rsn_wpa2_psk()
        seeds.append((_assoc_req(station, ie_blob), body_start, f'rates-{label}'))

    # Action frame seeds (all categories)
    BODY = struct.pack('<BHH', 1, 0, 0)
    for cat in range(256):
        for act in (0, 1, 255):
            seeds.append((_action(station, cat, act, BODY), None, f'action-cat{cat}-act{act}'))

    # Management frame seeds
    for algo in (0, 1, 2, 3, 0xFFFF):
        body = struct.pack('<HHH', algo, 1, 0)
        seeds.append((_mgmt(station, 11, body), None, f'auth-algo-{algo:04x}'))

    return seeds


# ── Havoc injector ────────────────────────────────────────────────────────────

class HavocInjector:
    """Inject havoc-mutated frames in an infinite loop."""

    def __init__(self, station, seeds: list, intensity: int,
                 budget: int, inter_frame_s: float, splice: SpliceMutator,
                 mon: CrashMonitor, feedback: FeedbackEngine):
        self.station      = station
        self.seeds        = seeds
        self.intensity    = intensity
        self.budget       = budget
        self.inter_frame_s = inter_frame_s
        self.splice       = splice
        self.mon          = mon
        self.feedback     = feedback
        self._injected      = 0
        self._crashes       = 0
        self._last_crash_ts = 0.0
        self._CRASH_COOLDOWN = 12.0  # seconds — skip crash check right after reconnect

    def run_forever(self) -> None:
        """Inject havoc mutations until budget exhausted."""
        log(STATUS, f'[havoc] Starting. seeds={len(self.seeds)} '
            f'intensity={self.intensity} budget={self.budget or "∞"}',
            color='cyan')

        while True:
            if self.budget and self._injected >= self.budget:
                break

            # Pick random seed
            frame_bytes, ie_offset, label = random.choice(self.seeds)

            try:
                # Apply havoc mutations
                mutated = havoc_frame(frame_bytes, intensity=self.intensity,
                                      splice_corpus=self.splice,
                                      ie_offset=ie_offset)

                # Skip if station not connected (no TK = can't inject encrypted data)
                # Management frames (type=0) don't need TK — always safe to inject
                frame      = Dot11(mutated)
                needs_tk   = (frame.type == 2 and bool(frame.FCfield & 0x40))
                if needs_tk and not self.station.tk:
                    time.sleep(0.1)
                    continue

                self.mon.record_inject(mutated, 'havoc', label)
                self.feedback.record_inject('havoc', label)
                self.station.inject_mon(frame)
                self._injected += 1
                time.sleep(self.inter_frame_s)

            except Exception as e:
                # Swallow per-frame errors — don't crash the loop
                time.sleep(0.05)
                continue

            # Check alive — but skip if inside cooldown window after last crash
            try:
                in_cooldown  = (time.time() - self._last_crash_ts) < self._CRASH_COOLDOWN
                disconnected = self.mon.check_wpaspy_queue()
                if (disconnected or self.mon.should_check()) and not in_cooldown:
                    alive = self.mon.is_alive()
                    self.mon.log_alive_result(alive)
                    if not alive:
                        crash_path = self.mon.save_crash_window()  # saves all N frames in window
                        reason = self._extract_reason()
                        self.feedback.record_signal(reason_code=reason, crash_saved=bool(crash_path))
                        self._crashes += 1
                        log(STATUS,
                            f'[havoc] CRASH #{self._crashes} at frame {self._injected} '
                            f'label={label} saved={crash_path}', color='red')
                        # Crash → new seed
                        if crash_path:
                            try:
                                with open(crash_path, 'rb') as f:
                                    crash_bytes = f.read()
                                if len(crash_bytes) >= 10:
                                    self.seeds.append((crash_bytes, ie_offset, f'crash-{label}'))
                                    self.splice.add_bytes(crash_bytes)
                                    log(STATUS, f'[havoc] Crash seed added. '
                                        f'Total seeds: {len(self.seeds)}', color='orange')
                            except Exception:
                                pass
                        # Wait until actually CONNECTED (not just ASSOCIATING)
                        # EAP-PEAP takes 4-6s → wait up to 15s
                        self._last_crash_ts = time.time()
                        for _ in range(150):
                            time.sleep(0.1)
                            try:
                                if 'wpa_state=COMPLETED' in self.station.wpaspy_command('STATUS'):
                                    break
                            except Exception:
                                pass
                        else:
                            log(STATUS, '[havoc] Reconnect timeout', color='orange')
                else:
                    self.feedback.record_alive()
            except Exception:
                time.sleep(0.1)

            # Progress log every 200 frames
            if self._injected % 200 == 0:
                log(STATUS, f'[havoc] {self._injected} frames injected, '
                    f'{self._crashes} crashes, {len(self.seeds)} seeds',
                    color='cyan')

    def _extract_reason(self) -> int:
        from fuzz.state_tracker import STAState
        if hasattr(self.mon, 'state_tracker') and self.mon.state_tracker:
            for t in reversed(self.mon.state_tracker.state_transitions()):
                if t.to_state == STAState.DISCONNECTED:
                    for tok in t.trigger_msg.split():
                        if tok.startswith('reason='):
                            try:
                                return int(tok[7:])
                            except ValueError:
                                pass
        return 0


# ── Test class ────────────────────────────────────────────────────────────────

class HavocCampaign(Test):
    """
    Probabilistic havoc fuzzer.
    Generates 10k–1M+ unique mutations per run.
    Crashes become new seeds (evolutionary).
    """
    name = 'havoc-campaign'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        import argparse as _ap
        _p = _ap.ArgumentParser(add_help=False)
        _p.add_argument('--budget',     type=int,   default=10000)
        _p.add_argument('--intensity',  type=int,   default=2)
        _p.add_argument('--seed-corpus', action='store_true')
        _p.add_argument('--delay',      type=float, default=0.03)
        args, _ = _p.parse_known_args()

        log(STATUS, '[havoc] Connected. Building seed corpus...', color='cyan')

        # AP profile
        profile = sniff_and_profile(station.nic_mon, target_bssid=station.bss, timeout=5)
        if profile is None:
            profile = APProfile(bssid=station.bss, security=SecurityType.WPA2,
                                ht_cap=True, vht_cap=False, he_cap=False)

        # Session setup
        from datetime import datetime as _dt
        sid = _dt.now().strftime('%Y%m%d_%H%M%S') + '_havoc_' + \
              profile.bssid.replace(':', '')[:6]
        mon      = CrashMonitor(station, session_id=sid, check_interval=30)
        feedback = FeedbackEngine(profile_id='havoc_' + profile.bssid.replace(':', '')[:12])
        feedback.load()

        # Splice corpus from crash files
        splice = SpliceMutator()
        if args.seed_corpus:
            n = splice.load_crash_dir('/tmp')
            log(STATUS, f'[havoc] Loaded {n} crash files as splice seeds', color='cyan')

        # Generate seed frames
        seeds = _generate_seed_frames(station)
        log(STATUS, f'[havoc] {len(seeds)} seed frames generated', color='cyan')
        log(STATUS, f'[havoc] Budget={args.budget or "∞"} intensity={args.intensity} '
            f'delay={args.delay}s', color='cyan')

        # Run havoc — Ctrl+C saves state cleanly before exit
        injector = HavocInjector(
            station=station, seeds=seeds,
            intensity=args.intensity, budget=args.budget,
            inter_frame_s=args.delay, splice=splice,
            mon=mon, feedback=feedback,
        )

        import signal as _sig
        def _shutdown(signum, _frame):
            log(STATUS, f'\n[havoc] Interrupted at frame {injector._injected}. Saving...',
                color='orange')
            mon.close()
            log(STATUS, feedback.report(), color='cyan')
            feedback.save()
            log(STATUS, f'[havoc] Saved. {injector._injected} frames, '
                f'{injector._crashes} crashes. PCAP+bins safe.', color='green')
            raise SystemExit(0)
        _sig.signal(_sig.SIGINT,  _shutdown)
        _sig.signal(_sig.SIGTERM, _shutdown)

        injector.run_forever()

        # Normal budget-exhausted summary
        mon.close()
        log(STATUS, feedback.report(), color='cyan')
        feedback.save()
        log(STATUS, f'[havoc] Done. {injector._injected} frames, '
            f'{injector._crashes} crashes.', color='cyan')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=5)
