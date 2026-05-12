"""
Phase 7: Crash frame replay — verify reproducibility of saved crash artifacts.

Run:
  # Single file
  sudo python3 run.py wlan0 replay-crash --config ~/iith/iith_wpa.conf \
    --file /tmp/wifi_fuzz_crash_<ts>_<phase>_<label>.bin

  # Single file, faster (match campaign injection speed)
  sudo python3 run.py wlan0 replay-crash --config ~/iith/iith_wpa.conf \
    --file /tmp/wifi_fuzz_crash_<ts>_<phase>_<label>.bin --count 5 --delay 0.05

  # Batch all /tmp/wifi_fuzz_crash_*.bin files
  sudo python3 run.py wlan0 replay-crash --config ~/iith/iith_wpa.conf \
    --batch --count 5 --delay 0.05

Loads a crash frame from .bin file, re-injects it against the connected AP,
and confirms whether the disconnect reproduces. Supports single-frame replay
and batch mode across all saved crash artifacts.

Usage:
  # Replay single crash frame
  REPLAY_FILE=/tmp/wifi_fuzz_crash_*.bin  sudo python3 run.py wlan0 replay-crash --config ~/iith/iith_wpa.conf

  # Batch: test all /tmp/wifi_fuzz_crash_*.bin files in sequence
  REPLAY_BATCH=1  sudo python3 run.py wlan0 replay-crash --config ~/iith/iith_wpa.conf

  # Control number of replay attempts per frame
  REPLAY_COUNT=5  REPLAY_FILE=...bin  sudo python3 run.py wlan0 replay-crash ...

Environment variables:
  REPLAY_FILE    Path to single .bin crash artifact.
  REPLAY_BATCH   Set to 1 to auto-discover and test all /tmp/wifi_fuzz_crash_*.bin.
  REPLAY_COUNT   Attempts per frame (default 3). Needed because AP may reconnect fast.
  REPLAY_DELAY   Seconds between attempts (default 1.0).

Outcome interpretation:
  REPRODUCED     Frame consistently causes AP disconnect. Strong candidate.
  INTERMITTENT   Disconnect on some attempts. Timing-sensitive.
  NOT_REPRODUCED No disconnect. Frame may need encrypted context or was noise.
"""
import os
import sys
import glob
import time
import struct

from dependencies.libwifi.wifi import log, STATUS
from library.testcase import Trigger, Action, Test


# ── Frame type classifier ────────────────────────────────────────────────────

def _frame_needs_encryption(data: bytes) -> bool:
    """Returns True if frame has Protected bit set (FC byte 1 bit 6)."""
    if len(data) < 2:
        return False
    fc_high = data[1]
    return bool(fc_high & 0x40)


def _frame_type_name(data: bytes) -> str:
    """Return human-readable frame type from FC bytes."""
    if len(data) < 2:
        return 'unknown'
    fc = struct.unpack_from('<H', data, 0)[0]
    ftype   = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    names = {
        (0, 0): 'AssocReq',  (0, 2): 'ReassocReq', (0, 4): 'ProbeReq',
        (0, 8): 'Beacon',    (0, 10): 'Disassoc',   (0, 11): 'Auth',
        (0, 12): 'Deauth',   (0, 13): 'Action',
        (2, 0): 'Data',      (2, 4): 'Null',        (2, 8): 'QoS-Data',
    }
    return names.get((ftype, subtype), f'type{ftype}/sub{subtype}')


def _load_bin(path: str) -> bytes:
    """Load .bin crash file. Strip EAPOL separator if present."""
    with open(path, 'rb') as f:
        data = f.read()
    if b'\n---\n' in data:
        data = data.split(b'\n---\n', 1)[0]
    return data


def _discover_crash_files() -> list:
    """Find all /tmp/wifi_fuzz_crash_*.bin and /tmp/eapol_crash_*.bin files."""
    files = sorted(
        glob.glob('/tmp/wifi_fuzz_crash_*.bin') +
        glob.glob('/tmp/eapol_crash_*.bin') +
        glob.glob('/tmp/ie_crash_*.bin') +
        glob.glob('/tmp/rsn_overread_*.bin')
    )
    return files


# ── Replay engine ─────────────────────────────────────────────────────────────

def _replay_one(station, frame_bytes: bytes, label: str,
                count: int = 3, delay: float = 1.0) -> dict:
    """
    Inject frame_bytes `count` times and measure AP disconnect rate.

    Returns:
        dict with keys: label, reproduced_count, attempts, rate, verdict
    """
    from scapy.layers.dot11 import Dot11

    try:
        frame = Dot11(frame_bytes)
    except Exception as e:
        log(STATUS, f'  [replay] Parse error for {label}: {e}', color='orange')
        return {'label': label, 'reproduced_count': 0, 'attempts': 0,
                'rate': 0.0, 'verdict': 'PARSE_ERROR'}

    needs_enc = _frame_needs_encryption(frame_bytes)
    ftype_name = _frame_type_name(frame_bytes)

    log(STATUS, f'  [replay] {label}  type={ftype_name}  enc_needed={needs_enc}  '
        f'len={len(frame_bytes)}B  attempts={count}', color='cyan')

    if needs_enc and not station.tk:
        log(STATUS, f'  [replay] SKIP — frame needs encryption but no TK', color='orange')
        return {'label': label, 'reproduced_count': 0, 'attempts': 0,
                'rate': 0.0, 'verdict': 'SKIP_NO_TK'}

    reproduced = 0

    for attempt in range(1, count + 1):
        # Check alive before inject
        try:
            pre = station.wpaspy_command('STATUS')
            if 'wpa_state=COMPLETED' not in pre:
                log(STATUS, f'  [replay] attempt {attempt}: not connected before inject — skip',
                    color='orange')
                time.sleep(2)
                continue
        except Exception:
            time.sleep(2)
            continue

        # Inject
        if needs_enc:
            from dependencies.libwifi.crypto import encrypt_ccmp
            station.pn += 1
            frame_to_send = encrypt_ccmp(frame, station.tk, station.pn)
        else:
            frame_to_send = frame

        station.inject_mon(frame_to_send)
        time.sleep(0.3)

        # Check alive after inject
        try:
            post = station.wpaspy_command('STATUS')
            alive = 'wpa_state=COMPLETED' in post
        except Exception:
            alive = False

        if not alive:
            reproduced += 1
            log(STATUS, f'  [replay] attempt {attempt}: DISCONNECTED ← reproduced!', color='red')
            # Wait for reconnect before next attempt
            time.sleep(3)
        else:
            log(STATUS, f'  [replay] attempt {attempt}: alive (no disconnect)', color='green')

        time.sleep(delay)

    rate = reproduced / count if count > 0 else 0.0
    if rate >= 0.8:
        verdict = 'REPRODUCED'
    elif rate >= 0.3:
        verdict = 'INTERMITTENT'
    else:
        verdict = 'NOT_REPRODUCED'

    color = 'red' if verdict == 'REPRODUCED' else ('orange' if verdict == 'INTERMITTENT' else 'green')
    log(STATUS, f'  [replay] → {verdict} ({reproduced}/{count}  {rate:.0%})', color=color)

    return {
        'label': label,
        'reproduced_count': reproduced,
        'attempts': count,
        'rate': rate,
        'verdict': verdict,
    }


# ── Test class ────────────────────────────────────────────────────────────────

class ReplayCrash(Test):
    """
    Replay saved crash frames to verify reproducibility.

    Single mode (REPLAY_FILE env var): replay one specific .bin file.
    Batch mode (REPLAY_BATCH=1): replay all /tmp/wifi_fuzz_crash_*.bin files.

    For each frame, injects REPLAY_COUNT times (default 3), measures
    how often it causes AP disconnect, and reports verdict:
      REPRODUCED     ≥ 80% attempts cause disconnect
      INTERMITTENT   30–79% attempts
      NOT_REPRODUCED < 30% attempts (may be noise or need different state)
    """
    name = 'replay-crash'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        # Accept flags directly from command line OR env vars.
        # CLI flags take precedence: --file PATH, --batch, --count N, --delay S
        import argparse as _ap
        _p = _ap.ArgumentParser(add_help=False)
        _p.add_argument('--file',  default=None)
        _p.add_argument('--batch', action='store_true')
        _p.add_argument('--count', type=int, default=None)
        _p.add_argument('--delay', type=float, default=None)
        _args, _ = _p.parse_known_args()

        replay_file  = _args.file  or os.environ.get('REPLAY_FILE', '')
        replay_batch = _args.batch or (os.environ.get('REPLAY_BATCH', '0').strip() == '1')
        replay_count = _args.count if _args.count is not None else int(os.environ.get('REPLAY_COUNT', '3'))
        replay_delay = _args.delay if _args.delay is not None else float(os.environ.get('REPLAY_DELAY', '1.0'))

        # Build list of (path, label) to replay
        targets = []

        if replay_batch:
            files = _discover_crash_files()
            if not files:
                log(STATUS, '[replay-crash] No crash files found in /tmp/', color='orange')
                return
            log(STATUS, f'[replay-crash] Batch mode: {len(files)} files', color='cyan')
            for f in files:
                targets.append((f, os.path.basename(f)))
        elif replay_file:
            if not os.path.exists(replay_file):
                log(STATUS, f'[replay-crash] File not found: {replay_file}', color='red')
                return
            targets.append((replay_file, os.path.basename(replay_file)))
        else:
            log(STATUS, '[replay-crash] Set REPLAY_FILE=path or REPLAY_BATCH=1', color='orange')
            log(STATUS, 'Available crash files:', color='cyan')
            for f in _discover_crash_files():
                log(STATUS, f'  {f}')
            return

        log(STATUS, f'[replay-crash] Starting replay. count={replay_count} delay={replay_delay}s',
            color='cyan')

        results = []
        for path, label in targets:
            log(STATUS, f'\n[replay-crash] === {label} ===', color='orange')
            try:
                data = _load_bin(path)
            except Exception as e:
                log(STATUS, f'  [replay] Read error: {e}', color='red')
                continue

            result = _replay_one(station, data, label,
                                  count=replay_count, delay=replay_delay)
            results.append(result)

        # Summary
        log(STATUS, '\n[replay-crash] ═══ SUMMARY ═══', color='cyan')
        log(STATUS, f'  {"Label":<55}  {"Verdict":<14}  Rate')
        log(STATUS, f'  {"─"*55}  {"─"*14}  ────')
        for r in results:
            color = ('red'    if r['verdict'] == 'REPRODUCED'    else
                     'orange' if r['verdict'] == 'INTERMITTENT'  else
                     'green'  if r['verdict'] == 'NOT_REPRODUCED' else 'white')
            log(STATUS,
                f'  {r["label"][:55]:<55}  {r["verdict"]:<14}  '
                f'{r["reproduced_count"]}/{r["attempts"]}',
                color=color)

        reproduced = [r for r in results if r['verdict'] == 'REPRODUCED']
        intermit   = [r for r in results if r['verdict'] == 'INTERMITTENT']
        log(STATUS, f'\n  REPRODUCED: {len(reproduced)}  INTERMITTENT: {len(intermit)}  '
            f'TOTAL: {len(results)}', color='cyan')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=5)
