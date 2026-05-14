"""
Crash detection and structured event logging for Wi-Fi fuzzing sessions.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Deque, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from fuzz.state_tracker import StateTracker

CRASH_DIR = '/tmp'

# ── PCAP writer ────────────────────────────────────────────────────────────────

_PCAP_MAGIC        = 0xa1b2c3d4
_PCAP_VERSION_MAJ  = 2
_PCAP_VERSION_MIN  = 4
_DLT_IEEE802_11    = 105   # raw 802.11, no RadioTap — opens directly in Wireshark


class PcapWriter:
    """
    Minimal PCAP writer for raw 802.11 frames (no external dependencies).

    Produces standard libpcap format (DLT=105) readable by Wireshark/tcpdump.
    Each written frame becomes one PCAP packet with real timestamp.

    Usage:
        w = PcapWriter('/tmp/session.pcap')
        w.write(raw_frame_bytes)
        w.close()
    """

    def __init__(self, path: str, dlt: int = _DLT_IEEE802_11):
        import struct as _s
        self.path = path
        self._f = open(path, 'wb')
        # Global header: magic version_maj version_min thiszone sigfigs snaplen network
        self._f.write(_s.pack('<IHHiIII',
            _PCAP_MAGIC, _PCAP_VERSION_MAJ, _PCAP_VERSION_MIN,
            0, 0, 65535, dlt))
        self._f.flush()
        self._count = 0

    def write(self, data: bytes) -> None:
        """Append one frame to the PCAP file."""
        import struct as _s
        ts      = time.time()
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        n = len(data)
        self._f.write(_s.pack('<IIII', ts_sec, ts_usec, n, n))
        self._f.write(data)
        self._f.flush()
        self._count += 1

    def close(self) -> None:
        self._f.close()

    def total(self) -> int:
        return self._count


# ── Beacon monitor ─────────────────────────────────────────────────────────────

def _rt_offset(data: bytes) -> int:
    """Return byte offset past RadioTap header (0 if none, -1 if malformed)."""
    if len(data) < 4 or data[0] != 0 or data[1] != 0:
        return 0
    rt_len = struct.unpack_from('<H', data, 2)[0]
    return rt_len if rt_len < len(data) else -1


class BeaconMonitor:
    """
    Background thread sniffing beacons from target AP on monitor interface.

    AP sends beacons every ~100ms regardless of client state.
    - Beacon gap > 500ms  → AP parser under load (interesting mutation)
    - Beacon gap > 3000ms → AP crashed/frozen (better crash signal than wpaspy alone)

    More reliable than wpaspy STATUS because:
    - Works even when wpa_supplicant loses connection
    - Detects AP firmware crash before reconnect completes
    - Detects partial crashes where AP still accepts auth but stops beaconing

    Auto-started by CrashMonitor. Accessible via mon.beacon.
    """

    CRASH_TIMEOUT_MS  = 3000   # gap > 3s = likely crashed
    LOAD_TIMEOUT_MS   = 500    # gap > 500ms = under load

    def __init__(self, iface: str, ap_bssid: str):
        self._iface    = iface
        self._bssid    = ap_bssid.lower().replace('-', ':')
        self._lock     = threading.Lock()
        self._last_ts  = 0.0
        self._intervals: Deque[float] = deque(maxlen=50)
        self._count    = 0
        self._thread: Optional[threading.Thread] = None
        self._running  = False

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True,
                                          name='BeaconMonitor')
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def is_alive(self, timeout_ms: float = CRASH_TIMEOUT_MS) -> bool:
        with self._lock:
            if self._last_ts == 0:
                return True   # no data yet — don't declare crash
            return (time.time() - self._last_ts) * 1000 < timeout_ms

    def gap_ms(self) -> float:
        with self._lock:
            return (time.time() - self._last_ts) * 1000 if self._last_ts else 0.0

    def avg_interval_ms(self) -> float:
        with self._lock:
            return (sum(self._intervals) / len(self._intervals) * 1000
                    if self._intervals else 100.0)

    def is_overloaded(self) -> bool:
        """Beacon gap > 2× average interval → AP parser under heavy load."""
        avg = self.avg_interval_ms()
        return self.gap_ms() > avg * 2.5

    def count(self) -> int:
        with self._lock:
            return self._count

    def _run(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0003))
            sock.bind((self._iface, 0))
            sock.settimeout(0.2)
        except Exception:
            return

        prev_ts = 0.0
        while self._running:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            except Exception:
                break

            off = _rt_offset(data)
            if off < 0 or len(data) < off + 24:
                continue
            dot11 = data[off:]

            fc  = struct.unpack_from('<H', dot11, 0)[0]
            typ = (fc >> 2) & 0x3
            sub = (fc >> 4) & 0xF
            if typ != 0 or sub != 8:   # not Beacon
                continue

            bssid = ':'.join(f'{b:02x}' for b in dot11[16:22])
            if bssid != self._bssid:
                continue

            ts = time.time()
            with self._lock:
                if prev_ts > 0:
                    self._intervals.append(ts - prev_ts)
                prev_ts       = ts
                self._last_ts = ts
                self._count  += 1

        sock.close()


# ── Response capture ────────────────────────────────────────────────────────────

@dataclass
class APResponse:
    """One management frame response captured from AP."""
    ts:         float
    kind:       str    # 'AssocResp', 'AuthResp', 'ADDBA-Resp', 'SA-Query-Resp', 'ProbeResp'
    status:     int    = 0
    extra:      dict   = field(default_factory=dict)


STATUS_NAMES = {0: 'success', 1: 'failure', 17: 'invalid-IE',
                23: 'invalid-RSN-caps', 40: 'rejected'}


class ResponseCapture:
    """
    Background thread capturing AP management frame responses on monitor interface.

    Captures frames FROM the AP BSSID to our MAC:
      AssocResp  → status code (tells us WHY parser rejected our AssocReq)
      AuthResp   → algo + status from auth frame processing
      ADDBA Resp → buf_size AP accepted (OOB probe confirmation)
      SA Query Resp → trans_id echo (PMF path confirmed)
      ProbeResp  → latency measure (parser load indicator)

    Parser-level signal: not just "are we connected" but
    "what did the AP's parser do with our specific frame?"

    Auto-started by CrashMonitor. Accessible via mon.responses.
    """

    def __init__(self, iface: str, ap_bssid: str, our_mac: str):
        self._iface    = iface
        self._bssid    = ap_bssid.lower().replace('-', ':')
        self._our_mac  = our_mac.lower().replace('-', ':')
        self._lock     = threading.Lock()
        self._responses: List[APResponse] = []
        self._thread: Optional[threading.Thread] = None
        self._running  = False

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True,
                                          name='ResponseCapture')
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def since(self, ts: float) -> List[APResponse]:
        with self._lock:
            return [r for r in self._responses if r.ts > ts]

    def last(self, kind: str) -> Optional[APResponse]:
        with self._lock:
            for r in reversed(self._responses):
                if r.kind == kind:
                    return r
        return None

    def all(self) -> List[APResponse]:
        with self._lock:
            return list(self._responses)

    def summary(self) -> str:
        from collections import Counter
        with self._lock:
            counts   = Counter(r.kind for r in self._responses)
            nonzero  = [(r.kind, r.status) for r in self._responses if r.status != 0]
        lines = [f'AP responses: {dict(counts)}']
        for kind, code in nonzero[:5]:
            name = STATUS_NAMES.get(code, f'code-{code}')
            lines.append(f'  {kind} status={code}({name})')
        return ', '.join(lines) if len(lines) == 1 else '\n'.join(lines)

    def _run(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0003))
            sock.bind((self._iface, 0))
            sock.settimeout(0.15)
        except Exception:
            return

        while self._running:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            except Exception:
                break
            self._handle(data, time.time())

        sock.close()

    def _handle(self, data: bytes, ts: float) -> None:
        off = _rt_offset(data)
        if off < 0 or len(data) < off + 24:
            return
        dot11 = data[off:]

        fc  = struct.unpack_from('<H', dot11, 0)[0]
        if ((fc >> 2) & 0x3) != 0:   # not management
            return
        sub = (fc >> 4) & 0xF

        addr1 = ':'.join(f'{b:02x}' for b in dot11[4:10])
        addr2 = ':'.join(f'{b:02x}' for b in dot11[10:16])
        if addr2 != self._bssid:
            return
        if addr1 != self._our_mac and addr1 != 'ff:ff:ff:ff:ff:ff':
            return

        body = dot11[24:]
        resp = None

        if sub == 1 and len(body) >= 6:    # AssocResp
            status = struct.unpack_from('<H', body, 2)[0]
            resp   = APResponse(ts=ts, kind='AssocResp', status=status,
                                extra={'cap': struct.unpack_from('<H', body, 0)[0],
                                       'aid': struct.unpack_from('<H', body, 4)[0]})

        elif sub == 11 and len(body) >= 6:  # AuthResp
            algo   = struct.unpack_from('<H', body, 0)[0]
            seq    = struct.unpack_from('<H', body, 2)[0]
            status = struct.unpack_from('<H', body, 4)[0]
            resp   = APResponse(ts=ts, kind='AuthResp', status=status,
                                extra={'algo': algo, 'seq': seq})

        elif sub == 5:                      # ProbeResp
            resp = APResponse(ts=ts, kind='ProbeResp', status=0)

        elif sub == 13 and len(body) >= 4:  # Action frame responses
            cat = body[0]; act = body[1]
            if cat == 3 and act == 1 and len(body) >= 7:    # ADDBA Resp
                status   = struct.unpack_from('<H', body, 3)[0]
                buf_size = (struct.unpack_from('<H', body, 5)[0] >> 6) & 0x3FF
                resp = APResponse(ts=ts, kind='ADDBA-Resp', status=status,
                                  extra={'buf_size': buf_size})
            elif cat == 8 and act == 1 and len(body) >= 4:  # SA Query Resp
                trans_id = struct.unpack_from('<H', body, 2)[0]
                resp = APResponse(ts=ts, kind='SA-Query-Resp', status=0,
                                  extra={'trans_id': trans_id})

        if resp is not None:
            with self._lock:
                self._responses.append(resp)


@dataclass
class FuzzEvent:
    """
    One logged fuzzing event.

    Recorded for every injected frame. On crash, the last event
    before disconnect is the crash candidate.

    Attributes:
        ts:          Unix timestamp of injection.
        phase:       Fuzzing phase name (e.g., "mgmt-auth-fuzz").
        label:       Mutation description (e.g., "auth-algo-0xffff").
        frame_len:   Injected frame length in bytes.
        alive_after: True if AP still alive after this injection (None = unchecked).
        crash:       True if this event is flagged as crash candidate.
    """
    ts:          float
    phase:       str
    label:       str
    frame_len:   int
    alive_after: Optional[bool] = None
    crash:       bool = False


class FuzzLogger:
    """
    Structured JSONL logger for fuzzing sessions.

    Each line in the log file is a JSON object representing one FuzzEvent.
    Log files are named: /tmp/wifi_fuzz_log_<session_id>.jsonl

    Attributes:
        session_id: Unique identifier for this fuzzing session.
        path:       Path to the JSONL log file.

    Usage:
        logger = FuzzLogger("my-session")
        logger.log(FuzzEvent(ts=time.time(), phase="mgmt", label="auth-x", frame_len=32))
        print(logger.path)
    """

    def __init__(self, session_id: str, log_dir: str = CRASH_DIR):
        self.session_id = session_id
        self.path = os.path.join(log_dir, 'wifi_fuzz_log_' + session_id + '.jsonl')
        self._count = 0
        self._write({'event': 'session_start', 'session_id': session_id, 'ts': time.time()})

    def log(self, event: FuzzEvent) -> None:
        """Append one FuzzEvent to the log file."""
        self._count += 1
        self._write(asdict(event))

    def log_phase(self, phase: str, info: str = '') -> None:
        """Log a phase transition marker."""
        self._write({'event': 'phase', 'phase': phase, 'info': info, 'ts': time.time()})

    def log_reconnect(self, phase: str, success: bool) -> None:
        """Log a reconnect attempt."""
        self._write({'event': 'reconnect', 'phase': phase, 'success': success, 'ts': time.time()})

    def log_profile(self, summary: str) -> None:
        """Log AP profile summary."""
        self._write({'event': 'ap_profile', 'summary': summary, 'ts': time.time()})

    def total(self) -> int:
        """Return total events logged."""
        return self._count

    def _write(self, obj: dict) -> None:
        with open(self.path, 'a') as f:
            f.write(json.dumps(obj) + '\n')


class CrashMonitor:
    """
    Monitors AP liveness and saves crash artifacts.

    Wraps the wpaspy STATUS poll pattern used across all fuzz tests,
    centralizing crash detection and artifact saving.

    Attributes:
        station:    wifi-framework station (Supplicant) instance.
        logger:     FuzzLogger for this session.
        check_interval: How many injections between alive checks (default 20).

    Usage:
        mon = CrashMonitor(station, session_id="run-001", check_interval=20)
        for frame in frames:
            mon.record_inject(raw(frame), phase="action-ba", label="buf-255")
            station.inject_mon(frame)
            if mon.should_check():
                if not mon.is_alive():
                    mon.save_crash()
                    return   # stop this phase
    """

    def __init__(self, station, session_id: str, check_interval: int = 30,
                 log_dir: str = CRASH_DIR, write_pcap: bool = True):
        self.station        = station
        self.check_interval = check_interval
        self.logger         = FuzzLogger(session_id, log_dir)
        self._inject_count  = 0
        self._last_frame    = None
        self._last_label    = ''
        self._last_phase    = ''
        self.state_tracker  = None  # set by FuzzCampaign after init

        # Two windows for crash attribution:
        #   _window_full: last check_interval frames (worst-case bound)
        #   _window_since_check: frames since LAST is_alive()=True check (precise bound)
        # When wpaspy disconnect fires immediately → _window_since_check has 1-5 frames.
        # When 30-frame poll detects crash → _window_since_check has up to 30 frames.
        # save_crash_window() prefers _window_since_check (smaller = more precise attribution).
        self._window_full: Deque[tuple]         = deque(maxlen=check_interval)  # (bytes, phase, label)
        self._window_since_check: Deque[tuple]  = deque()                       # resets on alive=True

        # PCAP capture of all injected frames (Wireshark-compatible)
        self._pcap: Optional[PcapWriter] = None
        if write_pcap:
            pcap_path = os.path.join(log_dir, 'fuzz_' + session_id + '.pcap')
            self._pcap = PcapWriter(pcap_path)
            self.logger._write({'event': 'pcap_path', 'path': pcap_path, 'ts': time.time()})

        # Auto-start beacon monitor + response capture (background threads)
        # beacon: tracks AP liveness via beacon continuity (more reliable than wpaspy alone)
        # responses: captures AssocResp/ADDBA-Resp/SA-Query-Resp for parser-level signal
        self.beacon: Optional[BeaconMonitor] = None
        self.responses: Optional[ResponseCapture] = None
        if hasattr(station, 'nic_mon') and station.nic_mon and hasattr(station, 'bss') and station.bss:
            try:
                self.beacon = BeaconMonitor(iface=station.nic_mon, ap_bssid=station.bss)
                self.beacon.start()
                self.responses = ResponseCapture(iface=station.nic_mon,
                                                  ap_bssid=station.bss,
                                                  our_mac=station.mac)
                self.responses.start()
                self.logger._write({'event': 'monitors_started',
                                     'beacon_iface': station.nic_mon,
                                     'ap_bssid': station.bss,
                                     'ts': time.time()})
            except Exception as e:
                self.logger._write({'event': 'monitors_failed', 'error': str(e), 'ts': time.time()})

    def record_inject(self, frame_bytes: bytes, phase: str, label: str) -> None:
        """
        Record a pending injection (call BEFORE station.inject_mon()).

        Stores the frame as crash candidate in case the AP disconnects
        during or after this injection.

        Args:
            frame_bytes: Raw bytes of the frame being injected.
            phase:       Current fuzzing phase name.
            label:       Mutation description.
        """
        self._inject_count += 1
        self._last_frame = frame_bytes
        self._last_phase = phase
        self._last_label = label
        event = FuzzEvent(ts=time.time(), phase=phase, label=label,
                          frame_len=len(frame_bytes))
        self.logger.log(event)
        if self._pcap is not None:
            self._pcap.write(frame_bytes)
        entry = (frame_bytes, phase, label)
        self._window_full.append(entry)
        self._window_since_check.append(entry)

    def log_alive_result(self, alive: bool) -> None:
        """
        Append alive-check result to log (call after is_alive()).

        When alive=True: reset _window_since_check — frames before this point
        are confirmed safe. Next crash window starts from here.
        """
        if alive:
            self._window_since_check.clear()  # ← resets precise crash window
        self.logger._write({
            'event': 'alive_check',
            'alive': alive,
            'window_size': len(self._window_since_check),
            'phase': self._last_phase,
            'label': self._last_label,
            'inject_count': self._inject_count,
            'ts': time.time(),
        })

    def should_check(self) -> bool:
        """True if it's time for a liveness check."""
        return self._inject_count % self.check_interval == 0

    def check_wpaspy_queue(self) -> bool:
        """
        Check wpaspy event queue for unsolicited DISCONNECTED events.

        Also feeds messages to StateTracker if attached.
        Returns True if a disconnect was detected in the queue.
        This catches disconnects between alive polls.
        """
        disconnected = False
        try:
            while self.station.wpaspy_ctrl.pending():
                msg = self.station.wpaspy_ctrl.recv()

                # Feed to state tracker
                if self.state_tracker is not None:
                    self.state_tracker.set_inject_context(
                        self._last_phase, self._last_label, self._inject_count)
                    transition = self.state_tracker.update_from_wpaspy(msg)
                    if transition is not None:
                        self.logger._write({
                            'event': 'state_transition',
                            'from': transition.from_state.name,
                            'to': transition.to_state.name,
                            'trigger_msg': transition.trigger_msg,
                            'phase': transition.inject_phase,
                            'label': transition.inject_label,
                            'inject_count': transition.inject_count,
                            'ts': transition.ts,
                        })

                if 'CTRL-EVENT-DISCONNECTED' in msg:
                    self.logger._write({
                        'event': 'wpaspy_disconnect',
                        'msg': msg.strip(),
                        'phase': self._last_phase,
                        'label': self._last_label,
                        'inject_count': self._inject_count,
                        'ts': time.time(),
                    })
                    disconnected = True
        except Exception:
            pass
        return disconnected

    def is_alive(self) -> bool:
        """
        Poll AP liveness using TWO signals:
          1. wpaspy STATUS (wpa_state=COMPLETED) — checks our client connection
          2. BeaconMonitor gap — checks if AP is still beaconing (beacon > 3s gap = crashed)

        Beacon check catches AP crashes that happen between wpaspy polls:
          - AP firmware crash: beacons stop immediately, wpaspy may still show COMPLETED
          - AP parser hang: beacon gap spikes before full disconnect
        """
        # Signal 1: beacon continuity (AP crashed if beacons stopped)
        if self.beacon is not None and self.beacon.count() > 5:
            if not self.beacon.is_alive(timeout_ms=3000):
                self.logger._write({'event': 'beacon_gap_crash',
                                     'gap_ms': self.beacon.gap_ms(),
                                     'phase': self._last_phase,
                                     'label': self._last_label,
                                     'ts': time.time()})
                return False

        # Signal 2: wpaspy connection state
        try:
            resp = self.station.wpaspy_command('STATUS')
            return 'wpa_state=COMPLETED' in resp
        except Exception:
            return False

    def ap_overloaded(self) -> bool:
        """True if AP beacon gap > 2× normal interval (parser under load)."""
        return self.beacon is not None and self.beacon.is_overloaded()

    def last_ap_response(self, kind: str) -> Optional[APResponse]:
        """Get last captured AP response of given type (e.g. 'AssocResp', 'ADDBA-Resp')."""
        if self.responses is None:
            return None
        return self.responses.last(kind)

    def ap_responses_since(self, ts: float) -> List[APResponse]:
        """All AP responses captured after given timestamp."""
        if self.responses is None:
            return []
        return self.responses.since(ts)

    def close(self) -> None:
        """Stop all background monitors, flush and close PCAP file."""
        if self.beacon is not None:
            self.beacon.stop()
            self.logger._write({'event': 'beacon_monitor_stopped',
                                 'total_beacons': self.beacon.count(),
                                 'avg_interval_ms': round(self.beacon.avg_interval_ms(), 1),
                                 'ts': time.time()})
        if self.responses is not None:
            self.responses.stop()
            self.logger._write({'event': 'response_capture_stopped',
                                 'summary': self.responses.summary(),
                                 'ts': time.time()})
        if self._pcap is not None:
            self.logger._write({'event': 'pcap_closed',
                                'total_frames': self._pcap.total(),
                                'path': self._pcap.path,
                                'ts': time.time()})
            self._pcap.close()
            self._pcap = None

    def save_crash_window(self) -> Optional[str]:
        """
        Save the precise crash window as PCAP + individual .bin files.

        Uses _window_since_check (frames since last alive=True check) when
        non-empty — this is the smallest, most precise window.
        Falls back to _window_full (last check_interval frames) if empty.

        Example:
          Alive check at frame 800 → window_since_check cleared
          Frames 801-830 injected, disconnect at 831 detected by wpaspy
          → window_since_check has 30 frames (801-830), trigger is in those 30

          OR: disconnect at 803 detected by wpaspy drain (every frame)
          → window_since_check has 2 frames (801-802), much smaller!
        """
        # Use smaller precise window (since last alive check) if available
        window = list(self._window_since_check) or list(self._window_full)
        if not window:
            return self.save_crash()

        try:
            ts_str    = datetime.now().strftime('%Y%m%d_%H%M%S')
            phase     = self._last_phase
            n         = len(window)
            precision = 'precise' if self._window_since_check else 'full'

            # Window PCAP — all N frames in chronological order
            pcap_path = os.path.join(CRASH_DIR,
                                      f'wifi_fuzz_window_{ts_str}_{phase}_N{n}_{precision}.pcap')
            w = PcapWriter(pcap_path)
            for frame_bytes, ph, lbl in window:
                w.write(frame_bytes)
            w.close()

            # Individual .bins for bisection replay
            for i, (frame_bytes, ph, lbl) in enumerate(window):
                lbl_safe = lbl.replace(' ', '_')[:40]
                bin_path = os.path.join(CRASH_DIR,
                                         f'wifi_fuzz_window_{ts_str}_{phase}_{i:02d}_{lbl_safe}.bin')
                with open(bin_path, 'wb') as f:
                    f.write(frame_bytes)

            self.logger._write({
                'event': 'crash_window_saved',
                'pcap_path': pcap_path,
                'frame_count': n,
                'precision': precision,
                'phase': phase,
                'frames': [{'idx': i, 'label': lbl, 'len': len(fb)}
                           for i, (fb, _, lbl) in enumerate(window)],
                'ts': time.time(),
            })
            return pcap_path

        except Exception:
            return self.save_crash()

    def save_crash(self) -> Optional[str]:
        """
        Save the last injected frame as a crash candidate binary.

        Saves to: /tmp/wifi_fuzz_crash_<ts>_<phase>_<label>.bin

        Returns:
            Path to saved file, or None if save failed.
        """
        if self._last_frame is None:
            return None
        try:
            ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            label  = self._last_label.replace(' ', '_')[:60]
            phase  = self._last_phase
            path   = os.path.join(CRASH_DIR,
                                   f'wifi_fuzz_crash_{ts_str}_{phase}_{label}.bin')
            with open(path, 'wb') as f:
                f.write(self._last_frame)
            self.logger._write({'event': 'crash_saved', 'path': path,
                                 'phase': phase, 'label': label, 'ts': time.time()})
            return path
        except Exception:
            return None
