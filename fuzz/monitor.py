"""
Crash detection and structured event logging for Wi-Fi fuzzing sessions.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, TYPE_CHECKING

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

        # PCAP capture of all injected frames (Wireshark-compatible)
        self._pcap: Optional[PcapWriter] = None
        if write_pcap:
            pcap_path = os.path.join(log_dir, 'fuzz_' + session_id + '.pcap')
            self._pcap = PcapWriter(pcap_path)
            self.logger._write({'event': 'pcap_path', 'path': pcap_path, 'ts': time.time()})

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

    def log_alive_result(self, alive: bool) -> None:
        """
        Append alive-check result to log (call after is_alive()).

        Separate event so JSONL stays append-only while still capturing
        which alive check corresponds to which inject batch.
        """
        self.logger._write({
            'event': 'alive_check',
            'alive': alive,
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
        Poll AP liveness via wpaspy STATUS command.

        Returns:
            True if wpa_state=COMPLETED (associated + keys installed).
            False if disconnected, timeout, or exception.
        """
        try:
            resp = self.station.wpaspy_command('STATUS')
            return 'wpa_state=COMPLETED' in resp
        except Exception:
            return False

    def close(self) -> None:
        """Flush and close PCAP file."""
        if self._pcap is not None:
            self.logger._write({'event': 'pcap_closed',
                                'total_frames': self._pcap.total(),
                                'path': self._pcap.path,
                                'ts': time.time()})
            self._pcap.close()
            self._pcap = None

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
            ts    = int(time.time())
            label = self._last_label.replace(' ', '_')[:60]
            phase = self._last_phase
            path  = os.path.join(CRASH_DIR, f'wifi_fuzz_crash_{ts}_{phase}_{label}.bin')
            with open(path, 'wb') as f:
                f.write(self._last_frame)
            self.logger._write({'event': 'crash_saved', 'path': path,
                                 'phase': phase, 'label': label, 'ts': ts})
            return path
        except Exception:
            return None
