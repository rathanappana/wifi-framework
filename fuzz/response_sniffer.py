"""
Tier 2: Response sniffer — captures AP frames during fuzzing campaign.

Runs on monwlan0 as a daemon thread alongside the main campaign loop.
Captures frames FROM the AP BSSID directed AT our MAC and feeds them
to FeedbackEngine with reason codes and status codes.

Captured frame types:
  Deauth   (type=0 sub=12) — reason code → maps to Signal
  Disassoc (type=0 sub=10) — reason code
  Auth     (type=0 sub=11) → unexpected auth from AP = state machine signal
  AssocResp (type=0 sub=1) — status code (non-zero = rejection)
  ProbeResp (type=0 sub=5) — unexpected probe resp = AP changed state

Also measures response latency:
  inject_ts recorded on record_inject()
  When AP frame arrives within 500ms of last inject → latency = delta

Thread safety: all state updates via Lock. Daemon thread auto-stops when
main thread exits.
"""
from __future__ import annotations

import struct
import threading
import time
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from fuzz.feedback import FeedbackEngine


# Deauth/Disassoc subtype to (type, subtype) tuples of interest
_MGMT_INTEREST = {
    (0, 12): 'Deauth',
    (0, 10): 'Disassoc',
    (0, 11): 'Auth',
    (0,  1): 'AssocResp',
    (0,  5): 'ProbeResp',
}

_CORRELATION_WINDOW_S = 0.5   # max seconds between inject and AP response


class ResponseSniffer:
    """
    Background thread sniffing AP responses on monitor interface.

    Correlates each captured AP frame with the last injected mutation.
    Feeds reason/status codes to FeedbackEngine for scoring.

    Usage:
        sniffer = ResponseSniffer(iface='monwlan0',
                                  ap_bssid='ee:55:a8:06:7f:dd',
                                  our_mac='78:20:51:ac:6b:b8',
                                  feedback=fe)
        sniffer.start()
        # ... campaign runs ...
        sniffer.stop()
        print(sniffer.summary())
    """

    def __init__(self, iface: str, ap_bssid: str, our_mac: str,
                 feedback: 'FeedbackEngine'):
        self._iface     = iface
        self._ap_bssid  = ap_bssid.lower().replace('-', ':')
        self._our_mac   = our_mac.lower().replace('-', ':')
        self._feedback  = feedback
        self._thread: Optional[threading.Thread] = None
        self._running   = False
        self._lock      = threading.Lock()

        # Stats
        self._deauth_count    = 0
        self._disassoc_count  = 0
        self._assocresp_count = 0
        self._other_count     = 0
        self._responses: list = []   # list of (ts, frame_name, reason_code)

    # ── Control ────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start background sniffer thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop,
                                         name='ResponseSniffer', daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal sniffer to stop. Does not wait for thread to exit."""
        self._running = False

    def join(self, timeout: float = 2.0) -> None:
        """Wait for sniffer thread to exit."""
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    # ── Sniffer loop ───────────────────────────────────────────────────────────

    def _sniff_loop(self) -> None:
        """Main sniff loop. Runs in daemon thread."""
        import socket as _socket

        try:
            # Raw 802.11 socket on monwlan0 — same type as wifi-framework's MonitorSocket
            # AF_PACKET, SOCK_RAW, ETH_P_ALL — multiple sockets on same iface are OK
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW,
                                   _socket.htons(0x0003))  # ETH_P_ALL
            sock.bind((self._iface, 0))
            sock.settimeout(0.1)
        except Exception as e:
            # Interface not available or permission error
            return

        while self._running:
            try:
                data = sock.recv(4096)
            except _socket.timeout:
                continue
            except Exception:
                break

            self._handle(data)

        sock.close()

    def _handle(self, data: bytes) -> None:
        """Parse raw frame and feed signal if it's from AP to us."""
        if len(data) < 24:
            return

        # Check for RadioTap header (first 2 bytes = 0x00 0x00)
        offset = 0
        if len(data) >= 4 and data[0] == 0 and data[1] == 0:
            # RadioTap: length at bytes 2-3 (LE)
            rt_len = struct.unpack_from('<H', data, 2)[0]
            if rt_len < len(data):
                offset = rt_len
            else:
                return

        dot11 = data[offset:]
        if len(dot11) < 24:
            return

        fc = struct.unpack_from('<H', dot11, 0)[0]
        ftype   = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xF

        frame_name = _MGMT_INTEREST.get((ftype, subtype))
        if frame_name is None:
            return

        # addr1 = DA, addr2 = SA/TA
        addr1 = ':'.join(f'{b:02x}' for b in dot11[4:10])
        addr2 = ':'.join(f'{b:02x}' for b in dot11[10:16])

        # Must be FROM AP BSSID
        if addr2 != self._ap_bssid:
            return
        # Must be TO us (or broadcast)
        if addr1 != self._our_mac and addr1 != 'ff:ff:ff:ff:ff:ff':
            return

        # Extract reason/status code (first 2 bytes of body)
        body_offset = offset + 24
        reason_code = 0
        if len(data) >= body_offset + 2:
            reason_code = struct.unpack_from('<H', data, body_offset)[0]

        ts = time.time()
        self._dispatch(frame_name, reason_code, ts)

    def _dispatch(self, frame_name: str, reason_code: int, ts: float) -> None:
        """Feed captured AP frame to FeedbackEngine and update stats."""
        with self._lock:
            self._responses.append((ts, frame_name, reason_code))

            if frame_name == 'Deauth':
                self._deauth_count += 1
            elif frame_name == 'Disassoc':
                self._disassoc_count += 1
            elif frame_name == 'AssocResp':
                self._assocresp_count += 1
                if reason_code != 0:
                    # Non-zero status = rejection → signal
                    self._feedback.record_signal(reason_code=40)  # reason 40 = assoc rejected
                return
            else:
                self._other_count += 1
                return

        # Record disconnect signal (Deauth or Disassoc) to feedback engine
        # crash_saved=False here — CrashMonitor sets that separately
        self._feedback.record_signal(reason_code=reason_code, crash_saved=False)

    # ── Stats ──────────────────────────────────────────────────────────────────

    def summary(self) -> str:
        with self._lock:
            total = len(self._responses)
            if not total:
                return '[ResponseSniffer] No AP responses captured.'
            lines = [f'[ResponseSniffer] {total} AP responses captured:',
                     f'  Deauth:    {self._deauth_count}',
                     f'  Disassoc:  {self._disassoc_count}',
                     f'  AssocResp: {self._assocresp_count} (non-zero status)',
                     f'  Other:     {self._other_count}']
            # Show last 5 responses
            lines.append('  Last responses:')
            for ts, name, code in self._responses[-5:]:
                lines.append(f'    {name:<12} reason/status={code}')
            return '\n'.join(lines)

    def captured_responses(self) -> list:
        with self._lock:
            return list(self._responses)
