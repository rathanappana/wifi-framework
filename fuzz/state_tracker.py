"""
802.11 protocol state machine tracker for stateful fuzzing.

Tracks STA<->AP association state by watching wpaspy events.
Records which injected frame caused each state transition.

State machine:
  IDLE → AUTHENTICATING → AUTHENTICATED → ASSOCIATING → CONNECTED → DISCONNECTED
              ↑                                                           |
              └───────────────────────────────────────────────────────────┘

State violation injections (the attack surface):
  From CONNECTED: send Auth frame     → AP should ignore or deauth (state machine reset)
  From CONNECTED: send AssocReq again → "unexpected reassoc" handler
  From CONNECTED: send unprotected Data (Protected=0) → AP should deauth (reason=7)
  From CONNECTED: send Data ToDS=0    → wrong direction data path
  From AUTHENTICATED: send Data       → pre-assoc data injection
  From IDLE: send Action frames       → pre-auth action dispatch
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class STAState(IntEnum):
    IDLE            = 0   # no connection
    AUTHENTICATING  = 1   # Auth frame sent, waiting response
    AUTHENTICATED   = 2   # Auth complete, not yet associated
    ASSOCIATING     = 3   # AssocReq sent, waiting response
    CONNECTED       = 4   # EAPOL done, PTK installed
    DISCONNECTED    = 5   # got deauth/disassoc


# wpaspy message → state mapping (substring match)
_WPASPY_STATE_MAP = {
    'CTRL-EVENT-DISCONNECTED':          STAState.DISCONNECTED,
    'CTRL-EVENT-ASSOC-REJECT':          STAState.AUTHENTICATED,
    'Associated with':                  STAState.ASSOCIATING,
    'WPA: Key negotiation completed':   STAState.CONNECTED,
    'CTRL-EVENT-CONNECTED':             STAState.CONNECTED,
    'SME: Trying to authenticate':      STAState.AUTHENTICATING,
    'wlan0: PMKSA-CACHE-ADDED':        STAState.CONNECTED,
}


@dataclass
class StateTransition:
    """
    One recorded state transition.

    Attributes:
        ts:           Unix timestamp.
        from_state:   State before transition.
        to_state:     State after transition.
        trigger_msg:  wpaspy message that triggered it (if any).
        inject_phase: Campaign phase in progress at transition time.
        inject_label: Label of last injected frame at transition time.
        inject_count: Injection counter at transition time.
    """
    ts:           float
    from_state:   STAState
    to_state:     STAState
    trigger_msg:  str   = ''
    inject_phase: str   = ''
    inject_label: str   = ''
    inject_count: int   = 0


class StateTracker:
    """
    Watches wpaspy events and tracks 802.11 association state.

    Designed for integration with CrashMonitor / FuzzCampaign:
      1. Call update_from_wpaspy(msg) for every wpaspy message received.
      2. Call set_inject_context(phase, label, count) before each injection.
      3. Query current_state() and state_transitions() for analysis.

    Thread-safety: single-threaded (same event loop as wifi-framework).
    """

    def __init__(self):
        self._state:          STAState           = STAState.IDLE
        self._transitions:    List[StateTransition] = []
        self._inject_phase:   str                = ''
        self._inject_label:   str                = ''
        self._inject_count:   int                = 0
        self._last_bssid:     str                = ''
        self._connected_at:   Optional[float]    = None
        self._disconnect_count: int              = 0

    # ── Context setters ────────────────────────────────────────────────────────

    def set_inject_context(self, phase: str, label: str, count: int) -> None:
        """Call before each injection to record causal context."""
        self._inject_phase = phase
        self._inject_label = label
        self._inject_count = count

    # ── State update ───────────────────────────────────────────────────────────

    def update_from_wpaspy(self, msg: str) -> Optional[StateTransition]:
        """
        Parse a wpaspy message and update state if applicable.

        Args:
            msg: Raw wpaspy message string.

        Returns:
            StateTransition if state changed, None otherwise.
        """
        new_state = None
        for substring, state in _WPASPY_STATE_MAP.items():
            if substring in msg:
                new_state = state
                break

        if new_state is None or new_state == self._state:
            return None

        # Extract BSSID from disconnect message
        if 'CTRL-EVENT-DISCONNECTED' in msg:
            self._disconnect_count += 1
            parts = msg.split()
            for p in parts:
                if p.startswith('bssid='):
                    self._last_bssid = p[6:]

        transition = StateTransition(
            ts=time.time(),
            from_state=self._state,
            to_state=new_state,
            trigger_msg=msg.strip(),
            inject_phase=self._inject_phase,
            inject_label=self._inject_label,
            inject_count=self._inject_count,
        )

        if new_state == STAState.CONNECTED:
            self._connected_at = time.time()
        if new_state == STAState.DISCONNECTED:
            self._connected_at = None

        self._state = new_state
        self._transitions.append(transition)
        return transition

    # ── Queries ────────────────────────────────────────────────────────────────

    def current_state(self) -> STAState:
        return self._state

    def is_connected(self) -> bool:
        return self._state == STAState.CONNECTED

    def connection_age(self) -> Optional[float]:
        """Seconds since last CONNECTED transition. None if not connected."""
        if self._connected_at is None:
            return None
        return time.time() - self._connected_at

    def state_transitions(self) -> List[StateTransition]:
        return list(self._transitions)

    def disconnects_caused_by_phase(self, phase: str) -> List[StateTransition]:
        """Return all DISCONNECTED transitions that occurred during given phase."""
        return [t for t in self._transitions
                if t.to_state == STAState.DISCONNECTED and t.inject_phase == phase]

    def regression_transitions(self) -> List[StateTransition]:
        """
        Return transitions that lost connectivity.

        DISCONNECTED (=5) is semantically IDLE — it's a reset, not an advance.
        Regressions: any transition FROM CONNECTED/ASSOCIATING/AUTHENTICATED
        TO DISCONNECTED or IDLE.
        """
        loss_states = {STAState.DISCONNECTED, STAState.IDLE}
        gain_states = {STAState.AUTHENTICATED, STAState.ASSOCIATING, STAState.CONNECTED}
        return [t for t in self._transitions
                if t.from_state in gain_states and t.to_state in loss_states]

    def disconnect_count(self) -> int:
        return self._disconnect_count

    def summary(self) -> str:
        regress = len(self.regression_transitions())
        return (f"state={self._state.name} transitions={len(self._transitions)} "
                f"disconnects={self._disconnect_count} regressions={regress}")

    def to_dict_list(self) -> list:
        """Serialize all transitions for JSONL logging."""
        return [
            {
                'ts': t.ts,
                'from': t.from_state.name,
                'to': t.to_state.name,
                'msg': t.trigger_msg,
                'phase': t.inject_phase,
                'label': t.inject_label,
                'inject_count': t.inject_count,
            }
            for t in self._transitions
        ]


# ── State-violation frame generators ─────────────────────────────────────────

def state_violation_frames(station) -> list:
    """
    Return list of (label, frame) for out-of-state injections.

    These frames are "wrong" for the current CONNECTED state:
      - Auth frames: AP should ignore (we're connected) or deauth
      - Unprotected Data: AP should send deauth reason=7 (no encryption)
      - Pre-auth Data: data frame from pre-association state
      - Duplicate AssocReq: triggers reassoc handler

    All inject WHILE station is in CONNECTED state.
    """
    import struct
    from scapy.layers.dot11 import Dot11, Dot11QoS, Dot11Auth

    frames = []

    # 1. Auth frames while connected (trigger state machine reset?)
    for algo, seq, label in [
        (0, 1, 'auth-open-seq1-while-connected'),
        (0, 2, 'auth-open-seq2-while-connected'),
        (3, 1, 'auth-sae-commit-while-connected'),
        (2, 1, 'auth-ft-while-connected'),
        (0xFFFF, 1, 'auth-unknown-algo-while-connected'),
    ]:
        body = struct.pack('<HHH', algo, seq, 0)
        p = Dot11(type=0, subtype=11, FCfield=0,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss)
        p = p / body
        frames.append((label, p))

    # 2. Unprotected Data frame while connected (Protected bit must be 1)
    # FCfield=0x01 = ToDS only, no Protected bit → AP sees plaintext data
    for fc, label in [
        (0x01, 'data-unprotected-tods'),
        (0x00, 'data-unprotected-no-tods'),
        (0x02, 'data-unprotected-fromds'),
    ]:
        p = Dot11(type=2, subtype=0, FCfield=fc,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss)
        p = p / (b'\x00' * 16)
        frames.append((label, p))

    # 3. Null data frames with wrong power-save state
    for fc, label in [
        (0x11, 'null-tods-pwrsave-1'),    # ToDS + PowerMgmt
        (0x31, 'null-tods-pm-moredata'),  # ToDS + PM + MoreData
        (0x01, 'null-tods-pm-0'),         # ToDS only, no PM
    ]:
        p = Dot11(type=2, subtype=4, FCfield=fc,
                  addr1=station.bss, addr2=station.mac, addr3=station.bss)
        frames.append((label, p))

    # 4. Duplicate AssocReq while already associated
    cap_fixed = struct.pack('<HH', 1073, 10)
    rates_ie = b'\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24'
    from fuzz.mutator import ie_build
    rsn_ie = ie_build(48, b'\x01\x00' + b'\x00\x0f\xac\x02' + b'\x01\x00' + b'\x00\x0f\xac\x04' + b'\x01\x00' + b'\x00\x0f\xac\x02')
    p = Dot11(type=0, subtype=0, FCfield=0,
              addr1=station.bss, addr2=station.mac, addr3=station.bss)
    p = p / (cap_fixed + rates_ie + rsn_ie)
    frames.append(('assocreq-while-associated', p))

    # 5. Disassoc from STA→AP (we disassoc ourselves, then immediately send data)
    p = Dot11(type=0, subtype=10, FCfield=0,
              addr1=station.bss, addr2=station.mac, addr3=station.bss)
    p = p / struct.pack('<H', 0)  # reason=0
    frames.append(('disassoc-then-data', p))

    return frames
