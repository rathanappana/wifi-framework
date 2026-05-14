"""
Tier 1: Behavioral feedback engine for Wi-Fi fuzzing.

Scores mutation categories based on observed AP signals:
  - AP disconnect + reason code (best signal — parser actually triggered)
  - Response latency spike (parser doing more work → deeper code path)
  - No reaction (frame dropped or ignored — low value mutation)

Scores persist across sessions (/tmp/fuzz_feedback_<profile>.json).
Each new campaign loads prior scores → prioritizes high-signal categories.

Integration:
  FeedbackEngine is created by FuzzCampaign.
  record_inject() called before each injection.
  record_signal() called when AP reaction observed (by ResponseSniffer or wpaspy).
  report() called at campaign end → ranked mutation priorities.
  save() called at campaign end → persists for next run.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, asdict
from enum import IntEnum
from typing import Dict, List, Optional, Tuple


class Signal(IntEnum):
    """
    Observed AP signal strength. Higher = more interesting.

    Reason code mapping (IEEE 802.11-2020):
      R6  = class 2 frame from non-authenticated STA → wrong state
      R7  = class 3 frame from non-associated STA → assoc state confusion
      R8  = STA left ESS (STA sent deauth/disassoc) → state machine
      R9  = STA not authenticated → RSN/auth parser rejection
      R23 = invalid IE → direct IE parser error (best signal)
    """
    ALIVE        = 0    # no AP reaction
    DROP         = 1    # frame silently dropped (alive check passed immediately)
    LATENCY      = 3    # response latency > 2× baseline → slower parser path
    DISCONNECT   = 5    # disconnect, unknown reason
    DISC_R8      = 6    # reason=8: state machine confusion (auth while connected)
    DISC_R6      = 8    # reason=6: class 2 frame → HE/VHT/HT parser path
    DISC_R9      = 10   # reason=9: RSN/IE rejection → parser actively parsed
    DISC_R23     = 12   # reason=23: invalid IE directly → deep parser hit
    DISC_R7      = 9    # reason=7: assoc state confusion
    CRASH_SAVED  = 20   # crash artifact saved (strongest signal)


# Map wpaspy/sniffer reason codes → Signal
_REASON_TO_SIGNAL: Dict[int, Signal] = {
    6:  Signal.DISC_R6,
    7:  Signal.DISC_R7,
    8:  Signal.DISC_R8,
    9:  Signal.DISC_R9,
    23: Signal.DISC_R23,
}


@dataclass
class MutationRecord:
    """One recorded injection + its observed AP signal."""
    phase:       str
    label:       str
    ts:          float
    signal:      int       # Signal enum value
    reason_code: int = 0
    latency_ms:  float = 0.0


def _category(phase: str, label: str) -> str:
    """
    Derive mutation category key from phase + label.

    Goals:
      - Group related mutations: "rsn-version-256" and "rsn-version-1024" → "rsn-version"
      - Strip specific values (numbers) to generalize
      - Keep phase prefix for phase-level analysis

    Examples:
      phase=ie-fuzzing label=rsn-assoc-rsn-version-256  → "ie-fuzzing:rsn-version"
      phase=ie-fuzzing label=rates-assoc-rates-all-zeros → "ie-fuzzing:rates"
      phase=mgmt-plane label=auth-algo-0x0002            → "mgmt-plane:auth-algo"
      phase=action-block-ack label=addba-bufsz-65-off-by-one → "action-block-ack:addba-bufsz"
    """
    # Strip leading direction markers (assoc/reassoc/rsn-)
    stripped = label
    for prefix in ('rsn-assoc-', 'rsn-reassoc-', 'assoc-', 'reassoc-',
                   'rates-assoc-', 'rates-reassoc-'):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
            break

    # Split on '-', remove pure-numeric and hex (0x...) tokens
    parts = stripped.split('-')
    kept = []
    for p in parts:
        if p.startswith('0x') or p.isdigit():
            break  # stop at first numeric value
        kept.append(p)

    # Keep max 2 meaningful parts for good grouping:
    # rsn-version-256 → rsn-version, rsn-group-tkip → rsn-group
    key = '-'.join(kept[:2]) if kept else label[:20]
    return f'{phase}:{key}'


class FeedbackEngine:
    """
    Scores mutation categories from observed AP behavioral signals.

    Thread-safe: ResponseSniffer calls record_signal() from a background thread.

    Usage:
        fe = FeedbackEngine(profile_id='ee55a8')
        fe.load()                                  # load prior session scores
        fe.record_inject('ie-fuzzing', 'rsn-version-256')
        fe.record_signal(Signal.DISC_R9, reason_code=9)
        fe.record_inject('ie-fuzzing', 'rsn-version-1')
        fe.record_alive()                          # no reaction
        fe.report()                                # ranked categories
        fe.save()                                  # persist for next run
    """

    PERSIST_DIR = '/tmp'

    def __init__(self, profile_id: str = ''):
        self._profile_id  = profile_id
        self._records:    List[MutationRecord] = []
        self._cat_scores: Dict[str, float]     = {}   # cumulative score per category
        self._cat_counts: Dict[str, int]       = {}   # injection count per category
        self._phase_scores: Dict[str, float]   = {}   # cumulative score per phase
        self._lock = threading.Lock()

        # Inject context (set before inject, read on signal)
        self._last_phase  = ''
        self._last_label  = ''
        self._last_inject_ts = 0.0

        # Latency baseline: rolling average of response latency for ALIVE frames
        self._latency_samples: List[float] = []
        self._latency_baseline = 0.0

    # ── Context setters ────────────────────────────────────────────────────────

    def record_inject(self, phase: str, label: str) -> None:
        """Call immediately before each injection."""
        with self._lock:
            self._last_phase = phase
            self._last_label = label
            self._last_inject_ts = time.time()
            cat = _category(phase, label)
            self._cat_counts[cat] = self._cat_counts.get(cat, 0) + 1

    def record_alive(self, latency_ms: float = 0.0) -> None:
        """AP still alive after this injection. Low signal but track latency."""
        with self._lock:
            # Check latency spike against baseline
            sig = Signal.ALIVE
            if latency_ms > 0:
                self._latency_samples.append(latency_ms)
                if len(self._latency_samples) > 20:
                    self._latency_samples.pop(0)
                self._latency_baseline = sum(self._latency_samples) / len(self._latency_samples)
                if self._latency_baseline > 0 and latency_ms > self._latency_baseline * 2.0:
                    sig = Signal.LATENCY

            self._record_score(self._last_phase, self._last_label, int(sig), 0, latency_ms)

    def record_signal(self, reason_code: int = 0, crash_saved: bool = False) -> None:
        """
        Record AP disconnect/crash signal. Call when disconnect detected.

        Args:
            reason_code: 802.11 reason code from Deauth/Disassoc frame.
            crash_saved: True if crash artifact was saved.
        """
        with self._lock:
            latency_ms = (time.time() - self._last_inject_ts) * 1000.0
            # Accumulate reason_code signal + crash bonus (additive, not either/or)
            reason_sig = int(_REASON_TO_SIGNAL.get(reason_code, Signal.DISCONNECT))
            score = reason_sig + (int(Signal.CRASH_SAVED) if crash_saved else 0)
            self._record_score(self._last_phase, self._last_label,
                               score, reason_code, latency_ms)

    def _record_score(self, phase: str, label: str, score: int,
                      reason_code: int, latency_ms: float) -> None:
        rec = MutationRecord(phase=phase, label=label, ts=time.time(),
                             signal=score, reason_code=reason_code,
                             latency_ms=latency_ms)
        self._records.append(rec)

        cat = _category(phase, label)
        self._cat_scores[cat]     = self._cat_scores.get(cat, 0.0) + float(score)
        self._phase_scores[phase] = self._phase_scores.get(phase, 0.0) + float(score)

    # ── Queries ────────────────────────────────────────────────────────────────

    def ranked_categories(self) -> List[Tuple[str, float, int]]:
        """
        Return mutation categories sorted by total score descending.
        Returns: [(category, total_score, inject_count), ...]
        """
        with self._lock:
            out = []
            for cat, score in sorted(self._cat_scores.items(),
                                     key=lambda x: x[1], reverse=True):
                out.append((cat, score, self._cat_counts.get(cat, 0)))
            return out

    def ranked_phases(self) -> List[Tuple[str, float]]:
        """Return phases sorted by total score descending."""
        with self._lock:
            return sorted(self._phase_scores.items(), key=lambda x: x[1], reverse=True)

    def high_interest(self, top_n: int = 10) -> List[str]:
        """Return top-N mutation category keys with highest signal."""
        return [cat for cat, _, _ in self.ranked_categories()[:top_n]]

    def zero_signal_phases(self) -> List[str]:
        """Return phases that produced zero signal — candidates for budget reduction."""
        with self._lock:
            all_phases = set(self._phase_scores.keys())
            return [p for p in all_phases if self._phase_scores.get(p, 0) == 0]

    def total_records(self) -> int:
        with self._lock:
            return len(self._records)

    # ── Persistence ────────────────────────────────────────────────────────────

    def save(self, path: str = None) -> str:
        """Persist scores to JSON for next campaign run."""
        path = path or os.path.join(self.PERSIST_DIR,
                                     f'fuzz_feedback_{self._profile_id}.json')
        with self._lock:
            data = {
                'profile_id':   self._profile_id,
                'saved_at':     time.time(),
                'cat_scores':   self._cat_scores,
                'cat_counts':   self._cat_counts,
                'phase_scores': self._phase_scores,
                'record_count': len(self._records),
            }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return path

    def load(self, path: str = None) -> bool:
        """
        Load prior session scores. Adds to current scores (not replace).
        Returns True if loaded successfully.
        """
        path = path or os.path.join(self.PERSIST_DIR,
                                     f'fuzz_feedback_{self._profile_id}.json')
        if not os.path.exists(path):
            return False
        try:
            with open(path) as f:
                data = json.load(f)
            with self._lock:
                # Merge with decay factor (prior session scores count 50%)
                for cat, score in data.get('cat_scores', {}).items():
                    self._cat_scores[cat] = self._cat_scores.get(cat, 0) + score * 0.5
                for cat, count in data.get('cat_counts', {}).items():
                    self._cat_counts[cat] = self._cat_counts.get(cat, 0) + count
                for phase, score in data.get('phase_scores', {}).items():
                    self._phase_scores[phase] = self._phase_scores.get(phase, 0) + score * 0.5
            return True
        except Exception:
            return False

    # ── Report ─────────────────────────────────────────────────────────────────

    def report(self) -> str:
        """Return formatted feedback report string."""
        lines = ['', '═' * 64,
                 ' FEEDBACK REPORT — Mutation Signal Scores',
                 '═' * 64]

        ranked = self.ranked_categories()
        if not ranked:
            lines.append('  No data recorded.')
            return '\n'.join(lines)

        lines.append(f'  {"Category":<45}  {"Score":>7}  {"Count":>5}  Avg')
        lines.append(f'  {"─"*45}  {"─"*7}  {"─"*5}  ───')

        for cat, score, count in ranked[:20]:
            avg = score / count if count else 0
            marker = '  *** HIGH SIGNAL' if score >= 10 else ''
            lines.append(f'  {cat:<45}  {score:>7.1f}  {count:>5d}  '
                         f'{avg:.2f}{marker}')

        lines.append('')
        lines.append('  Top phases by signal:')
        for phase, score in self.ranked_phases()[:8]:
            lines.append(f'    {phase:<30} score={score:.1f}')

        zero = self.zero_signal_phases()
        if zero:
            lines.append('')
            lines.append(f'  Zero-signal phases (reduce next run): {zero}')

        lines.append('')
        lines.append(f'  Total recorded: {self.total_records()} injections')
        lines.append('═' * 64)
        return '\n'.join(lines)
