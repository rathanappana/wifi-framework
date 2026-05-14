"""
Expansion engine test — feedback-driven loop fuzzing on confirmed crash frames.

Loads .bin crash files as seeds, generates variants via 6 mutation strategies,
injects them, and saves new crashes. New crashes feed back as seeds (BFS).

Runs until budget exhausted or no more seeds remain.

Run:
  # Expand a single crash frame (200-frame budget)
  sudo python3 run.py wlan0 fuzz-expand --config ~/iith/iith_wpa.conf \
    --file /tmp/wifi_fuzz_crash_20260513_103651_ie-fuzzing_rsn-assoc-rsn-version-256.bin

  # Expand all crash frames in /tmp/ (500-frame budget)
  sudo python3 run.py wlan0 fuzz-expand --config ~/iith/iith_wpa.conf \
    --batch --budget 500

  # Deep sweep on one crash: exhaustive RSN version field (65536 values)
  sudo python3 run.py wlan0 fuzz-expand --config ~/iith/iith_wpa.conf \
    --file /tmp/wifi_fuzz_crash_*.bin --budget 2000 --sweep

Strategies applied per field in order:
  boundary_arith  → seed ± 1,2,4,8,16,32,64,128 (16 variants per field)
  bit_flip        → flip each bit (8×width variants per field)
  byte_boundary   → 0x00,0x01,0x7F,0x80,0xFE,0xFF per byte
  random          → random values (fill remaining budget)
  havoc           → model-agnostic random mutations (always runs)
  increment       → sequential from seed value (optional)
  sweep           → exhaustive 0..max (only with --sweep flag)
"""
import os
import sys
import glob
import argparse
import time

from dependencies.libwifi.wifi import log, STATUS
from library.testcase import Trigger, Action, Test
from fuzz.expander import ExpansionEngine, Strategy


def _discover_crash_files() -> list:
    return sorted(
        glob.glob('/tmp/wifi_fuzz_crash_*.bin') +
        glob.glob('/tmp/wifi_expand_crash_*.bin')
    )


class FuzzExpand(Test):
    """
    Expansion loop: take confirmed crash frames, generate variants, re-inject.

    Flags (via command line, run.py uses parse_known_args):
      --file PATH      Single crash file to expand
      --batch          Expand all /tmp/wifi_fuzz_crash_*.bin files
      --budget N       Max total frames to inject (default 200)
      --sweep          Add exhaustive field sweep strategy
      --delay S        Inter-frame delay in seconds (default 0.05)
    """
    name = 'fuzz-expand'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,    action=Action.Function),
            Action(trigger=Trigger.Disconnected, action=Action.Terminate),
        ])

    def run(self, station):
        import argparse as _ap
        _p = _ap.ArgumentParser(add_help=False)
        _p.add_argument('--file',   default=None)
        _p.add_argument('--batch',  action='store_true')
        _p.add_argument('--budget', type=int,   default=200)
        _p.add_argument('--sweep',  action='store_true')
        _p.add_argument('--delay',  type=float, default=0.05)
        args, _ = _p.parse_known_args()

        # Collect seed files
        seeds = []
        if args.batch:
            seeds = _discover_crash_files()
            if not seeds:
                log(STATUS, '[fuzz-expand] No crash files in /tmp/', color='orange')
                return
        elif args.file:
            if os.path.exists(args.file):
                seeds = [args.file]
            else:
                log(STATUS, f'[fuzz-expand] File not found: {args.file}', color='red')
                return
        else:
            seeds = _discover_crash_files()
            if not seeds:
                log(STATUS, '[fuzz-expand] No seeds found. Set --file or --batch.', color='orange')
                log(STATUS, 'Available in /tmp/:')
                for f in glob.glob('/tmp/*.bin'):
                    log(STATUS, f'  {f}')
                return

        log(STATUS, f'[fuzz-expand] Seeds: {len(seeds)}  Budget: {args.budget}',
            color='cyan')
        for s in seeds:
            log(STATUS, f'  {os.path.basename(s)}')

        # Choose strategies
        strategies = [
            Strategy.BOUNDARY_ARITH,
            Strategy.BIT_FLIP,
            Strategy.BYTE_BOUNDARY,
            Strategy.RANDOM,
            Strategy.HAVOC,
            Strategy.INCREMENT,
        ]
        if args.sweep:
            strategies.append(Strategy.SWEEP)
            log(STATUS, '[fuzz-expand] Sweep mode: exhaustive field values enabled',
                color='orange')

        # Run expansion
        engine = ExpansionEngine(
            station=station,
            seed_paths=seeds,
            budget=args.budget,
            strategies=strategies,
            per_seed_budget=max(50, args.budget // max(len(seeds), 1)),
            inter_frame_s=args.delay,
        )

        log(STATUS, '[fuzz-expand] Starting expansion loop...', color='cyan')
        results = engine.run()

        # Summary
        log(STATUS, engine.summary(), color='cyan')
        log(STATUS, '', color='cyan')

        # Per-seed summary
        total_new = sum(len(r.new_crashes) for r in results)
        log(STATUS, f'[fuzz-expand] ═══ PER-SEED RESULTS ═══', color='cyan')
        for r in results:
            status_color = 'red' if r.new_crashes else 'green'
            status = f'NEW CRASHES: {len(r.new_crashes)}' if r.new_crashes else 'no new crashes'
            log(STATUS, f'  {os.path.basename(r.seed_path):<55}  {status}',
                color=status_color)
            if r.new_crashes:
                for cp in r.new_crashes:
                    log(STATUS, f'    → {cp}', color='red')
            if r.fields_tested:
                log(STATUS, f'    Fields: {", ".join(r.fields_tested[:5])}')
            if r.strategies:
                log(STATUS, f'    Strategies triggered: {", ".join(r.strategies[:5])}')

        log(STATUS, f'\n[fuzz-expand] Total new crashes: {total_new}', color='cyan')
        log(STATUS, f'[fuzz-expand] Total injected: {engine._injected}', color='cyan')

        if total_new == 0:
            log(STATUS, '[fuzz-expand] No new crashes. AP parser may be robust OR '
                'disconnects are timing-dependent. Try --budget 1000 or --sweep.',
                color='orange')

    def generate(self, station):
        self.actions[0].set_function(self.run)
        self.actions[0].set_terminate(delay=5)
