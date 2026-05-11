#!/usr/bin/env python3
"""
Unit tests for Phase 1 (daemon hooks) + Phase 2 (FrameMutator).

Run: python3 test_mutator.py
No Wi-Fi interface required.
"""
import sys, random
sys.path.insert(0, '.')

from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
    Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11Deauth,
    Dot11Elt, RadioTap
)
from scapy.all import raw

from library.mutator import (
    FrameMutator, MutationConfig,
    parse_ies, build_ies, mgmt_ie_offset,
    STRATEGIES, IE_RSN, IE_HT_CAPABILITIES,
)

PASS = 0
FAIL = 0

def ok(name):
    global PASS
    PASS += 1
    print(f"  PASS  {name}")

def fail(name, reason):
    global FAIL
    FAIL += 1
    print(f"  FAIL  {name}: {reason}")

def check(name, condition, reason=""):
    if condition:
        ok(name)
    else:
        fail(name, reason or "assertion failed")


# ── Helper frames ─────────────────────────────────────────────────────────────

RSN_BODY = bytes([
    0x01,0x00,                  # version=1
    0x00,0x0f,0xac,0x04,        # group=CCMP
    0x01,0x00,                  # pairwise count=1
    0x00,0x0f,0xac,0x04,        # pairwise=CCMP
    0x01,0x00,                  # AKM count=1
    0x00,0x0f,0xac,0x02,        # AKM=PSK
    0x00,0x00,                  # RSN caps
])

def make_beacon(ssid=b'TestAP', with_ht=False):
    f = (
        Dot11(type=0, subtype=8,
              addr1='ff:ff:ff:ff:ff:ff',
              addr2='aa:bb:cc:dd:ee:ff',
              addr3='aa:bb:cc:dd:ee:ff') /
        Dot11Beacon(cap='ESS') /
        Dot11Elt(ID=0, info=ssid) /
        Dot11Elt(ID=1, info=bytes([0x82,0x84,0x8b,0x96])) /
        Dot11Elt(ID=48, info=RSN_BODY)
    )
    if with_ht:
        f /= Dot11Elt(ID=45, info=b'\x6e\x00' + b'\x00'*24)
    return f

def make_assoc_req():
    return (
        Dot11(type=0, subtype=0,
              addr1='aa:bb:cc:dd:ee:ff',
              addr2='11:22:33:44:55:66',
              addr3='aa:bb:cc:dd:ee:ff') /
        Dot11AssoReq(cap='ESS', listen_interval=10) /
        Dot11Elt(ID=0,  info=b'TestAP') /
        Dot11Elt(ID=1,  info=bytes([0x82,0x84,0x8b,0x96])) /
        Dot11Elt(ID=48, info=RSN_BODY)
    )

def make_data():
    return Dot11(type=2, subtype=8,
                 addr1='aa:bb:cc:dd:ee:ff',
                 addr2='11:22:33:44:55:66',
                 addr3='aa:bb:cc:dd:ee:ff',
                 FCfield='to_DS')

def make_deauth():
    return (
        Dot11(type=0, subtype=12,
              addr1='ff:ff:ff:ff:ff:ff',
              addr2='aa:bb:cc:dd:ee:ff',
              addr3='aa:bb:cc:dd:ee:ff') /
        Dot11Deauth(reason=1)
    )

def make_beacon_with_radiotap():
    return RadioTap() / make_beacon()


# ── Test 1: IE parser round-trip ──────────────────────────────────────────────

def test_ie_roundtrip():
    print("\n[1] IE parse/build round-trip")

    beacon = make_beacon()
    raw_frame = bytes(beacon)
    offset = mgmt_ie_offset(beacon)
    check("offset is int", isinstance(offset, int))
    check("offset > 0", offset > 0)

    ies = parse_ies(raw_frame[offset:])
    check("3 IEs parsed", len(ies) == 3, f"got {len(ies)}")
    check("IE tags correct", [t for t,_ in ies] == [0, 1, 48])

    rebuilt = build_ies(ies)
    check("round-trip exact match", raw_frame[offset:] == rebuilt,
          f"orig={raw_frame[offset:].hex()} rebuilt={rebuilt.hex()}")


def test_ie_roundtrip_with_radiotap():
    print("\n[1b] IE offset with RadioTap prefix")
    f = make_beacon_with_radiotap()
    offset = mgmt_ie_offset(f)
    check("offset not None with RT", offset is not None)
    raw_f = bytes(f)
    ies = parse_ies(raw_f[offset:])
    check("IEs correct under RT", len(ies) == 3, f"got {len(ies)}")


# ── Test 2: Non-IE frames return None offset ──────────────────────────────────

def test_no_ie_offset():
    print("\n[2] Non-IE frames → None offset")

    data = make_data()
    check("data frame → None", mgmt_ie_offset(data) is None)

    deauth = make_deauth()
    check("deauth (no IEs) → None", mgmt_ie_offset(deauth) is None)

    non_wifi = b'\xde\xad\xbe\xef' * 10
    from scapy.all import Raw
    pkt = Raw(non_wifi)
    check("raw bytes → None", mgmt_ie_offset(pkt) is None)


# ── Test 3: Each strategy mutates frame ──────────────────────────────────────

def test_all_strategies():
    print("\n[3] All mutation strategies")
    beacon = make_beacon(with_ht=True)
    raw_f = bytes(beacon)
    offset = mgmt_ie_offset(beacon)

    for name, fn in STRATEGIES.items():
        try:
            result = fn(raw_f, ie_offset=offset)
            check(f"{name}: returns bytes", isinstance(result, bytes))
            check(f"{name}: same length ±64",
                  abs(len(result) - len(raw_f)) <= 64,
                  f"result len={len(result)} orig={len(raw_f)}")
            # Mutations should almost always change something
            # (ie_length/ie_overflow patch in-place so length same)
        except Exception as e:
            fail(f"{name}: exception", str(e))


# ── Test 4: FrameMutator — basic operation ────────────────────────────────────

def test_frame_mutator_basic():
    print("\n[4] FrameMutator basic operation")
    mutator = FrameMutator()
    beacon = make_beacon()

    results = [mutator.tx_hook(beacon, 'mon') for _ in range(20)]
    check("tx_hook never returns None for beacon", all(r is not None for r in results))
    check("tx_hook always returns Dot11", all(r.haslayer(Dot11) for r in results))
    check("seen=20", mutator.stats['seen'] == 20, str(mutator.stats))
    check("mutated>0", mutator.stats['mutated'] > 0, str(mutator.stats))
    check("dropped=0", mutator.stats['dropped'] == 0)


# ── Test 5: FrameMutator — data frames pass through ──────────────────────────

def test_frame_mutator_passthrough():
    print("\n[5] Non-mgmt frames pass through unchanged")
    mutator = FrameMutator()
    data = make_data()

    for _ in range(10):
        out = mutator.tx_hook(data, 'mon')
        check("data frame identical", out == data)

    deauth = make_deauth()
    for _ in range(5):
        out = mutator.tx_hook(deauth, 'mon')
        check("deauth (no IEs) not None", out is not None)

    check("skipped>0", mutator.stats['skipped'] > 0, str(mutator.stats))


# ── Test 6: FrameMutator — drop probability ──────────────────────────────────

def test_drop_probability():
    print("\n[6] Drop probability")
    random.seed(42)
    cfg = MutationConfig(drop_probability=0.5)
    mutator = FrameMutator(cfg)
    beacon = make_beacon()

    results = [mutator.tx_hook(beacon, 'mon') for _ in range(200)]
    drops = sum(1 for r in results if r is None)
    # With p=0.5 and 200 trials, expect ~100 drops ± 30
    check("drop ~50%", 60 <= drops <= 140, f"drops={drops}/200")
    check("stat dropped matches", mutator.stats['dropped'] == drops)


# ── Test 7: FrameMutator — subtype filter ────────────────────────────────────

def test_subtype_filter():
    print("\n[7] Subtype filter")
    # Only mutate beacon (subtype=8), not assoc req (subtype=0)
    cfg = MutationConfig(subtype_filter={8})
    mutator = FrameMutator(cfg)

    beacon = make_beacon()
    assoc  = make_assoc_req()

    beacon_results = [mutator.tx_hook(beacon, 'mon') for _ in range(20)]
    assoc_results  = [mutator.tx_hook(assoc,  'mon') for _ in range(20)]

    check("beacon mutated", mutator.stats['mutated'] > 0)
    check("assoc skipped", all(
        bytes(r) == bytes(assoc) for r in assoc_results if r is not None
    ))


# ── Test 8: FrameMutator — single strategy ───────────────────────────────────

def test_single_strategy():
    print("\n[8] Single strategy config")
    cfg = MutationConfig(enabled_strategies=['rsn_body'], mutations_per_frame=1)
    mutator = FrameMutator(cfg)
    beacon = make_beacon()

    raw_orig = bytes(beacon)
    offset = mgmt_ie_offset(beacon)

    changed_count = 0
    for _ in range(50):
        out = mutator.tx_hook(beacon, 'mon')
        if out is not None and bytes(out) != raw_orig:
            changed_count += 1

    check("rsn_body changes most frames", changed_count >= 40,
          f"changed={changed_count}/50")


# ── Test 9: rx_hook disabled by default ─────────────────────────────────────

def test_rx_hook_disabled():
    print("\n[9] rx_hook disabled by default (mutate_rx=False)")
    mutator = FrameMutator()
    beacon = make_beacon_with_radiotap()

    for _ in range(20):
        out = mutator.rx_hook(beacon, 'mon')
        check("rx_hook passthrough", bytes(out) == bytes(beacon))

    check("seen=0 (mutate_rx=False skips tracking)", mutator.stats['seen'] == 0)


# ── Test 10: daemon hook wiring (mock) ───────────────────────────────────────

def test_daemon_hook_wiring():
    print("\n[10] Daemon tx_hook/rx_hook wiring (mock station)")

    injected = []
    received = []

    class MockDaemon:
        def __init__(self):
            self.tx_hook = None
            self.rx_hook = None

        def inject_mon(self, p):
            if self.tx_hook:
                p = self.tx_hook(p, 'mon')
                if p is None:
                    return
            injected.append(p)

        def dispatch_rx(self, p):
            if self.rx_hook:
                p = self.rx_hook(p, 'mon')
                if p is None:
                    return
            received.append(p)

    daemon = MockDaemon()
    mutator = FrameMutator(MutationConfig(
        mutations_per_frame=1,
        mutate_rx=True,
    ))
    daemon.tx_hook = mutator.tx_hook
    daemon.rx_hook = mutator.rx_hook

    beacon = make_beacon()

    # TX: inject 10 beacons
    for _ in range(10):
        daemon.inject_mon(beacon)
    check("tx: 10 frames injected", len(injected) == 10)
    check("tx: frames are Dot11", all(f.haslayer(Dot11) for f in injected))

    # RX: dispatch 10 beacons
    for _ in range(10):
        daemon.dispatch_rx(beacon)
    check("rx: 10 frames received", len(received) == 10)

    # Drop test
    drop_daemon = MockDaemon()
    drop_mutator = FrameMutator(MutationConfig(drop_probability=1.0))
    drop_daemon.tx_hook = drop_mutator.tx_hook
    for _ in range(5):
        drop_daemon.inject_mon(beacon)
    check("drop_probability=1.0 drops all", len(injected) == 10)  # unchanged


# ── Test 11: assoc request mutations ─────────────────────────────────────────

def test_assoc_req_mutations():
    print("\n[11] AssocReq frame mutations")
    cfg = MutationConfig(
        enabled_strategies=['ie_duplicate', 'ie_remove', 'ie_overflow'],
        mutations_per_frame=2,
    )
    mutator = FrameMutator(cfg)
    assoc = make_assoc_req()

    results = [mutator.tx_hook(assoc, 'mon') for _ in range(30)]
    valid = [r for r in results if r is not None]

    check("assoc: results not empty", len(valid) > 0)
    check("assoc: results are Dot11", all(r.haslayer(Dot11) for r in valid))
    check("assoc: mutated count > 0", mutator.stats['mutated'] > 0)


# ── Run all tests ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("Wi-Fi Fuzzer Phase 1+2 Unit Tests")
    print("=" * 60)

    test_ie_roundtrip()
    test_ie_roundtrip_with_radiotap()
    test_no_ie_offset()
    test_all_strategies()
    test_frame_mutator_basic()
    test_frame_mutator_passthrough()
    test_drop_probability()
    test_subtype_filter()
    test_single_strategy()
    test_rx_hook_disabled()
    test_daemon_hook_wiring()
    test_assoc_req_mutations()

    print()
    print("=" * 60)
    print(f"Results: {PASS} passed, {FAIL} failed")
    print("=" * 60)
    sys.exit(0 if FAIL == 0 else 1)
