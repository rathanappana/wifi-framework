"""
Full automated fuzzing campaign against a connected AP.

Profiles AP from beacon, then runs all FuzzCampaign phases in order:
  data-header → sc-reassembly → ie-fuzzing → ie-ht/vht/he (if present)
  → mgmt-plane → action-block-ack → action-sa-query → action-spectrum
  → action-wnm → vendor-specific → action-cat-sweep
  → pmf-sa-stress (if PMF-required AP)

Profile is sniffed from beacons on nic_mon. Falls back to a
conservative default profile (HT+VHT, WPA2, no PMF) on timeout.

Run:
  sudo python3 run.py wlan0 ap-fuzz-campaign --config ~/iith/iith_wpa.conf

Optional: override profile source with env vars:
  AP_BSSID=ee:55:a8:06:7f:dd  sudo python3 run.py wlan0 ap-fuzz-campaign ...
"""
import os
import time

from dependencies.libwifi.wifi import log, STATUS
from library.testcase import Trigger, Action, Test
from fuzz.profiler import sniff_and_profile, APProfile, SecurityType
from fuzz.campaign import FuzzCampaign


# Default profile for IITH eduroam (Cisco Meraki MR46):
#   WPA2-Enterprise/PEAP, 802.11ac (HT+VHT), no HE, PMF capable.
#   Used when beacon sniff times out (AP on different channel, etc.)
def _default_iith_profile(bssid: str) -> APProfile:
    return APProfile(
        ssid='eduroam',
        bssid=bssid,
        channel=6,
        security=SecurityType.WPA2,
        ht_cap=True,
        vht_cap=True,
        he_cap=False,
        pmf_capable=True,
        pmf_required=False,
    )


class ApFuzzCampaign(Test):
    """
    Run FuzzCampaign against the connected AP.

    Connect → profile beacon → run all 10-13 phases → log results.
    Crash frames saved to /tmp/wifi_fuzz_crash_*.bin.
    Full event log saved to /tmp/fuzz_<session>.jsonl.
    """
    name = 'ap-fuzz-campaign'
    kind = Test.Supplicant

    def __init__(self):
        super().__init__([
            Action(trigger=Trigger.Connected,     action=Action.Function),
            Action(trigger=Trigger.Disconnected,  action=Action.Terminate),
        ])

    def run(self, station):
        log(STATUS, '[ap-fuzz-campaign] Connected. Profiling AP beacon...', color='cyan')

        # Sniff beacons on monitor interface to build AP capability profile.
        # nic_mon is the auto-created monitor interface ("mon" + nic_iface[:12]).
        profile = None
        target_bssid = os.environ.get('AP_BSSID') or station.bss
        try:
            profile = sniff_and_profile(
                iface=station.nic_mon,
                target_bssid=target_bssid,
                timeout=8,
            )
        except Exception as ex:
            log(STATUS, f'[ap-fuzz-campaign] Sniff error: {ex}', color='orange')

        if profile is None:
            profile = _default_iith_profile(station.bss or target_bssid or '')
            log(STATUS, '[ap-fuzz-campaign] Beacon timeout — using default IITH profile.', color='orange')
        else:
            log(STATUS, f'[ap-fuzz-campaign] Profile: {profile}', color='green')

        # Build and execute campaign
        campaign = FuzzCampaign(
            station=station,
            profile=profile,
            check_interval=20,
            inter_frame_s=0.04,
        )
        campaign.run()

    def generate(self, station):
        self.actions[0].set_function(self.run)
        # Terminate 5 seconds after campaign finishes (gives time for last alive check)
        self.actions[0].set_terminate(delay=5)
