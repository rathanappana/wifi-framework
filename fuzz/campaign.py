"""
FuzzCampaign: orchestrates post-authentication 802.11 fuzzing against a connected AP.

Requires an authenticated+connected Supplicant station from wifi-framework.
Run profile_from_beacon() first to build an APProfile, then pass to FuzzCampaign.run().
"""
from __future__ import annotations

import struct
import time
from typing import List, Optional

from dependencies.libwifi.wifi import log, STATUS, raw
from dependencies.libwifi.crypto import encrypt_ccmp
from scapy.layers.dot11 import (
    Dot11, Dot11QoS, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11Deauth,
    Dot11Disas, Dot11ProbeReq,
)
from scapy.all import RadioTap

from fuzz.mutator import (
    ByteStrategy, byte_mutate, all_byte_mutations, field_boundary_values, pack_le,
    ie_build, ie_wrong_length, ie_truncated, ie_zero_length,
    ie_max_length_claim, ie_extended_tag, ie_all_mutations,
    POST_AUTH_SEQUENCE_MUTATIONS,
)
from fuzz.ie_mutator import (
    mutations_rsn, mutations_ht, mutations_vht, mutations_he,
    mutations_rates, mutations_vendor,
    build_ht_cap, build_vht_cap, build_he_cap, build_rsn_wpa2_psk,
    malformed_ie_stack,
    OUI_BROADCOM, OUI_MICROSOFT, OUI_QUALCOMM,
)
from fuzz.monitor import CrashMonitor
from fuzz.profiler import APProfile
from fuzz.state_tracker import StateTracker, state_violation_frames
from fuzz.feedback import FeedbackEngine, Signal
from fuzz.response_sniffer import ResponseSniffer


# ── Frame builders ────────────────────────────────────────────────────────────

def _mgmt(station, subtype: int, body: bytes = b'', fc: int = 0):
    """Build a management frame (type=0) directed at the AP."""
    p = Dot11(type=0, subtype=subtype, FCfield=fc,
              addr1=station.bss, addr2=station.mac, addr3=station.bss)
    p = p / body
    return p


def _action(station, category: int, action: int, body: bytes = b''):
    """Build an Action frame (type=0, subtype=13)."""
    return _mgmt(station, 13, bytes([category, action]) + body)


def _qos_data(station, seq: int, tid: int = 0, fc: int = 1):
    """Build a QoS Data frame header (type=2, subtype=8), STA→AP."""
    p = Dot11(type=2, subtype=8, FCfield=fc,
              addr1=station.bss, addr2=station.mac, addr3=station.bss,
              SC=(seq & 4095) << 4)
    p = p / Dot11QoS(TID=tid & 15)
    return p


def _enc(station, frame):
    """Encrypt frame with CCMP using current session TK + auto-increment PN."""
    station.pn += 1
    return encrypt_ccmp(frame, station.tk, station.pn)


# ── Campaign ──────────────────────────────────────────────────────────────────

class FuzzCampaign:
    """
    Orchestrates all post-authentication 802.11 fuzzing against a connected AP.

    Phases run in order. Profile-specific phases (e.g., HE Cap mutations,
    Broadcom vendor frames) are automatically included based on APProfile.

    Args:
        station:        wifi-framework Supplicant instance (must be connected).
        profile:        APProfile from sniff_and_profile().
        check_interval: Alive checks every N injections (default 20).
        session_id:     Unique ID for log files (default: timestamp).
        inter_frame_s:  Delay between injections in seconds (default 0.04).
    """

    def __init__(self, station, profile: APProfile,
                 check_interval: int = 20, session_id: str = '',
                 inter_frame_s: float = 0.04):
        self.station       = station
        self.profile       = profile
        self.inter_frame_s = inter_frame_s
        self._seq          = 0
        self.mon           = None

        if not session_id:
            from datetime import datetime as _dt
            session_id = (_dt.now().strftime('%Y%m%d_%H%M%S') + '_'
                          + profile.bssid.replace(':', '')[:6])
        self.mon = CrashMonitor(station, session_id=session_id,
                                check_interval=check_interval)
        self.state_tracker = StateTracker()
        self.mon.state_tracker = self.state_tracker

        # Tier 1: behavioral feedback engine (scores mutation categories)
        # profile_id uses BSSID so scores persist per-AP across sessions
        profile_id = profile.bssid.replace(':', '')[:12]
        self.feedback = FeedbackEngine(profile_id=profile_id)
        self.feedback.load()  # load prior session scores if available

        # Tier 2: response sniffer (background thread, AP frame correlation)
        self.sniffer = ResponseSniffer(
            iface=station.nic_mon,
            ap_bssid=profile.bssid,
            our_mac=station.mac,
            feedback=self.feedback,
        )

    def run(self) -> None:
        """
        Run the complete post-authentication fuzzing campaign.

        Starts ResponseSniffer (Tier 2) before first phase.
        FeedbackEngine (Tier 1) scores each injection.
        Both report at campaign end.

        Phase order (from most impactful to broadest):
          1. Data plane (data subtypes, TID, FCfield, QoS)
          2. IE fuzzer (RSN, HT, VHT, HE, rates — in Assoc frames)
          3. Management plane (auth, deauth, probe)
          4. Action frames (Block Ack, SA Query, Spectrum, WNM)
          5. Vendor specific (profile-guided OUI selection)
          6. Category sweep (all 256 action categories)

        Each phase logs to the session JSONL file and saves crash frames.
        """
        log(STATUS, '[ap-fuzz] Profile: ' + str(self.profile), color='cyan')
        self.sniffer.start()
        log(STATUS, '[ap-fuzz] ResponseSniffer started on ' + self.station.nic_mon, color='cyan')

        hints = []
        if self.profile.ht_cap:  hints.append('ht_cap')
        if self.profile.vht_cap: hints.append('vht_cap')
        if self.profile.he_cap:  hints.append('he_cap')
        if self.profile.pmf_required: hints.append('pmf_sa_query')
        log(STATUS, '[ap-fuzz] Mutation hints: ' + str(hints))

        phases = [
            ('data-header',       self._phase_data_header),
            ('sc-reassembly',     self._phase_sc_reassembly),
            ('ie-fuzzing',        self._phase_ie_fuzzing),
            ('state-violations',  self._phase_state_violations),
            ('mgmt-plane',        self._phase_mgmt_plane),
            ('action-block-ack',  self._phase_action_block_ack),
            ('action-sa-query',   self._phase_action_sa_query),
            ('action-spectrum',   self._phase_action_spectrum),
            ('action-wnm',        self._phase_action_wnm),
            ('vendor-specific',   self._phase_vendor_specific),
            ('action-cat-sweep',  self._phase_action_cat_sweep),
        ]

        # Profile-guided additions
        if self.profile.ht_cap:
            phases.insert(3, ('ie-ht', self._phase_ie_ht))
        if self.profile.vht_cap:
            phases.insert(4, ('ie-vht', self._phase_ie_vht))
        if self.profile.he_cap:
            phases.insert(5, ('ie-he', self._phase_ie_he))
        if self.profile.pmf_required:
            phases.append(('pmf-sa-query-stress', self._phase_pmf_sa_stress))

        for phase_name, phase_fn in phases:
            log(STATUS, '[ap-fuzz] === Phase: ' + phase_name + ' ===', color='orange')
            self.mon.logger.log_phase(phase_name)
            crash_path, total, alive = phase_fn()
            if crash_path:
                log(STATUS, '[ap-fuzz] CRASH after ' + phase_name +
                    '. Saved=' + str(crash_path), color='red')
                # Try to reconnect and continue.
                # EAP-PEAP takes 4-6s → wait up to 15s for wpa_state=COMPLETED.
                # Do NOT use time.sleep(0.5) — that fires before auth completes.
                try:
                    self.station.wpaspy_command('REASSOCIATE')
                    reconnected = False
                    for _ in range(150):     # 150 × 0.1s = 15s max
                        time.sleep(0.1)
                        try:
                            st = self.station.wpaspy_command('STATUS')
                            if 'wpa_state=COMPLETED' in st:
                                reconnected = True
                                break
                        except Exception:
                            pass
                    if not reconnected:
                        log(STATUS, '[ap-fuzz] Reconnect failed (15s timeout). Stopping campaign.')
                        self.mon.logger.log_reconnect(phase_name, False)
                        break
                    # Drain wpaspy queue — clears interim DISCONNECTED events from
                    # the reconnect cycle so they don't get counted as new crashes.
                    self.mon.check_wpaspy_queue()
                    log(STATUS, '[ap-fuzz] Reconnected. Continuing.', color='green')
                    self.mon.logger.log_reconnect(phase_name, True)
                except Exception:
                    self.mon.logger.log_reconnect(phase_name, False)
                    break

        # Log state tracker summary
        st = self.state_tracker
        log(STATUS, '[ap-fuzz] State summary: ' + st.summary(), color='cyan')
        regressions = st.regression_transitions()
        if regressions:
            log(STATUS, f'[ap-fuzz] State regressions: {len(regressions)}', color='orange')
            for r in regressions:
                log(STATUS, f'  {r.from_state.name}→{r.to_state.name} '
                    f'phase={r.inject_phase} label={r.inject_label}', color='orange')
        self.mon.logger._write({'event': 'state_summary',
                                'transitions': st.to_dict_list(),
                                'ts': time.time()})

        self.mon.close()

        # Stop response sniffer + print summary
        self.sniffer.stop()
        log(STATUS, self.sniffer.summary(), color='cyan')

        # Print + save feedback scores
        log(STATUS, self.feedback.report(), color='cyan')
        fb_path = self.feedback.save()
        log(STATUS, '[ap-fuzz] Feedback saved: ' + fb_path, color='cyan')

        log(STATUS, '[ap-fuzz] Campaign complete. ' +
            str(self.mon.logger.total()) + ' events logged. AP alive=' +
            str(self.mon.is_alive()))
        log(STATUS, '[ap-fuzz] Log:  ' + self.mon.logger.path)
        if hasattr(self.mon, '_pcap') and self.mon._pcap is None:
            # pcap was open and just closed — reconstruct path for display
            pcap_path = self.mon.logger.path.replace('wifi_fuzz_log_', 'fuzz_').replace('.jsonl', '.pcap')
            log(STATUS, '[ap-fuzz] PCAP: ' + pcap_path + '  (open in Wireshark)')

    def _inj(self, frame, phase: str, label: str, encrypt: bool = False):
        """Encrypt (if requested) and inject frame through CrashMonitor + FeedbackEngine."""
        if encrypt and self.station.tk:
            frame = _enc(self.station, frame)
        frame_bytes = raw(frame)
        self.mon.record_inject(frame_bytes, phase, label)
        self.state_tracker.set_inject_context(phase, label, self.mon._inject_count)
        self.feedback.record_inject(phase, label)
        self.station.inject_mon(frame)
        time.sleep(self.inter_frame_s)

        # Proactive: drain wpaspy queue for DISCONNECTED events
        disconnected = self.mon.check_wpaspy_queue()

        ok = True
        crash_path = None
        if disconnected or self.mon.should_check():
            t0 = time.time()
            ok = self.mon.is_alive()
            latency_ms = (time.time() - t0) * 1000.0
            self.mon.log_alive_result(ok)
            if ok:
                self.feedback.record_alive(latency_ms)
            else:
                # Extract reason code from last wpaspy disconnect message
                reason_code = self._last_disconnect_reason()
                crash_path = self.mon.save_crash_window()  # saves all N frames in window
                self.feedback.record_signal(reason_code=reason_code,
                                             crash_saved=(crash_path is not None))
                log(STATUS, '[ap-fuzz] Disconnect in phase=' + phase +
                    ' label=' + label + ' saved=' + str(crash_path), color='red')
        return ok, crash_path

    def _last_disconnect_reason(self) -> int:
        """Extract reason code from StateTracker's last DISCONNECTED transition."""
        transitions = self.state_tracker.state_transitions()
        from fuzz.state_tracker import STAState
        for t in reversed(transitions):
            if t.to_state == STAState.DISCONNECTED and t.trigger_msg:
                # Parse: "CTRL-EVENT-DISCONNECTED bssid=... reason=N"
                for token in t.trigger_msg.split():
                    if token.startswith('reason='):
                        try:
                            return int(token[7:])
                        except ValueError:
                            pass
        return 0

    def _next_seq(self) -> int:
        seq = self._seq
        self._seq = (self._seq + 1) & 4095
        return seq

    # ── Phase 1: Data frame header mutations ──────────────────────────────────

    def _phase_data_header(self):
        """
        Systematically mutate every 802.11 data frame header field read by mac80211.

        IMPORTANT: Data frame BODY is irrelevant to mac80211.
        After CCMP decrypt, mac80211 passes plaintext up to network stack and is done.
        mac80211 only reads these header fields from data frames:

          subtype [3:0]    — dispatch table: null, CF-Poll, QoS variants (0-15)
          FCfield [7:0]    — 8 flag bits controlling processing path:
                             bit0=ToDS, bit1=FromDS, bit2=MoreFrags, bit3=Retry,
                             bit4=PwrMgmt, bit5=MoreData, bit6=Protected, bit7=Order
          QoS TID [3:0]    — indexes tid_rx[TID]: valid 0-7, reserved 8-15 (OOB)
          QoS EOSP [4]     — end-of-service-period (power save)
          QoS ACK [6:5]    — ACK policy: Normal(0), NoAck(1), NoExpl(2), BlockAck(3)
          QoS AMSDU [7]    — A-MSDU present: triggers different inner-frame parsing
          SC seqnum [15:4] — replay detection window (4096 values)
          SC fragnum [3:0] — reassembly buffer index (0-15)
          Duration [15:0]  — timer management

        We use a fixed minimal body (b"\\x00" * 4) — content does not matter.
        """
        phase = 'data-header'
        BODY  = b'\x00\x00\x00\x00'
        crash_path = None
        total = 0

        def data_hdr(subtype, fc, tid, qos_ctrl, seq, dur=0):
            """Build data frame with explicit header field values."""
            p = Dot11(type=2, subtype=subtype, FCfield=fc,
                      addr1=self.station.bss,
                      addr2=self.station.mac,
                      addr3=self.station.bss,
                      SC=(seq & 4095) << 4,
                      ID=dur & 65535)
            p = p / Dot11QoS(TID=tid & 15) / struct.pack('<H', qos_ctrl) / BODY
            return p

        # Subtype sweep (0–15)
        for sub in range(16):
            frame = data_hdr(sub, 1, 0, 0, self._next_seq())
            ok, cp = self._inj(frame, phase, f'subtype-{sub:#04x}', encrypt=True)
            total += 1
            if cp: crash_path = cp

        # FCfield mutations
        for fc, tid, encrypt, label in [
            (1, 0, True,  'tods-only-normal'),
            (3, 0, True,  'tods-fromds-wds'),
            (5, 0, True,  'tods-morefrag'),
            (9, 0, True,  'tods-retry'),
            (17, 0, True, 'tods-pwrmgmt'),
            (49, 0, True, 'tods-pm-moredata'),
            (129, 0, True, 'tods-order'),
            (65, 0, False, 'tods-protected-clear'),
            (1, 0, False,  'plaintext-no-protected'),
            (2, 0, True,  'fromds-only'),
            (255, 0, True, 'all-bits-set'),
            (254, 0, True, 'all-except-tods'),
            (0, 0, False,  'no-bits-set'),
        ]:
            frame = data_hdr(8, fc, tid, 0, self._next_seq())
            ok, cp = self._inj(frame, phase, f'fc-{label}', encrypt=encrypt)
            total += 1
            if cp: crash_path = cp

        # QoS TID sweep 0–15
        for tid in range(16):
            frame = data_hdr(8, 1, tid, 0, self._next_seq())
            ok, cp = self._inj(frame, phase, f'qos-tid-{tid}', encrypt=True)
            total += 1
            if cp: crash_path = cp

        # QoS control byte [1B]: full systematic coverage
        # field_boundary_values(1) = {0,1,85,127,128,170,254,255}
        # all_byte_mutations(1)    = zero/one/random/xor_aa/xor_55/boundary/bit_flip/incr/alt/const
        # QoS byte layout: TID[3:0] EOSP[4] ACK[6:5] AMSDU[7]
        for qos_ctrl in field_boundary_values(1):
            frame = data_hdr(8, 1, 0, qos_ctrl, self._next_seq())
            ok, cp = self._inj(frame, phase, f'qos-ctrl-bnd-{qos_ctrl:#04x}', encrypt=True)
            total += 1
            if cp: crash_path = cp
        for strategy, qos_bytes in all_byte_mutations(1):
            frame = data_hdr(8, 1, 0, qos_bytes[0], self._next_seq())
            ok, cp = self._inj(frame, phase, f'qos-ctrl-{strategy.value}', encrypt=True)
            total += 1
            if cp: crash_path = cp

        # FCfield byte [1B]: logical combos already done above
        # all_byte_mutations(1) adds ByteStrategy coverage beyond logical combos
        for strategy, fc_bytes in all_byte_mutations(1):
            fc_val = fc_bytes[0]
            enc = bool(fc_val & 0x40)
            frame = data_hdr(8, fc_val, 0, 0, self._next_seq())
            ok, cp = self._inj(frame, phase, f'fc-byte-{strategy.value}', encrypt=enc)
            total += 1
            if cp: crash_path = cp

        # A-MSDU: forged inner header + all ByteStrategy bodies
        inner_dst  = b'\xff\xff\xff\xff\xff\xff'
        inner_src  = b'\xde\xad\xbe\xef\x00\x01'
        inner_len  = struct.pack('>H', 0xDEAD)
        msdu_fixed = inner_dst + inner_src + inner_len
        for strategy, msdu_body in all_byte_mutations(16):
            frame = data_hdr(8, 1, 0, 0x80, self._next_seq())
            ok, cp = self._inj(frame / (msdu_fixed + msdu_body),
                               phase, f'qos-amsdu-{strategy.value}', encrypt=True)
            total += 1
            if cp: crash_path = cp

        # Duration field [2B]: full systematic coverage
        # field_boundary_values(2) = {0,1,85,...,65535}
        # all_byte_mutations(2)    = each ByteStrategy on 2-byte duration field
        for dur in field_boundary_values(2):
            frame = data_hdr(8, 1, 0, 0, self._next_seq(), dur)
            ok, cp = self._inj(frame, phase, f'duration-bnd-{dur:#06x}', encrypt=True)
            total += 1
            if cp: crash_path = cp
        for strategy, dur_bytes in all_byte_mutations(2):
            dur_val = struct.unpack('<H', dur_bytes)[0]
            frame = data_hdr(8, 1, 0, 0, self._next_seq(), dur_val)
            ok, cp = self._inj(frame, phase, f'duration-{strategy.value}', encrypt=True)
            total += 1
            if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    # ── Phase 2: Sequence Control reassembly ─────────────────────────────────

    def _phase_sc_reassembly(self):
        """
        Systematic Sequence Control (SC) field mutations targeting mac80211 reassembly.

        SC = [seqnum: 12 bits][fragnum: 4 bits]

        mac80211 reassembly path (ieee80211_rx_h_defragment):
          - Allocates per-STA fragment cache indexed by (seqnum, fragnum)
          - Expects: FN=0 arrives first, FN=1,2,...,N follow, MoreFrags=0 on last
          - Bugs triggered by:
            * FN > 0 without FN=0 (orphaned) → buffer never freed
            * Same (seqnum, FN=0) twice with different payload → cache confusion
            * MoreFrags=1 on last fragment → buffer held forever
            * seqnum gap > reorder window → old buffers evicted → potential UAF
            * FN=15 (max) → off-by-one in frag array

        All frames encrypted — AP must process (Protected frame from authenticated STA).
        Body content is irrelevant; SC field values drive the vulnerability.
        """
        phase = 'sc-reassembly'
        BODY  = b'\xcc' * 16
        crash_path = None
        total = 0

        def qos_sc(seq, fn, more_frags=False):
            """Build QoS Data frame with explicit SC seqnum + fragnum."""
            fc = 1 | (4 if more_frags else 0)
            hdr = Dot11(type=2, subtype=8, FCfield=fc,
                        addr1=self.station.bss,
                        addr2=self.station.mac,
                        addr3=self.station.bss,
                        SC=((seq & 4095) << 4) | (fn & 15))
            hdr = hdr / Dot11QoS(TID=0) / BODY
            return hdr

        # Orphaned fragments (FN > 0 without FN=0)
        for fn in (1, 3, 7, 14, 15):
            seq = self._next_seq()
            frame = qos_sc(seq, fn)
            ok, cp = self._inj(frame, phase, f'fn-{fn}-fixed-seq', encrypt=True)
            total += 1
            if cp: crash_path = cp

        # Orphaned frag burst (256 different seqnums, FN=1)
        for _ in range(256):
            frame = qos_sc(self._next_seq(), 1)
            ok, cp = self._inj(frame, phase, 'orphan-s' + format(self._seq, '03x') + '-fn', encrypt=True)
            total += 1
            if cp: crash_path = cp

        # MoreFrags=1 held forever (3 seqnums)
        for seq in (1024, 1025, 1026):
            frame = qos_sc(seq, 0, more_frags=True)
            ok, cp = self._inj(frame, phase, 'morefrag-held-fn', encrypt=True)
            total += 1
            if cp: crash_path = cp

        # Duplicate FN=0 with different payloads
        seq = self._next_seq()
        frame0a = qos_sc(seq, 0)
        frame0b = Dot11(raw(frame0a))
        ok, cp = self._inj(frame0a, phase, f'dup-fn0-first-s{seq:03x}', encrypt=True)
        total += 1
        if cp: crash_path = cp
        ok, cp = self._inj(frame0b, phase, f'dup-fn0-second-s{seq:03x}', encrypt=True)
        total += 1
        if cp: crash_path = cp

        # Max fragnum (15)
        for fn in (0, 1, 7, 15):
            frame = qos_sc(self._next_seq(), fn)
            ok, cp = self._inj(frame, phase, f'seq-{self._seq:#05x}-fn{fn}', encrypt=True)
            total += 1
            if cp: crash_path = cp

        # Replay same SC 5×
        seq = self._next_seq()
        for _ in range(5):
            frame = qos_sc(seq, 0)
            ok, cp = self._inj(frame, phase, 'replay-same-sc-x5', encrypt=True)
            total += 1
            time.sleep(0.05)
            if cp: crash_path = cp

        log(STATUS, '[ap-fuzz] Waiting 3s for reassembly eviction timer...', color='orange')
        time.sleep(3)

        return crash_path, total, self.mon.is_alive()

    # ── Phase 3: IE fuzzing via Assoc/Reassoc frames ─────────────────────────

    def _phase_ie_fuzzing(self):
        """
        Fuzz IE parsers by sending Assoc/Reassoc Requests with malformed IEs.

        The AP/mac80211 must parse Assoc Requests even from already-associated STAs
        (triggers "reassociation" or "unexpected assoc" handling path).

        Mutations applied to RSN IE (all variants), Vendor IEs, and a
        malformed-IE stack. HT/VHT/HE are in separate phases if profile says present.
        """
        phase = 'ie-fuzzing'
        rates_ie = ie_build(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        cap_info  = struct.pack('<HH', 1073, 10)  # capability + listen_interval
        crash_path = None
        total = 0

        # AKM auto-select from profile
        akms_map = {
            b'\x00\x0f\xac\x01': b'\x00\x0f\xac\x01',  # 8021X
            b'\x00\x0f\xac\x08': b'\x00\x0f\xac\x08',  # SAE
        }
        base_akms = [akms_map.get(a, b'\x00\x0f\xac\x02') for a in self.profile.rsn_akms[:1]] \
                    or [b'\x00\x0f\xac\x02']

        # RSN mutations
        for label, rsn_ie in mutations_rsn(base_akms=base_akms):
            for is_reassoc in (False, True):
                subtype = 2 if is_reassoc else 0
                kind    = 'reassoc' if is_reassoc else 'assoc'
                ies = rates_ie + rsn_ie
                fixed = cap_info + (b'\x00' * 10 if is_reassoc else b'')
                frame = _mgmt(self.station, subtype, fixed + ies)
                ok, cp = self._inj(frame, phase, f'rsn-{kind}-{label}')
                total += 1
                if cp: crash_path = cp

        # Rates IE mutations
        for label, rates_ie_mut in mutations_rates():
            ies = rates_ie_mut + build_rsn_wpa2_psk()
            frame = _mgmt(self.station, 0, cap_info + ies)
            ok, cp = self._inj(frame, phase, f'rates-assoc-{label}')
            total += 1
            if cp: crash_path = cp

        # Malformed IE stacks
        include_broadcom = OUI_BROADCOM in self.profile.vendor_ouis
        include_he       = self.profile.he_cap
        for is_reassoc in (False, True):
            blob   = malformed_ie_stack(include_broadcom=include_broadcom, include_he=include_he)
            kind   = 'reassoc' if is_reassoc else 'assoc'
            fixed  = cap_info + (b'\x00' * 10 if is_reassoc else b'')
            frame  = _mgmt(self.station, 2 if is_reassoc else 0, fixed + blob)
            ok, cp = self._inj(frame, phase, f'malformed-ie-stack-{kind}')
            total += 1
            if cp: crash_path = cp

        # Capability field bit sweep
        for bit in range(16):
            caps = struct.pack('<H', 1 << bit)
            ies  = rates_ie + build_rsn_wpa2_psk()
            frame = _mgmt(self.station, 0, caps + struct.pack('<H', 10) + ies)
            ok, cp = self._inj(frame, phase, f'cap-bit{bit}')
            total += 1
            if cp: crash_path = cp

        caps = struct.pack('<HH', 65535, 10)
        ies  = rates_ie + build_rsn_wpa2_psk()
        frame = _mgmt(self.station, 0, bytes(caps) + ies)
        ok, cp = self._inj(frame, phase, 'cap-all-ones')
        total += 1
        if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    def _phase_ie_ht(self):
        """HT Capabilities IE mutations (only if AP has HT — from profile)."""
        phase = 'ie-ht'
        rates = ie_build(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        fixed = struct.pack('<HH', 1073, 10)
        crash_path = None
        total = 0
        for label, ht_ie in mutations_ht():
            ies   = rates + build_rsn_wpa2_psk() + ht_ie
            frame = _mgmt(self.station, 0, fixed + ies)
            ok, cp = self._inj(frame, phase, label)
            total += 1
            if cp: crash_path = cp
        return crash_path, total, self.mon.is_alive()

    def _phase_ie_vht(self):
        """VHT Capabilities IE mutations (only if AP has VHT — from profile)."""
        phase = 'ie-vht'
        rates = ie_build(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        fixed = struct.pack('<HH', 1073, 10)
        crash_path = None
        total = 0
        for label, vht_ie in mutations_vht():
            ies   = rates + build_rsn_wpa2_psk() + vht_ie
            frame = _mgmt(self.station, 0, fixed + ies)
            ok, cp = self._inj(frame, phase, label)
            total += 1
            if cp: crash_path = cp
        return crash_path, total, self.mon.is_alive()

    def _phase_ie_he(self):
        """HE Capabilities IE mutations (only if AP has HE — from profile)."""
        phase = 'ie-he'
        rates = ie_build(1, b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        fixed = struct.pack('<HH', 1073, 10)
        crash_path = None
        total = 0
        for label, he_ie in mutations_he():
            ies   = rates + build_rsn_wpa2_psk() + he_ie
            frame = _mgmt(self.station, 0, fixed + ies)
            ok, cp = self._inj(frame, phase, label)
            total += 1
            if cp: crash_path = cp
        return crash_path, total, self.mon.is_alive()

    # ── Phase 4: Management plane ─────────────────────────────────────────────

    def _phase_mgmt_plane(self):
        """
        Fuzz management frame parsers: auth, deauth, disassoc, probe.

        Sending management frames while already connected forces the AP into
        "unexpected management from known STA" handling paths.
        """
        phase = 'mgmt-plane'
        crash_path = None
        total = 0

        # Auth frame mutations
        for algo in field_boundary_values(2):
            for seq in field_boundary_values(2):
                body = struct.pack('<HHH', algo, seq, 0)
                frame = _mgmt(self.station, 11, body)
                ok, cp = self._inj(frame, phase, f'auth-algo-0x{algo:04x}')
                total += 1
                if cp: crash_path = cp

        # SAE commit-style auth (algo=3, seq=1)
        for body_strat in (ByteStrategy.random, ByteStrategy.boundary, ByteStrategy.xor_aa):
            for body_len in (1, 4, 16, 100):
                sae_fixed = struct.pack('<HHH', 3, 1, 0)
                body = sae_fixed + byte_mutate(body_len, body_strat)
                frame = _mgmt(self.station, 11, body)
                ok, cp = self._inj(frame, phase, f'sae-body-{body_strat.value}')
                total += 1
                if cp: crash_path = cp

        # Deauth with every reason code + trailing garbage
        for code in field_boundary_values(2):
            frame = _mgmt(self.station, 12, struct.pack('<H', code))
            ok, cp = self._inj(frame, phase, f'deauth-reason-{code}')
            total += 1
            if cp: crash_path = cp

        for extra_len in (1, 3, 65535):
            extra = b'A' * min(extra_len, 100)
            frame = _mgmt(self.station, 12, struct.pack('<H', 1) + extra)
            ok, cp = self._inj(frame, phase, f'deauth-trail-{extra_len}b')
            total += 1
            if cp: crash_path = cp

        # Disassoc reason sweep
        for code in field_boundary_values(2):
            frame = _mgmt(self.station, 10, struct.pack('<H', code))
            ok, cp = self._inj(frame, phase, f'disassoc-reason-{code}')
            total += 1
            if cp: crash_path = cp

        # Broadcast deauth (from our MAC to ff:ff:ff:ff:ff:ff)
        for code in field_boundary_values(2):
            p = Dot11(type=0, subtype=12, FCfield=0,
                      addr1='ff:ff:ff:ff:ff:ff',
                      addr2=self.station.mac,
                      addr3=self.station.bss)
            p = p / struct.pack('<H', code)
            ok, cp = self._inj(p, phase, f'bcast-deauth-{code}')
            total += 1
            if cp: crash_path = cp

        # Probe Request mutations
        for body_strat in (ByteStrategy.random, ByteStrategy.boundary):
            body = byte_mutate(16, body_strat)
            ies = ie_build(0, b'A' * 33) + ie_build(1, b'\x82\x84\x8b\x96')
            frame = _mgmt(self.station, 4, ies)
            ok, cp = self._inj(frame, phase, f'probe-body-{body_strat.value}')
            total += 1
            if cp: crash_path = cp

        # SSID IE edge cases in probe
        yield_map = [
            ('ssid-33-claim',  ie_wrong_length(0, b'A' * 32, 33)),
            ('ssid-255-claim', ie_wrong_length(0, b'A' * 32, 255)),
            ('no-ssid',        ie_zero_length(0)),
            ('dup-ssid',       ie_build(0, b'dup') + ie_build(0, b'dup')),
        ]
        for label, ssid_ie in yield_map:
            ies = ssid_ie + ie_build(1, b'\x82\x84\x8b\x96')
            frame = _mgmt(self.station, 4, ies)
            ok, cp = self._inj(frame, phase, f'probe-{label}')
            total += 1
            if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    # ── Phase 5: Block Ack action frames ──────────────────────────────────────

    def _phase_action_block_ack(self):
        """
        Block Ack action frame mutations (Category 3).

        Targets mac80211 ieee80211_process_addba_request():
          ADDBA buf_size > 64 → reorder_buf[] allocation may be wrong size.
          Frames at seqnum = start + buf_size → potential OOB write.
        """
        phase = 'action-block-ack'
        crash_path = None
        total = 0

        def addba_req(buf_size, tid=0, token=1, timeout=0, start_seq=0):
            ba_params = (1) | ((tid & 15) << 2) | ((buf_size & 1023) << 6)
            body = struct.pack('<BHHH', token, ba_params, timeout,
                               (start_seq & 4095) << 4)
            return body

        def delba(tid=0, initiator=1, reason=0):
            params = (initiator & 1) | ((tid & 15) << 12)
            body   = struct.pack('<BHH', 0, params, reason)
            return body

        # ADDBA buf_size boundary sweep
        for buf_size, tid, label in [
            (0,    0, 'bufsz-0'),
            (1,    0, 'bufsz-1'),
            (64,   0, 'bufsz-64-spec-max'),
            (65,   0, 'bufsz-65-off-by-one'),
            (255,  0, 'bufsz-255-8bit-max'),
            (256,  0, 'bufsz-256-he-min'),
            (512,  0, 'bufsz-512'),
            (1023, 0, 'bufsz-1023-10bit-max'),
            (255,  7, 'bufsz-255-tid7'),
            (255, 15, 'bufsz-255-tid15-reserved'),
        ]:
            body  = addba_req(buf_size, tid)
            frame = _action(self.station, 3, 0, body)  # Cat=3 (BA), Act=0 (ADDBA Req)
            ok, cp = self._inj(frame, phase, f'addba-{label}')
            total += 1
            if cp: crash_path = cp

            # OOB write probe: send frames at seqnum = start + buf_size
            if buf_size > 0:
                time.sleep(0.2)
                for off in range(min(3, buf_size)):
                    seq   = (off + buf_size) & 4095
                    data  = _qos_data(self.station, seq, tid=tid, fc=1)
                    data /= b'\xba\xad\xba\xad' * 4
                    ok, cp = self._inj(data, phase, f'addba-oob-probe-{label}-off{off}', encrypt=True)
                    total += 1
                    if cp: crash_path = cp

        # ADDBA buf_size ByteStrategy sweep (all_byte_mutations covers ByteStrategy on 2-byte field)
        for strategy, buf_bytes in all_byte_mutations(2):
            buf_size = struct.unpack('<H', buf_bytes)[0] & 0x3FF  # 10-bit field
            body = addba_req(buf_size)
            frame = _action(self.station, 3, 0, body)
            ok, cp = self._inj(frame, phase, f'addba-bufsz-{strategy.value}')
            total += 1
            if cp: crash_path = cp

        # DELBA for various TIDs
        for tid in field_boundary_values(1)[:8]:
            for reason in field_boundary_values(2):
                body  = delba(tid=tid, reason=reason)
                frame = _action(self.station, 3, 2, body)  # Act=2 (DELBA)
                ok, cp = self._inj(frame, phase, f'delba-tid{tid}-reason{reason}')
                time.sleep(0.1)
                total += 1
                if cp: crash_path = cp

        # Unknown BA action codes
        for act in field_boundary_values(1):
            frame = _action(self.station, 3, act, b'\x00' * 4)
            ok, cp = self._inj(frame, phase, f'ba-unknown-act-{act:#04x}')
            total += 1
            if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    # ── Phase 6: SA Query ─────────────────────────────────────────────────────

    def _phase_action_sa_query(self):
        """
        SA Query protocol mutation (Category 8).

        Targets mac80211 PMF: ieee80211_process_sa_query_req/resp().
        Protocol violations: response before request, trans_id sweep,
        rapid flood, wrong body lengths.
        """
        phase = 'action-sa-query'
        crash_path = None
        total = 0

        # Unsolicited SA Query Response (we send response without AP sending request)
        for tid in field_boundary_values(2):
            body  = struct.pack('<H', tid)
            frame = _action(self.station, 8, 1, body)  # Cat=8 (SA Query), Act=1 (Resp)
            ok, cp = self._inj(frame, phase, f'sa-resp-unsolicited-{tid:#06x}')
            total += 1
            if cp: crash_path = cp

        # SA Query Request trans_id sweep
        for tid in field_boundary_values(2):
            body  = struct.pack('<H', tid)
            frame = _action(self.station, 8, 0, body)  # Act=0 (Request)
            ok, cp = self._inj(frame, phase, f'sa-req-{tid:#06x}')
            total += 1
            if cp: crash_path = cp

        # Rapid SA flood (32 rapid requests)
        for i in range(32):
            body  = struct.pack('<H', i)
            frame = _action(self.station, 8, 0, body)
            ok, cp = self._inj(frame, phase, f'sa-flood-{i}')
            total += 1
            if cp: crash_path = cp

        # Body length mutations
        for body, label in [
            (b'', 'empty'), (b'\x12', '1-byte'), (b'\xab\xcd\xef', '3-bytes'),
            (b'\xff' * 50, '50-bytes'),
        ]:
            for act in (0, 1):
                frame = _action(self.station, 8, act, body)
                ok, cp = self._inj(frame, phase, f'sa-body-{label}')
                total += 1
                if cp: crash_path = cp

        # Unknown SA action codes
        for act in field_boundary_values(1):
            frame = _action(self.station, 8, act, b'\x00\x00')
            ok, cp = self._inj(frame, phase, f'sa-unknown-act-{act:#04x}')
            total += 1
            if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    # ── Phase 7: Spectrum Management ─────────────────────────────────────────

    def _phase_action_spectrum(self):
        """
        Spectrum Management action frame mutations (Category 0).

        Targets mac80211 ieee80211_process_measurement_req()
        and ieee80211_process_chanswitch().
        """
        phase = 'action-spectrum'
        crash_path = None
        total = 0

        def meas_req(token, meas_type, channel, duration, mode=0):
            ie_body = bytes([token, mode, meas_type, channel]) + struct.pack('<H', duration) + b'\x00' * 8
            ie = ie_build(38, ie_body)  # Measurement Request IE
            return ie

        # Measurement type sweep
        for meas_type in field_boundary_values(1):
            for ch in (0,):
                for dur in field_boundary_values(2)[:4]:
                    ie   = meas_req(1, meas_type, ch, dur)
                    frame = _action(self.station, 0, 0, ie)  # Cat=0, Act=0 (Measurement Req)
                    ok, cp = self._inj(frame, phase, f'meas-type-{meas_type:#04x}')
                    total += 1
                    if cp: crash_path = cp

        # Channel switch announcements
        for new_ch in field_boundary_values(1):
            for count in field_boundary_values(1):
                csa_body  = bytes([1, new_ch, count])  # mode, new_ch, count
                csa_ie    = ie_build(37, csa_body)  # CSA IE tag=37
                frame = _action(self.station, 0, 4, csa_ie)  # Act=4 (Chan Switch)
                ok, cp = self._inj(frame, phase, f'csa-ch{new_ch:#04x}-cnt{count:#04x}')
                total += 1
                if cp: crash_path = cp

        # Unknown spectrum actions
        for act in field_boundary_values(1):
            frame = _action(self.station, 0, act, b'\x00' * 4)
            ok, cp = self._inj(frame, phase, f'spectrum-unknown-act-{act:#04x}')
            total += 1
            if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    # ── Phase 8: WNM ──────────────────────────────────────────────────────────

    def _phase_action_wnm(self):
        """
        WNM action frame mutations (Category 10).

        Targets mac80211/hostapd WNM processing:
          BSS Transition Request with many neighbor entries → alloc stress.
          WNM Sleep Request with interval=0 or 65535.
        """
        phase = 'action-wnm'
        crash_path = None
        total = 0

        def neighbor_ie(bssid):
            body = (bytes.fromhex(bssid.replace(':', '')) +
                    b'\x00\x00\x00\x00' + b'\x00\x00\x06\x04' + b'\x00\x00\x00\x00\x00\x00')
            return ie_build(52, body)

        def bss_trans_req(token, req_mode, disassoc_timer, validity, neighbors_ies):
            return bytes([token, req_mode]) + struct.pack('<H', disassoc_timer) + \
                   bytes([validity]) + neighbors_ies

        # BSS Transition Request with varying neighbor counts
        bssid = self.station.bss or 'aa:bb:cc:dd:ee:ff'
        for count in field_boundary_values(1):
            nr_ie  = neighbor_ie(bssid) * min(count, 50)  # cap at 50
            body   = bss_trans_req(1, 1, 0, 10, nr_ie)
            frame  = _action(self.station, 10, 7, body)  # Cat=10 (WNM), Act=7 (BSS Trans Req)
            ok, cp = self._inj(frame, phase, f'wnm-bss-trans-{count}-neighbors')
            total += 1
            if cp: crash_path = cp

        # WNM BSS Trans with malformed neighbor IE
        for label, wnm_ie in [
            ('zero-len',    bytes([52, 0])),
            ('claim-255',   ie_wrong_length(52, b'\xcc' * 13, 255)),
            ('truncated-6', ie_truncated(52, b'\xcc' * 13, 6)),
            ('all-ones',    ie_build(52, b'\xff' * 13)),
        ]:
            body  = bss_trans_req(1, 1, 0, 10, wnm_ie)
            frame = _action(self.station, 10, 7, body)
            ok, cp = self._inj(frame, phase, f'wnm-bad-nr-{label}')
            total += 1
            if cp: crash_path = cp

        # WNM Sleep Request
        for interval in field_boundary_values(2):
            body  = bytes([1]) + struct.pack('<H', interval)  # action_type=1, interval
            frame = _action(self.station, 10, 16, body)  # Act=16 (WNM Sleep)
            ok, cp = self._inj(frame, phase, f'wnm-sleep-{interval:#06x}')
            total += 1
            if cp: crash_path = cp

        # WNM BSS Transition Query (reason codes)
        for reason in field_boundary_values(1):
            frame = _action(self.station, 10, 6, bytes([1, reason]))  # Act=6 (Trans Query)
            ok, cp = self._inj(frame, phase, f'wnm-trans-query-reason-{reason:#04x}')
            total += 1
            if cp: crash_path = cp

        # Unknown WNM action codes
        for act in field_boundary_values(1):
            frame = _action(self.station, 10, act, b'\x00' * 4)
            ok, cp = self._inj(frame, phase, f'wnm-unknown-act-{act:#04x}')
            total += 1
            if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    # ── Phase 9: Vendor Specific action frames ────────────────────────────────

    def _phase_vendor_specific(self):
        """
        Vendor Specific action frame mutations (Category 127 / 126).

        OUI selection driven by APProfile:
          - Always: Broadcom (brcmfmac target), Microsoft, Qualcomm
          - Extra: unknown/random OUIs (test unknown-vendor dispatch path)

        Also targets Category 126 (Protected Vendor Specific)
        to test PMF vendor frame handling.
        """
        phase = 'vendor-specific'
        crash_path = None
        total = 0

        ouis = [OUI_BROADCOM, OUI_MICROSOFT, OUI_QUALCOMM]
        oui_names = {OUI_BROADCOM: 'brcm', OUI_MICROSOFT: 'msft', OUI_QUALCOMM: 'qcom'}

        for oui, name in zip(ouis, [oui_names[o] for o in ouis]):
            for subtype in field_boundary_values(1):
                for body_len in field_boundary_values(1):
                    body     = b'' if body_len == 0 else b'\x01' * min(body_len, 100)
                    payload  = oui + bytes([subtype]) + body
                    hdr      = bytes([127, 0]) + payload  # Cat=127, Act=0
                    frame    = _mgmt(self.station, 13, hdr)
                    ok, cp   = self._inj(frame, phase, f'vendor-{name}-sub{subtype:#04x}-bodylen{body_len:#04x}')
                    total   += 1
                    if cp: crash_path = cp

        # Protected Vendor Specific (Cat=126)
        for subtype in field_boundary_values(1):
            payload = OUI_BROADCOM + bytes([subtype]) + b'\xde\xad\xbe\xef'
            hdr     = bytes([126, 0]) + payload
            frame   = _mgmt(self.station, 13, hdr, fc=0x40)  # Protected
            ok, cp  = self._inj(frame, phase, f'vendor-protected-brcm-sub{subtype:#04x}')
            total  += 1
            if cp: crash_path = cp

        # Truncated vendor IE bodies
        for body, label in [(b'', 'no-body'), (b'\x00', '1-byte'),
                             (b'\x00\x90', 'partial-oui'), (b'\x00\x90\x4c', 'oui-only')]:
            hdr   = bytes([127, 0]) + body
            frame = _mgmt(self.station, 13, hdr)
            ok, cp = self._inj(frame, phase, f'vendor-truncated-{label}')
            total += 1
            if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    # ── Phase 10: Action category sweep ───────────────────────────────────────

    def _phase_action_cat_sweep(self):
        """
        Action frame category sweep: all 256 category × all 256 action values.

        KEY INSIGHT on body content:
          - For KNOWN categories (0-28): mac80211 parses body as protocol fields.
            We use minimal structured body (dialog_token=1 + zeros) because
            category+action dispatch is what matters, not body bytes.
          - For UNKNOWN/RESERVED categories (29-125): mac80211 drops frame at
            dispatcher without reading body. Body is IRRELEVANT for these.
            We still send them because the dispatcher itself may have bugs
            (null pointer, unhandled switch case).
          - Category 126/127 (vendor): handled separately in vendor phase.

        Total: 256 cats × 256 acts = 65536 frames.
        Reduced: 256 cats × 4 selected acts = 1024 frames (acts 0,1,2,255).
        act=0   → typically "request" action in most categories
        act=1   → typically "response" — unexpected direction (STA sends response)
        act=2   → typically "report" or third action
        act=255 → guaranteed unknown action in every category
        """
        phase = 'action-cat-sweep'
        BODY  = struct.pack('<BHH', 1, 0, 0)  # dialog_token=1, status=0, reserved=0
        crash_path = None
        total = 0

        log(STATUS, '[ap-fuzz] Category sweep: 256 cats × 4 acts = 1024 frames', color='orange')

        for cat in range(256):
            for act in (0, 1, 2, 255):
                frame  = _action(self.station, cat, act, BODY)
                label  = f'cat{cat:03d}-act{act:02x}'
                ok, cp = self._inj(frame, phase, label)
                total += 1
                if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()

    # ── Phase N: State violation injections ──────────────────────────────────

    def _phase_state_violations(self):
        """
        Inject out-of-state frames while fully CONNECTED.

        Tests AP state machine robustness:
          - Auth while connected:     AP should ignore or deauth (state machine reset)
          - Unprotected Data:         AP must send deauth reason=7 (Protected violation)
          - Null/Power-save tricks:   driver power-save state confusion
          - Duplicate AssocReq:       triggers unexpected reassoc handler path

        State regressions caused by these frames are logged with exact causal
        frame via StateTracker. A forced disconnect = AP reacted to state violation.

        Wait 1s between frames — AP state machines often have debounce timers.
        """
        phase = 'state-violations'
        crash_path = None
        total = 0

        log(STATUS, '[ap-fuzz] Injecting state-violation frames (connected state)', color='orange')
        log(STATUS, '[ap-fuzz] State before: ' + self.state_tracker.summary())

        frames = state_violation_frames(self.station)
        for label, frame in frames:
            ok, cp = self._inj(frame, phase, label, encrypt=False)
            total += 1
            if cp:
                crash_path = cp
            time.sleep(1.0)  # extra delay — state machine debounce

        # Encrypted variants of critical frames
        for fc, label in [
            (0x40, 'data-protected-no-tods-enc'),   # Protected bit but wrong direction
            (0x41, 'data-protected-tods-enc'),       # Normal protected data
        ]:
            from scapy.layers.dot11 import Dot11, Dot11QoS
            p = Dot11(type=2, subtype=8, FCfield=fc,
                      addr1=self.station.bss, addr2=self.station.mac,
                      addr3=self.station.bss, SC=self._next_seq() << 4)
            p = p / Dot11QoS(TID=0) / (b'\x00' * 16)
            ok, cp = self._inj(p, phase, label, encrypt=True)
            total += 1
            if cp:
                crash_path = cp
            time.sleep(0.5)

        log(STATUS, '[ap-fuzz] State after: ' + self.state_tracker.summary())
        regressions = self.state_tracker.disconnects_caused_by_phase(phase)
        if regressions:
            log(STATUS, f'[ap-fuzz] State violations triggered {len(regressions)} disconnects!',
                color='red')
            for r in regressions:
                log(STATUS, f'  FRAME: {r.inject_label} → {r.to_state.name}', color='red')

        return crash_path, total, self.mon.is_alive()

    # ── Phase 11: PMF SA Query stress (WPA3/PMF-required only) ───────────────

    def _phase_pmf_sa_stress(self):
        """
        PMF SA Query stress: 128 rapid requests + all boundary trans_ids.

        Only run if profile.pmf_required is True (WPA3 or PMF-mandatory AP).
        Targets ieee80211_process_sa_query_req() queue management.
        """
        phase = 'pmf-sa-stress'
        log(STATUS, '[ap-fuzz] PMF SA Query stress (PMF-required AP)', color='orange')
        crash_path = None
        total = 0

        for i in range(128):
            body  = struct.pack('<H', i)
            frame = _action(self.station, 8, 0, body)
            ok, cp = self._inj(frame, phase, f'pmf-sa-req-{i}')
            total += 1
            time.sleep(0.01)
            if cp: crash_path = cp

        # Boundary trans_ids
        for tid in field_boundary_values(2):
            body  = struct.pack('<H', tid & 65535)
            frame = _action(self.station, 8, 0, body)
            ok, cp = self._inj(frame, phase, f'pmf-sa-req-{tid}')
            total += 1
            if cp: crash_path = cp

        return crash_path, total, self.mon.is_alive()
