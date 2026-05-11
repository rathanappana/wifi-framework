#!/usr/bin/env python3
"""
Crash frame parser — decode .bin files saved by the fuzzer.

Usage:
  python3 parse_crash.py /tmp/wifi_fuzz_crash_*.bin
  python3 parse_crash.py           # prompts for filename
  python3 parse_crash.py file1.bin file2.bin ...
"""
import sys
import struct
import os

try:
    from scapy.layers.dot11 import (
        Dot11, Dot11Beacon, Dot11AssoReq, Dot11ReassoReq,
        Dot11Auth, Dot11Deauth, Dot11Disas, Dot11ProbeReq,
        Dot11Elt, RadioTap,
    )
    from scapy.all import raw, hexdump
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ── IE tag names ──────────────────────────────────────────────────────────────

IE_NAMES = {
    0: 'SSID', 1: 'SupportedRates', 3: 'DSParam', 5: 'TIM',
    7: 'Country', 11: 'QBSS', 20: 'PowerCap', 21: 'SupportedChannels',
    32: 'PowerConstraint', 35: 'TPC', 36: 'SupportedRegClasses',
    37: 'CSA', 38: 'MeasurementReq', 39: 'MeasurementRpt',
    45: 'HT-Capabilities', 48: 'RSN', 52: 'NeighborReport',
    54: 'Mobility', 61: 'HT-Operation', 74: 'ADDBA', 107: 'Interworking',
    127: 'ExtCapabilities', 191: 'VHT-Capabilities', 192: 'VHT-Operation',
    199: 'WideBW', 221: 'Vendor', 255: 'Extension',
}

DOT11_SUBTYPES = {
    (0, 0):  'AssocReq',      (0, 1):  'AssocResp',
    (0, 2):  'ReassocReq',    (0, 3):  'ReassocResp',
    (0, 4):  'ProbeReq',      (0, 5):  'ProbeResp',
    (0, 8):  'Beacon',        (0, 9):  'ATIM',
    (0, 10): 'Disassoc',      (0, 11): 'Auth',
    (0, 12): 'Deauth',        (0, 13): 'Action',
    (2, 0):  'Data',          (2, 4):  'Null',
    (2, 8):  'QoS-Data',      (2, 12): 'QoS-Null',
    (2, 15): 'QoS-CF-Ack',
}

AKM_NAMES = {
    b'\x00\x0f\xac\x01': '802.1X',
    b'\x00\x0f\xac\x02': 'PSK',
    b'\x00\x0f\xac\x03': 'FT-8021X',
    b'\x00\x0f\xac\x04': 'FT-PSK',
    b'\x00\x0f\xac\x06': 'PSK-SHA256',
    b'\x00\x0f\xac\x08': 'SAE',
    b'\x00\x0f\xac\x0c': 'FT-SAE',
    b'\x00\x0f\xac\x12': 'OWE',
}

CIPHER_NAMES = {
    b'\x00\x0f\xac\x00': 'USE-GROUP',
    b'\x00\x0f\xac\x01': 'WEP-40',
    b'\x00\x0f\xac\x02': 'TKIP',
    b'\x00\x0f\xac\x04': 'CCMP-128',
    b'\x00\x0f\xac\x06': 'CMAC',
    b'\x00\x0f\xac\x08': 'GCMP-128',
    b'\x00\x0f\xac\x09': 'GCMP-256',
    b'\x00\x0f\xac\x0a': 'CCMP-256',
    b'\x00\x50\xf2\x02': 'TKIP(WPA1)',
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def sep(char='─', n=64):
    return char * n

def mac(b):
    return ':'.join(f'{x:02x}' for x in b)

def anomaly(msg):
    return f'  *** ANOMALY: {msg} ***'

def hexrow(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part  = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  {i:04x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(lines)

# ── IE parser ─────────────────────────────────────────────────────────────────

def parse_ies(data: bytes, frame_remaining: int) -> list:
    """
    Walk IE TLV chain. Returns list of dicts with anomaly flags.
    frame_remaining = bytes after IE chain start (for over-read detection).
    """
    ies = []
    i = 0
    total = len(data)

    while i < total:
        if i + 1 >= total:
            ies.append({'offset': i, 'tag': data[i], 'claimed': '?',
                        'actual': 0, 'body': b'', 'anomalies': ['TRUNCATED_AT_LENGTH']})
            break

        tag     = data[i]
        claimed = data[i+1]
        actual  = min(claimed, total - i - 2)
        body    = data[i+2 : i+2+actual]
        overread = claimed - actual

        info = {
            'offset':   i,
            'tag':      tag,
            'name':     IE_NAMES.get(tag, f'tag-{tag}'),
            'claimed':  claimed,
            'actual':   actual,
            'body':     body,
            'anomalies': [],
        }

        if overread > 0:
            info['anomalies'].append(f'OVER-READ {overread} bytes past frame')
        if claimed == 255:
            info['anomalies'].append('MAX_LEN_CLAIM (255)')
        if claimed == 0 and tag in (48, 45, 191, 255):
            info['anomalies'].append('ZERO_LEN_CRITICAL_IE')

        # RSN IE deep parse
        if tag == 48 and actual >= 2:
            info['rsn'] = parse_rsn_ie(body)

        # HT Capabilities
        if tag == 45 and actual >= 2:
            cap = struct.unpack_from('<H', body)[0]
            info['ht_cap_info'] = f'0x{cap:04x}'

        ies.append(info)
        i += 2 + actual
        if overread > 0:
            break  # can't continue parsing past over-read

    return ies


def parse_rsn_ie(body: bytes) -> dict:
    """Decode RSN IE fields."""
    rsn = {'anomalies': []}
    if len(body) < 2:
        rsn['anomalies'].append('BODY_TOO_SHORT')
        return rsn

    version = struct.unpack_from('<H', body, 0)[0]
    rsn['version'] = version
    if version != 1:
        rsn['anomalies'].append(f'BAD_VERSION={version} (spec=1)')

    offset = 2
    if offset + 4 <= len(body):
        rsn['group_cipher'] = CIPHER_NAMES.get(bytes(body[offset:offset+4]),
                                                 body[offset:offset+4].hex())
        offset += 4
    else:
        rsn['anomalies'].append('TRUNCATED_AT_GROUP_CIPHER')
        return rsn

    if offset + 2 <= len(body):
        pc = struct.unpack_from('<H', body, offset)[0]
        rsn['pairwise_count'] = pc
        offset += 2
        if pc > 4:
            rsn['anomalies'].append(f'PAIRWISE_COUNT={pc} (suspicious)')
        ciphers = []
        for _ in range(pc):
            if offset + 4 > len(body):
                rsn['anomalies'].append('TRUNCATED_PAIRWISE_LIST')
                break
            ciphers.append(CIPHER_NAMES.get(bytes(body[offset:offset+4]),
                                             body[offset:offset+4].hex()))
            offset += 4
        rsn['pairwise_ciphers'] = ciphers
    else:
        rsn['anomalies'].append('TRUNCATED_AT_PAIRWISE_COUNT')
        return rsn

    if offset + 2 <= len(body):
        ac = struct.unpack_from('<H', body, offset)[0]
        rsn['akm_count'] = ac
        offset += 2
        if ac > 4:
            rsn['anomalies'].append(f'AKM_COUNT={ac} (suspicious)')
        akms = []
        for _ in range(ac):
            if offset + 4 > len(body):
                rsn['anomalies'].append('TRUNCATED_AKM_LIST')
                break
            akms.append(AKM_NAMES.get(bytes(body[offset:offset+4]),
                                       body[offset:offset+4].hex()))
            offset += 4
        rsn['akms'] = akms

    if offset + 2 <= len(body):
        caps = struct.unpack_from('<H', body, offset)[0]
        rsn['rsn_caps'] = f'0x{caps:04x}'
        rsn['pmf_capable']  = bool(caps & (1 << 7))
        rsn['pmf_required'] = bool(caps & (1 << 6))

    return rsn


# ── Frame parser ──────────────────────────────────────────────────────────────

def parse_dot11_frame(data: bytes) -> dict:
    """
    Manual 802.11 frame decoder (no scapy dependency).
    Returns structured dict with anomaly flags.
    """
    result = {'raw_len': len(data), 'anomalies': [], 'ies': []}

    if len(data) < 10:
        result['anomalies'].append('FRAME_TOO_SHORT')
        return result

    fc_bytes  = struct.unpack_from('<H', data, 0)[0]
    proto     = fc_bytes & 0x3
    ftype     = (fc_bytes >> 2) & 0x3
    subtype   = (fc_bytes >> 4) & 0xF
    fc_flags  = (fc_bytes >> 8) & 0xFF

    result['fc_raw']  = f'0x{fc_bytes:04x}'
    result['type']    = ftype
    result['subtype'] = subtype
    result['frame_name'] = DOT11_SUBTYPES.get((ftype, subtype), f'type{ftype}/sub{subtype}')

    # FCfield flags
    flags = []
    if fc_flags & 0x01: flags.append('ToDS')
    if fc_flags & 0x02: flags.append('FromDS')
    if fc_flags & 0x04: flags.append('MoreFrags')
    if fc_flags & 0x08: flags.append('Retry')
    if fc_flags & 0x10: flags.append('PwrMgmt')
    if fc_flags & 0x20: flags.append('MoreData')
    if fc_flags & 0x40: flags.append('Protected')
    if fc_flags & 0x80: flags.append('Order/HTC')
    result['fc_flags'] = flags

    if ftype == 2 and not (fc_flags & 0x40):
        result['anomalies'].append('DATA_FRAME_UNPROTECTED (no Protected bit)')

    result['duration'] = struct.unpack_from('<H', data, 2)[0]

    # Addresses (24 bytes fixed header minimum)
    if len(data) >= 22:
        result['addr1'] = mac(data[4:10])
        result['addr2'] = mac(data[10:16])
        result['addr3'] = mac(data[16:22])
        result['sc']    = struct.unpack_from('<H', data, 22)[0]
        result['seqnum']  = (result['sc'] >> 4) & 0xFFF
        result['fragnum'] = result['sc'] & 0xF

    # Body start (24 for most mgmt, 26 for QoS data)
    body_offset = 24
    if ftype == 2 and subtype in (8, 9, 10, 11, 12, 13, 14, 15):
        body_offset = 26   # QoS header adds 2 bytes
    if len(data) < body_offset:
        return result

    body = data[body_offset:]

    # Management frame fixed fields + IEs
    if ftype == 0:
        if subtype in (0, 2):      # AssocReq / ReassocReq
            if len(body) >= 4:
                cap_info = struct.unpack_from('<H', body, 0)[0]
                listen_int = struct.unpack_from('<H', body, 2)[0]
                result['cap_info'] = f'0x{cap_info:04x}'
                result['listen_interval'] = listen_int
                ie_offset = 4
                if subtype == 2:   # ReassocReq has extra 6-byte current AP field
                    ie_offset = 10
                result['ies'] = parse_ies(body[ie_offset:],
                                          len(data) - body_offset - ie_offset)

        elif subtype == 11:        # Auth
            if len(body) >= 6:
                algo = struct.unpack_from('<H', body, 0)[0]
                seq  = struct.unpack_from('<H', body, 2)[0]
                status = struct.unpack_from('<H', body, 4)[0]
                result['auth_algo']   = algo
                result['auth_seq']    = seq
                result['auth_status'] = status
                ALGOS = {0: 'Open', 1: 'SharedKey', 2: 'FT', 3: 'SAE'}
                result['auth_algo_name'] = ALGOS.get(algo, f'unknown-{algo}')
                if algo not in ALGOS:
                    result['anomalies'].append(f'UNKNOWN_AUTH_ALGO={algo}')

        elif subtype in (10, 12):  # Disassoc / Deauth
            if len(body) >= 2:
                reason = struct.unpack_from('<H', body, 0)[0]
                result['reason_code'] = reason

        elif subtype == 4:         # ProbeReq
            result['ies'] = parse_ies(body, len(body))

        elif subtype == 13:        # Action
            if len(body) >= 2:
                result['action_category'] = body[0]
                result['action_code']     = body[1]

    return result


# ── Display ───────────────────────────────────────────────────────────────────

def display_frame(path: str, data: bytes):
    print(sep('═'))
    print(f' FILE : {os.path.basename(path)}')
    print(f' SIZE : {len(data)} bytes')
    print(sep('═'))

    # Try RadioTap first
    has_radiotap = (len(data) >= 4 and data[0] == 0 and data[1] == 0)
    rt_len = 0
    if has_radiotap and HAS_SCAPY:
        try:
            rt = RadioTap(data)
            rt_len = rt.len
            print(f' [RadioTap] length={rt_len} present=0x{rt.present:08x}')
            data = data[rt_len:]
            print(f' [RadioTap stripped] remaining {len(data)} bytes')
        except Exception:
            has_radiotap = False

    parsed = parse_dot11_frame(data)

    print()
    print(f'  Frame type   : {parsed.get("frame_name", "?")}  (type={parsed.get("type")} subtype={parsed.get("subtype")})')
    print(f'  FC           : {parsed.get("fc_raw")}  flags=[{" ".join(parsed.get("fc_flags", []))}]')
    print(f'  Duration     : {parsed.get("duration")}')
    if 'addr1' in parsed:
        print(f'  addr1 (DA)   : {parsed["addr1"]}')
        print(f'  addr2 (SA)   : {parsed["addr2"]}')
        print(f'  addr3 (BSSID): {parsed["addr3"]}')
        print(f'  SeqCtrl      : seq={parsed.get("seqnum")} frag={parsed.get("fragnum")}')

    if 'cap_info' in parsed:
        print(f'  CapInfo      : {parsed["cap_info"]}')
        print(f'  ListenIntv   : {parsed["listen_interval"]}')

    if 'auth_algo_name' in parsed:
        print(f'  Auth algo    : {parsed["auth_algo"]} ({parsed["auth_algo_name"]})')
        print(f'  Auth seq     : {parsed["auth_seq"]}')
        print(f'  Auth status  : {parsed["auth_status"]}')

    if 'reason_code' in parsed:
        print(f'  Reason code  : {parsed["reason_code"]}')

    if 'action_category' in parsed:
        print(f'  Action cat   : {parsed["action_category"]}')
        print(f'  Action code  : {parsed["action_code"]}')

    # Frame-level anomalies
    if parsed.get('anomalies'):
        print()
        for a in parsed['anomalies']:
            print(f'  *** FRAME ANOMALY: {a}')

    # IEs
    if parsed.get('ies'):
        print()
        print(f'  {"─"*60}')
        print(f'  Information Elements ({len(parsed["ies"])} parsed):')
        print(f'  {"─"*60}')
        for ie in parsed['ies']:
            tag  = ie['tag']
            name = ie['name']
            cl   = ie['claimed']
            act  = ie['actual']
            body = ie['body']

            overread_marker = ''
            if cl != act:
                overread_marker = f'  ← OVER-READ {cl-act}B'

            print(f'  offset={ie["offset"]:3d}  tag={tag:3d}(0x{tag:02x})  '
                  f'name={name:<22}  claimed={cl:3d}  actual={act:3d}'
                  + overread_marker)

            if body:
                print(f'           body: {body[:32].hex()}'
                      + ('...' if len(body) > 32 else ''))

            for a in ie.get('anomalies', []):
                print(f'           *** IE ANOMALY: {a}')

            # RSN deep decode
            if 'rsn' in ie:
                r = ie['rsn']
                print(f'           RSN version    : {r.get("version", "?")}')
                if 'group_cipher' in r:
                    print(f'           group cipher   : {r["group_cipher"]}')
                if 'pairwise_ciphers' in r:
                    print(f'           pairwise       : {r["pairwise_ciphers"]}')
                if 'akms' in r:
                    print(f'           AKMs           : {r["akms"]}')
                if 'rsn_caps' in r:
                    print(f'           RSN caps       : {r["rsn_caps"]}  '
                          f'pmf_cap={r.get("pmf_capable")} pmf_req={r.get("pmf_required")}')
                for a in r.get('anomalies', []):
                    print(f'           *** RSN ANOMALY: {a}')

            if 'ht_cap_info' in ie:
                print(f'           HT CapInfo     : {ie["ht_cap_info"]}')

    # Scapy summary
    if HAS_SCAPY:
        print()
        print(f'  {"─"*60}')
        print('  Scapy decode:')
        try:
            pkt = Dot11(data)
            print(f'  {pkt.summary()}')
        except Exception as e:
            print(f'  (scapy error: {e})')

    # Hex dump
    print()
    print(f'  {"─"*60}')
    print('  Hex dump:')
    print(hexrow(data))
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1:
        paths = sys.argv[1:]
    else:
        p = input('Enter .bin file path: ').strip()
        paths = [p] if p else []

    if not paths:
        print('No file provided.')
        sys.exit(1)

    for path in paths:
        if not os.path.exists(path):
            # Try /tmp/ prefix
            alt = '/tmp/' + os.path.basename(path)
            if os.path.exists(alt):
                path = alt
            else:
                print(f'File not found: {path}')
                continue

        with open(path, 'rb') as f:
            data = f.read()

        # Some crash files have appended separator (from eapol_crash writer)
        # Format: <frame_bytes>\n---\n<eapol_bytes>
        if b'\n---\n' in data:
            parts = data.split(b'\n---\n', 1)
            print(f'[Multi-part file: frame={len(parts[0])}B eapol={len(parts[1])}B]')
            data = parts[0]

        display_frame(path, data)


if __name__ == '__main__':
    main()
