#!/usr/bin/env python3
"""
Convert .bin crash frame files to a single .pcap for Wireshark analysis.

Usage:
  python3 bin_to_pcap.py /tmp/wifi_fuzz_crash_*.bin
  python3 bin_to_pcap.py /tmp/wifi_fuzz_crash_*.bin -o /tmp/crashes.pcap
  python3 bin_to_pcap.py                             # all /tmp/wifi_fuzz_crash_*.bin

Output: one .pcap containing all frames in filename order.
Open in Wireshark — each packet is a 802.11 management frame.
Add column "No." comment to see which .bin file each packet came from.
"""
import sys
import os
import glob
import struct
import time


_PCAP_MAGIC       = 0xa1b2c3d4
_PCAP_VERSION_MAJ = 2
_PCAP_VERSION_MIN = 4
_DLT_IEEE802_11   = 105


def write_pcap(out_path: str, frames: list):
    """
    Write list of (filename, data) tuples to a PCAP file.
    DLT=105 (raw 802.11). Timestamps spaced 10ms apart for ordering.
    """
    with open(out_path, 'wb') as f:
        # Global header
        f.write(struct.pack('<IHHiIII',
            _PCAP_MAGIC, _PCAP_VERSION_MAJ, _PCAP_VERSION_MIN,
            0, 0, 65535, _DLT_IEEE802_11))

        ts = time.time()
        for _name, data in frames:
            ts_sec  = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            n = len(data)
            f.write(struct.pack('<IIII', ts_sec, ts_usec, n, n))
            f.write(data)
            ts += 0.01  # 10ms apart so Wireshark shows ordering


def load_bin(path: str) -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
    # Strip EAPOL multi-part separator if present
    if b'\n---\n' in data:
        data = data.split(b'\n---\n', 1)[0]
    return data


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Convert .bin crash frames to PCAP for Wireshark.')
    parser.add_argument('files', nargs='*',
                        help='.bin crash files (default: /tmp/wifi_fuzz_crash_*.bin)')
    parser.add_argument('-o', '--output', default=None,
                        help='Output PCAP path (default: /tmp/fuzz_crashes.pcap)')
    args = parser.parse_args()

    paths = args.files
    if not paths:
        paths = sorted(
            glob.glob('/tmp/wifi_fuzz_crash_*.bin') +
            glob.glob('/tmp/eapol_crash_*.bin') +
            glob.glob('/tmp/ie_crash_*.bin') +
            glob.glob('/tmp/rsn_overread_*.bin')
        )
        if not paths:
            print('No .bin crash files found in /tmp/')
            sys.exit(1)

    out_path = args.output or '/tmp/fuzz_crashes.pcap'

    frames = []
    skipped = 0
    for path in paths:
        if not os.path.exists(path):
            print(f'  SKIP (not found): {path}')
            skipped += 1
            continue
        try:
            data = load_bin(path)
            if len(data) < 10:
                print(f'  SKIP (too short {len(data)}B): {os.path.basename(path)}')
                skipped += 1
                continue
            frames.append((os.path.basename(path), data))
            print(f'  + {os.path.basename(path)}  ({len(data)}B)')
        except Exception as e:
            print(f'  SKIP (error: {e}): {path}')
            skipped += 1

    if not frames:
        print('No valid frames loaded.')
        sys.exit(1)

    write_pcap(out_path, frames)
    print()
    print(f'Written: {out_path}')
    print(f'Frames:  {len(frames)}  (skipped {skipped})')
    print()
    print('Open in Wireshark:')
    print(f'  wireshark {out_path}')
    print()
    print('Filter by frame type:')
    print('  wlan.fc.type == 0                    # management')
    print('  wlan.fc.type_subtype == 0x00         # AssocReq')
    print('  wlan.fc.type_subtype == 0x02         # ReassocReq')
    print('  wlan.rsn.version != 1                # bad RSN version')
    print('  wlan.tag.length > 100 && wlan.tag.number == 48  # RSN IE oversized')


if __name__ == '__main__':
    main()
