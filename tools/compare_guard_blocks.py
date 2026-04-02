#!/usr/bin/env python3
"""
Focused comparison of guard condition blocks across all weapons.
Properly parses each weapon's string table by locating "key_guard" and walking backwards.
"""

import struct
import os
from collections import Counter, defaultdict
from pathlib import Path

PAAC_DIR = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm"


def find_string_table(data):
    """Find and parse the string table by locating 'key_guard' and walking backwards."""
    kg_pos = data.find(b'key_guard')
    if kg_pos < 0:
        return None, []

    # key_guard is preceded by its length (uint16 = 10, including null terminator)
    # Walk backward: before the string is uint16 length = 10 (0x0A 0x00)
    len_pos = kg_pos - 2
    if len_pos < 0:
        return None, []
    slen = struct.unpack_from("<H", data, len_pos)[0]
    if slen != 10:  # "key_guard\0" = 10 bytes
        # Try offset -1 for misalignment
        return None, []

    # Walk backwards through entries to find the table start
    # Each entry: uint16 length + string bytes
    # Keep walking back until we hit an invalid entry
    entries_from_end = []
    cur = len_pos
    while cur >= 4:
        # Current entry starts at cur: uint16 len + string
        entry_len = struct.unpack_from("<H", data, cur)[0]
        if entry_len < 1 or entry_len > 256:
            break
        entry_str = data[cur + 2:cur + 2 + entry_len - 1]
        try:
            text = entry_str.decode('ascii')
            if not all(c.isalnum() or c in '_/. ' for c in text):
                break
        except:
            break
        entries_from_end.append((cur, text))

        # Walk backwards to find previous entry
        # We need to check: the 2 bytes before cur should be the length of the previous entry's string
        # But we don't know where the previous entry starts
        # Strategy: try reading uint16 at various positions before cur
        found_prev = False
        for backtrack in range(2, 260):
            prev_pos = cur - backtrack
            if prev_pos < 2:
                break
            prev_len = struct.unpack_from("<H", data, prev_pos)[0]
            if prev_len >= 1 and prev_len <= 256 and prev_pos + 2 + prev_len == cur:
                # Validate the string
                prev_str = data[prev_pos + 2:prev_pos + 2 + prev_len - 1]
                try:
                    text = prev_str.decode('ascii')
                    if all(c.isalnum() or c in '_/. ' for c in text):
                        cur = prev_pos
                        found_prev = True
                        break
                except:
                    pass
        if not found_prev:
            break

    # cur now points to the first entry we could find
    # The table count (uint16) should be at cur - 2
    table_start = cur - 2
    if table_start < 0:
        return None, []

    count = struct.unpack_from("<H", data, table_start)[0]

    # Now parse forward from table_start
    entries = []
    off = table_start + 2
    for i in range(count):
        if off + 2 > len(data):
            break
        slen = struct.unpack_from("<H", data, off)[0]
        if slen < 1 or slen > 256 or off + 2 + slen > len(data):
            break
        s = data[off + 2:off + 2 + slen - 1].decode('ascii', errors='replace')
        entries.append(s)
        off += 2 + slen

    return table_start, entries


def parse_condition_blocks(data):
    """Find all uniform 260-byte M0%D blocks."""
    magic = b'\x4D\x30\x25\x44'
    markers = []
    pos = 0
    while True:
        idx = data.find(magic, pos)
        if idx == -1:
            break
        markers.append(idx)
        pos = idx + 1

    blocks = []
    for i in range(len(markers) - 1):
        if markers[i + 1] - markers[i] == 260:
            off = markers[i]
            blocks.append((off, data[off:off + 260]))
    return blocks, markers


def main():
    paac_dir = Path(PAAC_DIR)
    files = sorted(paac_dir.glob("*_upper.paac"))

    print(f"{'Weapon':<22s} {'Blocks':>6s} {'Guard#':>6s} {'GuardIdx':>8s} {'GuardLabel':>20s}")
    print("-" * 75)

    all_weapons = {}

    for f in files:
        data = open(f, 'rb').read()
        st_off, st_entries = find_string_table(data)
        blocks, markers = parse_condition_blocks(data)

        # Find guard label index
        guard_idx = None
        guard_label = "?"
        for i, s in enumerate(st_entries):
            if s == "key_guard":
                guard_idx = i
                guard_label = s
                break

        # Count guard blocks
        guard_count = 0
        guard_blocks = []
        for off, b in blocks:
            li = b[216]
            if li == guard_idx:
                guard_count += 1
                kc = b[229]
                src = struct.unpack_from("<H", b, 212)[0]
                tgt = struct.unpack_from("<I", b, 246)[0]
                flags = b[252:260]
                opcode = b[224:234]
                guard_blocks.append({
                    'offset': off, 'src': src, 'kc': kc, 'tgt': tgt,
                    'flags': flags, 'opcode': opcode, 'label_idx': li,
                })

        print(f"{f.stem:<22s} {len(blocks):>6d} {guard_count:>6d} {str(guard_idx):>8s} {guard_label:>20s}")

        all_weapons[f.stem] = {
            'blocks': blocks,
            'guard_blocks': guard_blocks,
            'string_table': st_entries,
            'guard_idx': guard_idx,
            'data': data,
            'markers': markers,
        }

    # ============================================================
    # DETAILED GUARD BLOCK COMPARISON
    # ============================================================
    print("\n" + "=" * 120)
    print("DETAILED GUARD BLOCKS PER WEAPON")
    print("=" * 120)

    for name, w in sorted(all_weapons.items()):
        gb = w['guard_blocks']
        if not gb:
            continue

        print(f"\n  {name} ({len(gb)} guard blocks):")

        # Key_code distribution within guard blocks
        kc_dist = Counter(g['kc'] for g in gb)
        print(f"    Key_code dist: {dict(sorted(kc_dist.items()))}")

        # Flags analysis
        union = [0] * 8
        inter = [0xFF] * 8
        for g in gb:
            for j in range(8):
                union[j] |= g['flags'][j]
                inter[j] &= g['flags'][j]
        u_hex = " ".join(f"{b:02X}" for b in union)
        i_hex = " ".join(f"{b:02X}" for b in inter)
        print(f"    Flags union: [{u_hex}]")
        print(f"    Flags inter: [{i_hex}]")

        # Opcode patterns
        op_dist = Counter(g['opcode'][:6].hex() for g in gb)
        print(f"    Opcode patterns (first 6 bytes):")
        for pat, cnt in op_dist.most_common(10):
            print(f"      {pat}: {cnt}")

        # Target family distribution
        tgt_dist = Counter(g['tgt'] for g in gb)
        print(f"    Target families: {dict(sorted(tgt_dist.items()))}")

        # Show first few blocks
        print(f"    First 5 blocks:")
        for g in gb[:5]:
            op_hex = g['opcode'].hex(' ').upper()
            fl_hex = g['flags'].hex(' ').upper()
            print(f"      src={g['src']:>5d} kc=0x{g['kc']:02X} tgt={g['tgt']:>8d} op=[{op_hex}] fl=[{fl_hex}]")

    # ============================================================
    # COMPARE: label distribution across weapons with same numbering
    # ============================================================
    print("\n" + "=" * 120)
    print("STRING TABLE COMPARISON (first 25 entries per weapon)")
    print("=" * 120)

    for name, w in sorted(all_weapons.items()):
        st = w['string_table']
        if st:
            print(f"\n  {name} ({len(st)} entries):")
            for i, s in enumerate(st[:25]):
                marker = " <-- GUARD" if 'guard' in s.lower() else ""
                marker += " <-- ATTACK" if 'attack' in s.lower() else ""
                print(f"    [{i:>2d}] {s}{marker}")

    # ============================================================
    # INTER-WEAPON DIFFERENTIAL: how many blocks per label_index
    # ============================================================
    print("\n" + "=" * 120)
    print("LABEL INDEX DISTRIBUTION COMPARISON (all weapons side by side)")
    print("=" * 120)

    # For each weapon, build label distribution
    all_labels = set()
    weapon_dists = {}
    for name, w in sorted(all_weapons.items()):
        dist = Counter()
        for off, b in w['blocks']:
            dist[b[216]] += 1
        weapon_dists[name] = dist
        all_labels.update(dist.keys())

    # Print header
    weapons_with_blocks = [n for n in sorted(all_weapons.keys()) if all_weapons[n]['blocks']]
    header = f"{'LabelIdx':>8s} | " + " | ".join(f"{n[:12]:>12s}" for n in weapons_with_blocks)
    print(header)
    print("-" * len(header))

    for li in sorted(all_labels):
        # Get the label name from the first weapon that has a string table
        label_name = f"?{li}"
        for n in weapons_with_blocks:
            st = all_weapons[n]['string_table']
            if li < len(st):
                label_name = st[li][:20]
                break

        counts = []
        for n in weapons_with_blocks:
            c = weapon_dists[n].get(li, 0)
            counts.append(f"{c:>12d}" if c else f"{'':>12s}")

        print(f"{li:>8d} | " + " | ".join(counts) + f"  ({label_name})")

    # ============================================================
    # KEY_CODE DISTRIBUTION COMPARISON
    # ============================================================
    print("\n" + "=" * 120)
    print("KEY_CODE DISTRIBUTION COMPARISON (all weapons side by side)")
    print("=" * 120)

    all_kcs = set()
    weapon_kc_dists = {}
    for name, w in sorted(all_weapons.items()):
        dist = Counter()
        for off, b in w['blocks']:
            dist[b[229]] += 1
        weapon_kc_dists[name] = dist
        all_kcs.update(dist.keys())

    header = f"{'KeyCode':>8s} | " + " | ".join(f"{n[:12]:>12s}" for n in weapons_with_blocks)
    print(header)
    print("-" * len(header))

    for kc in sorted(all_kcs):
        counts = []
        for n in weapons_with_blocks:
            c = weapon_kc_dists[n].get(kc, 0)
            counts.append(f"{c:>12d}" if c else f"{'':>12s}")
        print(f"    0x{kc:02X} | " + " | ".join(counts))

    # ============================================================
    # CROSS-TAB: For each weapon, label=guard blocks vs key_code
    # ============================================================
    print("\n" + "=" * 120)
    print("GUARD LABEL BLOCKS: key_code × weapon")
    print("=" * 120)

    for kc in sorted(all_kcs):
        counts = []
        for n in weapons_with_blocks:
            gi = all_weapons[n]['guard_idx']
            c = sum(1 for off, b in all_weapons[n]['blocks'] if b[216] == gi and b[229] == kc)
            counts.append(f"{c:>12d}" if c else f"{'':>12s}")
        print(f"    0x{kc:02X} | " + " | ".join(counts))


if __name__ == "__main__":
    main()
