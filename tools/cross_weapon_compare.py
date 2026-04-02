#!/usr/bin/env python3
"""
Step 2: Cross-weapon .paac comparison.

Parse condition graphs from ALL extracted weapon .paac files and compare:
- Block counts, label distributions, key_code distributions
- String tables (which weapon-specific labels exist?)
- State record counts and inline transition patterns
- Differential: which weapons have guard transitions that sword lacks?
"""

import struct
import os
from collections import Counter, defaultdict
from pathlib import Path

PAAC_DIR = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm"


def parse_paac(path):
    """Parse a .paac file: header, string table, condition blocks."""
    with open(path, "rb") as f:
        data = f.read()

    result = {'path': path, 'size': len(data), 'data': data}

    # Header (68 bytes)
    if len(data) < 68:
        return result
    node_count = struct.unpack_from("<I", data, 0)[0]
    speed = struct.unpack_from("<f", data, 4)[0]
    flags = struct.unpack_from("<I", data, 8)[0]
    result['header'] = {'nodes': node_count, 'speed': speed, 'flags': flags}

    # Find string table: look for sequences of length-prefixed strings after state records
    # String table marker: uint16 count followed by (uint16_len, ascii_string) entries
    # We'll scan for them by looking for the pattern

    # Find all M0%D markers
    magic = b'\x4D\x30\x25\x44'
    markers = []
    pos = 0
    while True:
        idx = data.find(magic, pos)
        if idx == -1:
            break
        markers.append(idx)
        pos = idx + 1

    result['total_markers'] = len(markers)

    # Find uniform 260-byte blocks
    uniform = []
    for i in range(len(markers) - 1):
        if markers[i + 1] - markers[i] == 260:
            off = markers[i]
            uniform.append(data[off:off + 260])

    result['uniform_blocks'] = uniform

    # Parse string table(s) - find "key_guard" or "key_" prefixed strings
    strings = {}
    # Scan for "key_" in the file to find the string table region
    key_pos = data.find(b'key_')
    if key_pos > 0:
        # Walk backwards to find the table start
        # String table format: count(u16) then (len(u16) + chars) per entry
        # Try to find the table by scanning backwards for a reasonable count
        region_start = max(0, key_pos - 2000)
        region = data[region_start:key_pos + 2000]

        # Alternative: just find all "key_*" strings and label strings
        found_strings = []
        scan = 0
        while scan < len(data) - 4:
            # Look for key_ prefix
            idx = data.find(b'key_', scan)
            if idx == -1:
                break
            # Read backwards 2 bytes for length
            if idx >= 2:
                slen = struct.unpack_from("<H", data, idx - 2)[0]
                if 4 <= slen <= 64 and idx - 2 + 2 + slen <= len(data):
                    s = data[idx:idx + slen - 1].decode('ascii', errors='replace')
                    found_strings.append(s)
            scan = idx + 1
        result['key_strings'] = sorted(set(found_strings))

    # Also find the proper string table by scanning for common label pattern
    # Each string table: uint16 count, then count entries of (uint16 len, string bytes)
    string_tables = []
    for trial_offset in range(0x8000, min(len(data), 0x200000), 2):
        if trial_offset + 2 > len(data):
            break
        count = struct.unpack_from("<H", data, trial_offset)[0]
        if 10 <= count <= 200:
            # Try to read entries
            off = trial_offset + 2
            entries = []
            valid = True
            for j in range(count):
                if off + 2 > len(data):
                    valid = False
                    break
                slen = struct.unpack_from("<H", data, off)[0]
                if slen < 1 or slen > 256:
                    valid = False
                    break
                if off + 2 + slen > len(data):
                    valid = False
                    break
                s = data[off + 2:off + 2 + slen - 1]
                try:
                    text = s.decode('ascii')
                    if not all(c.isalnum() or c in '_/.' for c in text):
                        valid = False
                        break
                except:
                    valid = False
                    break
                entries.append(text)
                off += 2 + slen
            if valid and len(entries) == count and count >= 10:
                # Check if this looks like a real string table
                has_key = any('key_' in e for e in entries)
                if has_key:
                    string_tables.append((trial_offset, entries))
                    break

    if string_tables:
        result['string_table'] = string_tables[0][1]
        result['string_table_offset'] = string_tables[0][0]

    return result


def extract_block_fields(block):
    """Extract fields from a 260-byte block."""
    return {
        'source_id': struct.unpack_from("<H", block, 212)[0],
        'label_index': block[216],
        'key_code': block[229],
        'opcode_prefix': block[224:227],
        'opcode_6': block[224:230],
        'target_family': struct.unpack_from("<I", block, 246)[0],
        'flags': block[252:260],
        'byte_80': struct.unpack_from("<H", block, 80)[0],
        'byte_222': block[222],
        'byte_231_233': block[231:234],
    }


def main():
    # Find all .paac files
    paac_dir = Path(PAAC_DIR)
    paac_files = sorted(paac_dir.glob("*_upper.paac")) + sorted(paac_dir.glob("*.paac"))
    # Deduplicate
    seen = set()
    unique_files = []
    for f in paac_files:
        if f.name not in seen:
            seen.add(f.name)
            unique_files.append(f)

    print(f"Found {len(unique_files)} .paac files in {PAAC_DIR}\n")

    weapons = {}
    for f in unique_files:
        print(f"Parsing {f.name}...")
        weapons[f.stem] = parse_paac(str(f))

    # ============================================================
    # 1. OVERVIEW TABLE
    # ============================================================
    print("\n" + "=" * 120)
    print("1. WEAPON OVERVIEW")
    print("=" * 120)
    print(f"{'Weapon':<25s} {'Size':>10s} {'Nodes':>7s} {'M0%D':>6s} {'260B':>6s} {'KeyStrings':>12s}")
    print("-" * 80)
    for name, w in sorted(weapons.items()):
        h = w.get('header', {})
        n_keys = len(w.get('key_strings', []))
        print(f"{name:<25s} {w['size']:>10d} {h.get('nodes', '?'):>7} {w['total_markers']:>6d} "
              f"{len(w.get('uniform_blocks', [])):>6d} {n_keys:>12d}")

    # ============================================================
    # 2. STRING TABLE COMPARISON
    # ============================================================
    print("\n" + "=" * 120)
    print("2. STRING TABLES — KEY LABELS PER WEAPON")
    print("=" * 120)

    all_labels = set()
    weapon_labels = {}
    for name, w in sorted(weapons.items()):
        st = w.get('string_table', w.get('key_strings', []))
        key_labels = [s for s in st if s.startswith('key_')]
        weapon_labels[name] = set(key_labels)
        all_labels.update(key_labels)
        print(f"\n  {name} ({len(st)} total strings, {len(key_labels)} key_ labels):")
        for s in sorted(key_labels):
            print(f"    {s}")

    # ============================================================
    # 3. LABEL DISTRIBUTION PER WEAPON
    # ============================================================
    print("\n" + "=" * 120)
    print("3. CONDITION BLOCK — LABEL DISTRIBUTION PER WEAPON")
    print("=" * 120)

    for name, w in sorted(weapons.items()):
        blocks = w.get('uniform_blocks', [])
        if not blocks:
            print(f"\n  {name}: NO condition blocks")
            continue

        st = w.get('string_table', [])
        label_counts = Counter()
        kc_counts = Counter()
        for b in blocks:
            f = extract_block_fields(b)
            li = f['label_index']
            label_name = st[li] if li < len(st) else f"?{li}"
            label_counts[label_name] += 1
            kc_counts[f['key_code']] += 1

        print(f"\n  {name} ({len(blocks)} blocks):")
        print(f"    Label distribution (top 15):")
        for label, cnt in label_counts.most_common(15):
            print(f"      {label:>35s}: {cnt}")
        print(f"    Key_code distribution:")
        for kc, cnt in sorted(kc_counts.items()):
            print(f"      0x{kc:02X}: {cnt}")

    # ============================================================
    # 4. GUARD-SPECIFIC COMPARISON
    # ============================================================
    print("\n" + "=" * 120)
    print("4. GUARD BLOCKS — CROSS-WEAPON COMPARISON")
    print("=" * 120)

    for name, w in sorted(weapons.items()):
        blocks = w.get('uniform_blocks', [])
        st = w.get('string_table', [])
        if not blocks or not st:
            continue

        # Find guard-related labels
        guard_indices = [i for i, s in enumerate(st) if 'guard' in s.lower()]
        guard_blocks = []
        for bi, b in enumerate(blocks):
            f = extract_block_fields(b)
            if f['label_index'] in guard_indices:
                label_name = st[f['label_index']] if f['label_index'] < len(st) else f"?{f['label_index']}"
                guard_blocks.append((bi, f, label_name))

        if guard_blocks:
            print(f"\n  {name}: {len(guard_blocks)} guard-related blocks (indices: {guard_indices})")
            for bi, f, lname in guard_blocks[:20]:
                opcode_hex = f['opcode_6'].hex(' ').upper()
                flags_hex = f['flags'].hex(' ').upper()
                print(f"    Block {bi:>3d}: src={f['source_id']:>5d} label={lname:>20s} "
                      f"kc=0x{f['key_code']:02X} tgt={f['target_family']:>8d} "
                      f"op=[{opcode_hex}] fl=[{flags_hex}]")
            if len(guard_blocks) > 20:
                print(f"    ... and {len(guard_blocks) - 20} more")
        else:
            print(f"\n  {name}: NO guard blocks")

    # ============================================================
    # 5. UNIQUE PATTERNS — WHAT DOES EACH WEAPON HAVE THAT SWORD DOESN'T?
    # ============================================================
    print("\n" + "=" * 120)
    print("5. OPCODE PATTERNS — PER WEAPON COMPARISON WITH SWORD")
    print("=" * 120)

    sword_data = weapons.get('sword_upper', {})
    sword_blocks = sword_data.get('uniform_blocks', [])
    if sword_blocks:
        sword_patterns = Counter()
        for b in sword_blocks:
            f = extract_block_fields(b)
            pattern = (f['opcode_prefix'].hex(), f['key_code'], f['byte_222'])
            sword_patterns[pattern] += 1

        for name, w in sorted(weapons.items()):
            if name == 'sword_upper':
                continue
            blocks = w.get('uniform_blocks', [])
            if not blocks:
                continue

            other_patterns = Counter()
            for b in blocks:
                f = extract_block_fields(b)
                pattern = (f['opcode_prefix'].hex(), f['key_code'], f['byte_222'])
                other_patterns[pattern] += 1

            # Find patterns in other weapon but NOT in sword
            unique_to_other = {k: v for k, v in other_patterns.items() if k not in sword_patterns}
            if unique_to_other:
                print(f"\n  {name} has patterns NOT in sword:")
                for (px, kc, b222), cnt in sorted(unique_to_other.items(), key=lambda x: -x[1]):
                    print(f"    prefix={px} kc=0x{kc:02X} b222={b222}: {cnt} blocks")

    # ============================================================
    # 6. FLAGS COMPARISON — GUARD BLOCKS ACROSS WEAPONS
    # ============================================================
    print("\n" + "=" * 120)
    print("6. FLAGS OF GUARD BLOCKS — CROSS-WEAPON")
    print("=" * 120)

    for name, w in sorted(weapons.items()):
        blocks = w.get('uniform_blocks', [])
        st = w.get('string_table', [])
        if not blocks or not st:
            continue

        guard_indices = [i for i, s in enumerate(st) if 'guard' in s.lower()]
        guard_flags = []
        for b in blocks:
            f = extract_block_fields(b)
            if f['label_index'] in guard_indices:
                guard_flags.append(f['flags'])

        if guard_flags:
            union = [0] * 8
            inter = [0xFF] * 8
            for fl in guard_flags:
                for j in range(8):
                    union[j] |= fl[j]
                    inter[j] &= fl[j]
            u_hex = " ".join(f"{b:02X}" for b in union)
            i_hex = " ".join(f"{b:02X}" for b in inter)
            print(f"  {name:<25s}: {len(guard_flags):>3d} guard blocks, "
                  f"union=[{u_hex}] inter=[{i_hex}]")

    # ============================================================
    # 7. NON-UNIFORM BLOCKS ANALYSIS
    # ============================================================
    print("\n" + "=" * 120)
    print("7. NON-UNIFORM BLOCKS (M0%D markers NOT at 260-byte spacing)")
    print("=" * 120)

    for name, w in sorted(weapons.items()):
        data = w['data']
        magic = b'\x4D\x30\x25\x44'
        markers = []
        pos = 0
        while True:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            markers.append(idx)
            pos = idx + 1

        non_uniform = []
        for i in range(len(markers) - 1):
            dist = markers[i + 1] - markers[i]
            if dist != 260:
                non_uniform.append((i, markers[i], dist))

        if non_uniform:
            print(f"\n  {name}: {len(non_uniform)} non-uniform gaps:")
            for idx, off, dist in non_uniform[:10]:
                print(f"    Marker #{idx} at 0x{off:X}: gap={dist} bytes")
            if len(non_uniform) > 10:
                print(f"    ... and {len(non_uniform) - 10} more")
            # Histogram of gap sizes
            gap_hist = Counter(d for _, _, d in non_uniform)
            print(f"    Gap size histogram: {dict(gap_hist.most_common(10))}")


if __name__ == "__main__":
    main()
