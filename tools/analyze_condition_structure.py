#!/usr/bin/env python3
"""
Analyze the COMPLETE structure of the condition section, including gaps between
260-byte M0%D blocks. The 260-byte blocks are only 26% of the section — what's
in the other 74%?

For both sword_upper and dualsword_upper:
- Map all M0%D markers (uniform and non-uniform)
- Analyze gap regions between markers
- Look for patterns in gap data (especially 16-byte inline transitions)
- Cross-reference with string table labels
"""

import struct
from collections import Counter, defaultdict
from pathlib import Path

PAAC_DIR = Path(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm")


def find_string_table(data):
    kg = data.find(b'key_guard\x00')
    if kg < 0: return []
    for back in range(500, 1, -1):
        trial = kg - 1 - back
        if trial < 0: continue
        count = struct.unpack_from('<H', data, trial)[0]
        if count < 5 or count > 200: continue
        off = trial + 2
        entries = []
        ok = True
        for i in range(count):
            if off >= len(data): ok = False; break
            slen = data[off]
            if slen < 2 or slen > 255 or off + 1 + slen > len(data): ok = False; break
            s = data[off+1:off+slen].decode('ascii', errors='replace')
            entries.append(s)
            off += 1 + slen
        if ok and len(entries) == count and 'key_guard' in entries:
            return entries
    return []


def find_condition_section(data):
    """Find the condition section by locating the first cluster of M0%D markers."""
    magic = b'\x4D\x30\x25\x44'
    markers = []
    pos = 0
    while True:
        idx = data.find(magic, pos)
        if idx == -1: break
        markers.append(idx)
        pos = idx + 1

    if not markers:
        return 0, len(data), markers

    # Find where the dense cluster of M0%D markers begins
    # The condition section has markers close together (260 bytes apart)
    # State records also have M0%D but with larger gaps
    for i in range(len(markers) - 1):
        if markers[i + 1] - markers[i] == 260:
            # Found first uniform block — condition section starts here or earlier
            # Walk back to find the actual start
            start = markers[i]
            # Check if markers before this are also part of the condition section
            for j in range(i - 1, -1, -1):
                gap = markers[j + 1] - markers[j]
                if gap > 10000:  # Too far apart — not condition section
                    break
                start = markers[j]
            return start, len(data), [m for m in markers if m >= start]

    return markers[0], len(data), markers


def analyze_weapon(name, path):
    data = open(path, 'rb').read()
    st = find_string_table(data)
    guard_idx = next((i for i, s in enumerate(st) if s == 'key_guard'), None)

    cond_start, cond_end, markers = find_condition_section(data)
    cond = data[cond_start:]

    print(f"\n{'='*100}")
    print(f"WEAPON: {name} ({len(data)} bytes)")
    print(f"String table: {len(st)} entries, guard_idx={guard_idx}")
    print(f"Condition section: starts at 0x{cond_start:X}, {len(markers)} markers")
    print(f"{'='*100}")

    if len(markers) < 2:
        print("  Too few markers for analysis")
        return

    # Classify gaps between markers
    gaps = []
    for i in range(len(markers) - 1):
        gap_size = markers[i + 1] - markers[i]
        gap_start = markers[i]
        gaps.append((gap_start, gap_size))

    gap_hist = Counter(g[1] for g in gaps)
    print(f"\n  Gap size histogram (marker-to-marker distances):")
    for size, cnt in gap_hist.most_common(20):
        pct = cnt / len(gaps) * 100
        print(f"    {size:>6d} bytes: {cnt:>4d} ({pct:5.1f}%)")

    # Analyze 260-byte blocks
    uniform = [(g[0], data[g[0]:g[0]+260]) for g in gaps if g[1] == 260]
    non_uniform = [(g[0], g[1]) for g in gaps if g[1] != 260]

    print(f"\n  260-byte blocks: {len(uniform)}")
    print(f"  Non-uniform gaps: {len(non_uniform)}")

    # For non-uniform gaps, analyze their internal structure
    print(f"\n  NON-UNIFORM GAP ANALYSIS:")
    for gap_off, gap_size in non_uniform[:20]:
        gap_data = data[gap_off:gap_off + gap_size]

        # Check for M0%D at start (should be there)
        has_m0 = gap_data[:4] == b'\x4D\x30\x25\x44'

        # Check for 16-byte transition patterns within the gap
        # Inline transition: [f32 threshold][f32 -1.0 sentinel][u32 target][u32 sequence]
        n_inline = 0
        for j in range(0, gap_size - 16, 4):
            f1 = struct.unpack_from('<f', gap_data, j)[0]
            f2 = struct.unpack_from('<f', gap_data, j + 4)[0]
            if abs(f2 - (-1.0)) < 0.001 and 0.0 <= f1 <= 2.0:
                n_inline += 1

        # Check for sub-M0%D markers within the gap
        sub_markers = []
        pos = 4  # skip the initial M0%D
        while pos < gap_size - 4:
            if gap_data[pos:pos+4] == b'\x4D\x30\x25\x44':
                sub_markers.append(pos)
            pos += 1

        # Read fields if it starts with M0%D
        label = ""
        if has_m0 and gap_size >= 230 and guard_idx is not None:
            li = gap_data[216] if gap_size > 216 else -1
            kc = gap_data[229] if gap_size > 229 else -1
            if li < len(st):
                label = f" label={st[li]}" if li >= 0 else ""
            if li == guard_idx:
                label += " *** GUARD ***"

        print(f"    @0x{gap_off:X}: {gap_size:>5d} bytes, M0%D={'Y' if has_m0 else 'N'}, "
              f"sub-markers={len(sub_markers)}, inline-like={n_inline}{label}")

    if len(non_uniform) > 20:
        print(f"    ... and {len(non_uniform) - 20} more")

    # Check: do non-uniform M0%D blocks have guard labels?
    guard_in_nonuniform = 0
    if guard_idx is not None:
        for gap_off, gap_size in non_uniform:
            if gap_size > 216:
                gap_data = data[gap_off:gap_off + gap_size]
                if gap_data[:4] == b'\x4D\x30\x25\x44' and gap_data[216] == guard_idx:
                    guard_in_nonuniform += 1
    print(f"\n  Guard label in non-uniform blocks: {guard_in_nonuniform}")

    # For uniform blocks, check how many per source_id
    src_ids = defaultdict(list)
    for off, block in uniform:
        src = struct.unpack_from('<H', block, 212)[0]
        li = block[216]
        src_ids[src].append(li)

    # Find source_ids that have guard blocks
    guard_srcs = set()
    noguard_srcs = set()
    for src, labels in src_ids.items():
        if guard_idx in labels:
            guard_srcs.add(src)
        else:
            noguard_srcs.add(src)

    # Source IDs with multiple blocks
    multi_src = {s: ls for s, ls in src_ids.items() if len(ls) > 1}

    print(f"\n  Unique source_ids: {len(src_ids)}")
    print(f"  Source_ids with guard: {len(guard_srcs)}")
    print(f"  Source_ids without guard: {len(noguard_srcs)}")
    print(f"  Source_ids with multiple blocks: {len(multi_src)}")

    # Show a few multi-block source_ids that include guard
    print(f"\n  Source_ids that have BOTH guard and other labels (first 10):")
    count = 0
    for src in sorted(guard_srcs):
        labels = src_ids[src]
        if len(labels) > 1:
            label_names = [st[l] if l < len(st) else f"?{l}" for l in labels]
            print(f"    src={src:>5d}: {label_names}")
            count += 1
            if count >= 10:
                break

    # Show source_ids that DON'T have guard (attack states?)
    print(f"\n  Source_ids WITHOUT guard (likely attack states, first 10):")
    count = 0
    for src in sorted(noguard_srcs):
        labels = src_ids[src]
        label_names = [st[l] if l < len(st) else f"?{l}" for l in labels]
        print(f"    src={src:>5d}: {label_names}")
        count += 1
        if count >= 10:
            break


def main():
    for name in ['sword_upper', 'dualsword_upper', 'battleaxe_upper']:
        path = PAAC_DIR / f"{name}.paac"
        if path.exists():
            analyze_weapon(name, path)


if __name__ == "__main__":
    main()
