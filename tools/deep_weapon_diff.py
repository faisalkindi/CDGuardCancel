#!/usr/bin/env python3
"""
Deep structural comparison of all weapon .paac files.

Analyzes:
  1. Full state record comparison (M0%D markers, transitions, guard presence)
  2. Inline transition diff (target distribution, guard thresholds)
  3. Condition block deep comparison (label x key_code cross-tab)
  4. 260-byte block byte-level diff of guard blocks across weapons
  5. Gap region presence analysis
  6. Guard mechanism summary table

Usage: py -3 deep_weapon_diff.py
"""

import struct
import sys
import os
from collections import Counter, defaultdict
from pathlib import Path

PAAC_DIR = Path(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm")
OUTPUT_FILE = Path(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\weapon_diff_results.txt")

MAGIC = b'\x4D\x30\x25\x44'  # M0%D
MARKER_BYTES = b'\x00\x00\x48\x42'  # float 50.0
SENTINEL_BYTES = b'\x00\x00\x80\xbf'  # float -1.0
TRANSITION_SIZE = 16

# Output buffer
_lines = []


def out(s=""):
    _lines.append(s)
    print(s)


def flush_output():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(_lines))
    out(f"\n[Saved to {OUTPUT_FILE}]")


# ---------------------------------------------------------------------------
# String table parser
# ---------------------------------------------------------------------------

def find_string_table(data):
    """Find and parse the label string table.

    Strategy: locate b'key_guard\\x00' (or b'key_norattack\\x00'), walk backward
    through length-prefixed strings (u8 len + bytes) to find table start, then
    read a u16 count just before the first entry.
    """
    # Try key_guard first, then key_norattack, then any key_ string
    anchor = data.find(b'key_guard\x00')
    if anchor < 0:
        anchor = data.find(b'key_norattack\x00')
    if anchor < 0:
        anchor = data.find(b'key_')
    if anchor < 0:
        return -1, []

    # The string containing the anchor has a u8 length byte before the text.
    # Walk backward: find the length byte for the anchor string.
    # key_guard\x00 = 10 bytes, so len byte = 10 at anchor-1
    # But we need a general approach: scan backwards for a plausible len byte.
    len_byte_pos = -1
    for back in range(1, 200):
        pos = anchor - back
        if pos < 0:
            break
        slen = data[pos]
        # Check: data[pos] = slen, data[pos+1 : pos+1+slen] should contain the anchor text
        if 2 <= slen <= 200 and pos + 1 + slen <= len(data):
            candidate = data[pos + 1: pos + 1 + slen]
            if anchor >= pos + 1 and anchor < pos + 1 + slen:
                # This length byte covers our anchor string
                len_byte_pos = pos
                break
    if len_byte_pos < 0:
        return -1, []

    # Walk backwards through strings to find the first entry
    cur = len_byte_pos
    while cur > 2:
        found_prev = False
        for check_len in range(1, 256):
            prev_start = cur - check_len - 1
            if prev_start < 0:
                break
            if data[prev_start] == check_len:
                candidate = data[prev_start + 1: prev_start + 1 + check_len]
                printable = sum(1 for b in candidate if 32 <= b < 127 or b == 0)
                if printable >= check_len * 0.7 and check_len >= 1:
                    cur = prev_start
                    found_prev = True
                    break
        if not found_prev:
            break

    table_start = cur  # offset of first string's length byte

    # Look for count (u16) before the table. Try offsets -2 and -1
    count_offset = table_start
    for delta in [2, 1]:
        candidate = table_start - delta
        if candidate >= 0:
            if delta == 2:
                val = struct.unpack_from('<H', data, candidate)[0]
            else:
                val = data[candidate]
            if 2 <= val <= 300:
                count_offset = candidate
                break

    # Parse forward
    entries = []
    off = table_start
    for _ in range(500):
        if off >= len(data):
            break
        slen = data[off]
        if slen == 0 or off + 1 + slen > len(data):
            break
        raw = data[off + 1: off + 1 + slen]
        null_pos = raw.find(b'\x00')
        text = raw[:null_pos].decode('ascii', errors='replace') if null_pos >= 0 else raw.decode('ascii', errors='replace')
        # Stop if we hit the animation path table (check next entry for uint16 count + .paa path)
        next_off = off + 1 + slen
        if next_off + 4 < len(data):
            maybe_count = struct.unpack_from('<H', data, next_off)[0]
            if 50 < maybe_count < 5000:
                path_len_off = next_off + 2
                if path_len_off < len(data):
                    plen = data[path_len_off]
                    if plen > 20 and path_len_off + 1 + plen <= len(data):
                        if b'.paa' in data[path_len_off + 1: path_len_off + 1 + plen]:
                            entries.append(text)
                            break
        entries.append(text)
        off += 1 + slen

    return table_start, entries


# ---------------------------------------------------------------------------
# State marker / transition parser
# ---------------------------------------------------------------------------

def find_all_markers(data):
    """Find M0%D magic markers."""
    markers = []
    pos = 0
    while True:
        idx = data.find(MAGIC, pos)
        if idx == -1:
            break
        markers.append(idx)
        pos = idx + 1
    return markers


def find_state_markers(data):
    """Find state markers: [uint16 label][00 00 48 42][00 bc]."""
    markers = []
    end = len(data) - 9
    i = 2
    while i < end:
        if data[i + 2:i + 6] == MARKER_BYTES and data[i + 6] == 0x00 and data[i + 7] == 0xbc:
            markers.append(i)
            i += 100
        else:
            i += 1
    return markers


def find_transitions(data, region_start, region_end):
    """Find inline transition block in a state region.
    Returns list of (threshold, sentinel, target, sequence) tuples, count_offset, data_offset.
    """
    best = None
    for j in range(region_start + 0x50, min(region_end, len(data) - 16)):
        count = data[j]
        if count < 1 or count > 60:
            continue
        rec_start = j + 1
        rec_end = rec_start + count * TRANSITION_SIZE
        if rec_end > region_end or rec_end > len(data):
            continue
        # Validate sentinels
        valid = True
        for k in range(count):
            if data[rec_start + k * 16 + 4: rec_start + k * 16 + 8] != SENTINEL_BYTES:
                valid = False
                break
        if not valid:
            continue
        # Validate targets
        all_ok = True
        for k in range(count):
            target = struct.unpack_from('<I', data, rec_start + k * 16 + 8)[0]
            if target > 2000:
                all_ok = False
                break
        if not all_ok:
            continue
        # Prefer block closest to region end
        if best is None or j > best[0]:
            trans = []
            for k in range(count):
                rec = rec_start + k * 16
                t = (
                    struct.unpack_from('<f', data, rec)[0],      # threshold
                    struct.unpack_from('<f', data, rec + 4)[0],   # sentinel
                    struct.unpack_from('<I', data, rec + 8)[0],   # target
                    struct.unpack_from('<I', data, rec + 12)[0],  # sequence
                )
                trans.append(t)
            best = (j, trans, j, rec_start)
    if best:
        return best[1], best[2], best[3]
    return [], -1, -1


# ---------------------------------------------------------------------------
# Condition block (260-byte) parser
# ---------------------------------------------------------------------------

def find_condition_blocks(data):
    """Find all uniform 260-byte M0%D blocks and non-uniform gaps."""
    m0d_markers = find_all_markers(data)
    blocks = []
    non_uniform = []
    for i in range(len(m0d_markers) - 1):
        gap = m0d_markers[i + 1] - m0d_markers[i]
        off = m0d_markers[i]
        if gap == 260:
            blocks.append((off, data[off:off + 260]))
        else:
            non_uniform.append((i, off, gap))
    # Last marker
    if m0d_markers:
        last = m0d_markers[-1]
        remaining = len(data) - last
        if remaining >= 260:
            blocks.append((last, data[last:last + 260]))
    return blocks, non_uniform, m0d_markers


def extract_block_fields(block):
    """Extract known fields from a 260-byte condition block."""
    return {
        'source_id': struct.unpack_from('<H', block, 212)[0],
        'label_index': block[216],
        'key_code': block[229],
        'opcode_6': block[224:230],
        'opcode_10': block[224:234],
        'target_family': struct.unpack_from('<I', block, 246)[0],
        'flags': block[252:260],
        'byte_80': struct.unpack_from('<H', block, 80)[0],
        'byte_222': block[222],
    }


# ---------------------------------------------------------------------------
# Main weapon parser
# ---------------------------------------------------------------------------

def parse_weapon(paac_path):
    """Parse a weapon .paac file comprehensively."""
    with open(paac_path, 'rb') as f:
        data = f.read()

    name = Path(paac_path).stem
    result = {
        'name': name,
        'path': str(paac_path),
        'size': len(data),
        'data': data,
    }

    # Header
    if len(data) >= 0x44:
        result['node_count'] = struct.unpack_from('<I', data, 0)[0]
        result['speed'] = struct.unpack_from('<f', data, 8)[0]
        result['flags'] = struct.unpack_from('<I', data, 0x18)[0]

    # String table
    st_offset, st_entries = find_string_table(data)
    result['string_table_offset'] = st_offset
    result['string_table'] = st_entries

    # State markers (the inline state machine region: 0x44 to string_table_offset)
    state_markers = find_state_markers(data)
    result['state_markers'] = state_markers

    # Parse states and transitions
    states = []
    for si, m in enumerate(state_markers):
        label_idx = struct.unpack_from('<H', data, m)[0]
        if si + 1 < len(state_markers):
            region_end = state_markers[si + 1] - 2
        else:
            region_end = st_offset if st_offset > m else min(m + 3000, len(data))

        trans, count_off, data_off = find_transitions(data, m, region_end)
        label_name = st_entries[label_idx] if 0 <= label_idx < len(st_entries) else f"idx_{label_idx}"

        states.append({
            'index': si,
            'marker_offset': m,
            'label_idx': label_idx,
            'label_name': label_name,
            'transitions': trans,
            'count_offset': count_off,
        })
    result['states'] = states

    # M0%D condition blocks
    cond_blocks, non_uniform_gaps, m0d_markers = find_condition_blocks(data)
    result['condition_blocks'] = cond_blocks
    result['non_uniform_gaps'] = non_uniform_gaps
    result['m0d_markers'] = m0d_markers

    # Guard label index
    guard_idx = None
    for i, s in enumerate(st_entries):
        if s == 'key_guard':
            guard_idx = i
            break
    result['guard_label_idx'] = guard_idx

    return result


# ===========================================================================
# Analysis sections
# ===========================================================================

def section_1_state_records(weapons):
    """Full State Record Comparison."""
    out("\n" + "=" * 120)
    out("SECTION 1: FULL STATE RECORD COMPARISON")
    out("=" * 120)

    # Classify M0%D markers
    out(f"\n{'Weapon':<22s} {'Size':>8s} {'States':>7s} {'Trans':>7s} {'AvgTr':>6s} "
        f"{'Guard':>6s} {'NoGrd':>6s} {'M0%D':>6s} {'260B':>6s} {'StrTbl':>6s}")
    out("-" * 110)

    for name, w in sorted(weapons.items()):
        states = w['states']
        total_states = len(states)
        total_trans = sum(len(s['transitions']) for s in states)
        avg_trans = total_trans / total_states if total_states else 0

        # Count states with guard transitions (target=0)
        guarded = 0
        unguarded = 0
        for s in states:
            has_guard = any(t[2] == 0 for t in s['transitions'])  # target==0
            if has_guard:
                guarded += 1
            elif s['transitions']:  # has transitions but no guard
                unguarded += 1

        out(f"{name:<22s} {w['size']:>8d} {total_states:>7d} {total_trans:>7d} {avg_trans:>6.1f} "
            f"{guarded:>6d} {unguarded:>6d} {len(w['m0d_markers']):>6d} "
            f"{len(w['condition_blocks']):>6d} {len(w['string_table']):>6d}")


def section_2_inline_transitions(weapons):
    """Inline Transition Diff."""
    out("\n" + "=" * 120)
    out("SECTION 2: INLINE TRANSITION DIFF")
    out("=" * 120)

    for name, w in sorted(weapons.items()):
        states = w['states']
        if not states:
            out(f"\n  {name}: NO states")
            continue

        all_trans = []
        for s in states:
            all_trans.extend(s['transitions'])

        if not all_trans:
            out(f"\n  {name}: {len(states)} states but NO transitions found")
            continue

        # Target distribution
        target_counts = Counter(t[2] for t in all_trans)
        unique_targets = len(target_counts)
        target_0_count = target_counts.get(0, 0)

        # Guard threshold distribution (for transitions targeting node 0)
        guard_thresholds = Counter()
        for t in all_trans:
            if t[2] == 0:
                guard_thresholds[round(t[0], 4)] += 1

        # All threshold distribution
        all_thresholds = Counter(round(t[0], 4) for t in all_trans)

        out(f"\n  {name}: {len(all_trans)} total transitions, {unique_targets} unique targets")
        out(f"    Transitions targeting node 0 (guard/idle): {target_0_count}")
        out(f"    Top 10 target nodes: {dict(target_counts.most_common(10))}")

        if guard_thresholds:
            out(f"    Guard (target=0) threshold distribution:")
            for thresh, cnt in sorted(guard_thresholds.items()):
                out(f"      threshold={thresh:>8.4f}: {cnt} transitions")

        out(f"    All threshold distribution (top 10):")
        for thresh, cnt in all_thresholds.most_common(10):
            out(f"      threshold={thresh:>8.4f}: {cnt} transitions")


def section_3_condition_blocks(weapons):
    """Condition Block Deep Comparison."""
    out("\n" + "=" * 120)
    out("SECTION 3: CONDITION BLOCK DEEP COMPARISON")
    out("=" * 120)

    weapons_with_blocks = {n: w for n, w in weapons.items() if w['condition_blocks']}

    if not weapons_with_blocks:
        out("  No weapons have condition blocks.")
        return

    out(f"\n  Weapons with condition blocks: {', '.join(sorted(weapons_with_blocks.keys()))}")

    # 3a. Cross-tabulate label_index vs key_code per weapon
    out("\n  --- 3a. Label Index vs Key Code Cross-Tabulation ---")

    for name, w in sorted(weapons_with_blocks.items()):
        st = w['string_table']
        blocks = w['condition_blocks']

        out(f"\n  {name} ({len(blocks)} blocks):")

        # Build cross-tab
        crosstab = defaultdict(Counter)
        for off, b in blocks:
            f = extract_block_fields(b)
            li = f['label_index']
            kc = f['key_code']
            label = st[li] if li < len(st) else f"?{li}"
            crosstab[label][kc] += 1

        # Print
        all_kcs = sorted(set(kc for counts in crosstab.values() for kc in counts))
        if not all_kcs:
            continue

        header = f"    {'Label':<30s} | " + " | ".join(f"0x{kc:02X}" for kc in all_kcs) + " | Total"
        out(header)
        out("    " + "-" * (len(header) - 4))
        for label in sorted(crosstab.keys()):
            counts = crosstab[label]
            total = sum(counts.values())
            row = f"    {label:<30s} | " + " | ".join(f"{counts.get(kc, 0):>4d}" for kc in all_kcs) + f" | {total:>5d}"
            out(row)

    # 3b. Do same label indices use same key codes across weapons?
    out("\n  --- 3b. Cross-Weapon Label-KeyCode Consistency ---")

    label_kc_by_weapon = defaultdict(lambda: defaultdict(set))
    for name, w in sorted(weapons_with_blocks.items()):
        st = w['string_table']
        for off, b in w['condition_blocks']:
            f = extract_block_fields(b)
            li = f['label_index']
            label = st[li] if li < len(st) else f"?{li}"
            label_kc_by_weapon[label][name].add(f['key_code'])

    for label in sorted(label_kc_by_weapon.keys()):
        weapon_data = label_kc_by_weapon[label]
        if len(weapon_data) < 2:
            continue
        out(f"\n    Label '{label}':")
        for wname, kcs in sorted(weapon_data.items()):
            out(f"      {wname:<22s}: key_codes = {{{', '.join(f'0x{k:02X}' for k in sorted(kcs))}}}")
        all_kc_sets = list(weapon_data.values())
        if all(s == all_kc_sets[0] for s in all_kc_sets):
            out(f"      -> CONSISTENT across all weapons")
        else:
            out(f"      -> DIFFERS between weapons!")

    # 3c. Guard blocks: opcode and flags comparison
    out("\n  --- 3c. Guard Block Opcode/Flags Cross-Weapon Comparison ---")

    for name, w in sorted(weapons_with_blocks.items()):
        st = w['string_table']
        gi = w['guard_label_idx']
        if gi is None:
            continue

        guard_blocks = [(off, b) for off, b in w['condition_blocks']
                        if b[216] == gi]
        if not guard_blocks:
            continue

        out(f"\n    {name}: {len(guard_blocks)} guard blocks")

        # Opcode distribution
        op_dist = Counter()
        flags_dist = Counter()
        for off, b in guard_blocks:
            f = extract_block_fields(b)
            op_dist[f['opcode_6'].hex()] += 1
            flags_dist[f['flags'].hex()] += 1

        out(f"      Opcode[224:230] distribution ({len(op_dist)} unique):")
        for pat, cnt in op_dist.most_common(10):
            out(f"        {pat}: {cnt}")
        out(f"      Flags[252:260] distribution ({len(flags_dist)} unique):")
        for pat, cnt in flags_dist.most_common(10):
            out(f"        {pat}: {cnt}")


def section_4_byte_level_diff(weapons):
    """260-Byte Block Byte-Level Diff of guard blocks."""
    out("\n" + "=" * 120)
    out("SECTION 4: GUARD BLOCK BYTE-LEVEL DIFF")
    out("=" * 120)

    # Collect guard blocks per weapon
    weapon_guard_blocks = {}
    for name, w in sorted(weapons.items()):
        gi = w['guard_label_idx']
        if gi is None:
            continue
        gblocks = [b for off, b in w['condition_blocks'] if b[216] == gi]
        if gblocks:
            weapon_guard_blocks[name] = gblocks

    if len(weapon_guard_blocks) < 2:
        out("  Need at least 2 weapons with guard blocks for comparison.")
        return

    out(f"\n  Weapons with guard blocks: {', '.join(f'{n}({len(bs)})' for n, bs in sorted(weapon_guard_blocks.items()))}")

    # 4a. Per-weapon: which bytes are fixed vs variable?
    out("\n  --- 4a. Fixed vs Variable Bytes Per Weapon ---")

    weapon_fixed = {}
    weapon_variable = {}

    for name, gblocks in sorted(weapon_guard_blocks.items()):
        fixed_bytes = set(range(260))
        fixed_values = {}

        for pos in range(260):
            vals = set(b[pos] for b in gblocks)
            if len(vals) == 1:
                fixed_values[pos] = vals.pop()
            else:
                fixed_bytes.discard(pos)

        variable_bytes = set(range(260)) - fixed_bytes
        weapon_fixed[name] = (fixed_bytes, fixed_values)
        weapon_variable[name] = variable_bytes

        out(f"\n    {name}: {len(fixed_bytes)} fixed bytes, {len(variable_bytes)} variable bytes")
        if variable_bytes:
            # Group consecutive variable bytes into ranges
            var_sorted = sorted(variable_bytes)
            ranges = []
            start = var_sorted[0]
            end = start
            for v in var_sorted[1:]:
                if v == end + 1:
                    end = v
                else:
                    ranges.append((start, end))
                    start = v
                    end = v
            ranges.append((start, end))
            out(f"      Variable byte ranges: {', '.join(f'{s}-{e}' if s != e else str(s) for s, e in ranges)}")

    # 4b. Cross-weapon: which fixed bytes differ between weapons?
    out("\n  --- 4b. Cross-Weapon Fixed Byte Differences ---")

    wnames = sorted(weapon_guard_blocks.keys())
    # Find bytes fixed in ALL weapons
    common_fixed = set(range(260))
    for name in wnames:
        common_fixed &= weapon_fixed[name][0]

    out(f"\n    Bytes fixed across ALL weapons: {len(common_fixed)} of 260")

    # Among common fixed bytes, which have different values?
    differ_positions = []
    same_positions = []
    for pos in sorted(common_fixed):
        vals = {weapon_fixed[name][1][pos] for name in wnames}
        if len(vals) > 1:
            differ_positions.append(pos)
        else:
            same_positions.append(pos)

    out(f"    Bytes with SAME value across all weapons: {len(same_positions)}")
    out(f"    Bytes with DIFFERENT values between weapons: {len(differ_positions)}")

    if differ_positions:
        out(f"\n    Positions where weapons differ (byte pos: weapon=value):")
        for pos in differ_positions[:50]:
            vals = {name: weapon_fixed[name][1][pos] for name in wnames}
            val_str = ", ".join(f"{n[:10]}=0x{v:02X}" for n, v in sorted(vals.items()))
            out(f"      [{pos:>3d}] {val_str}")
        if len(differ_positions) > 50:
            out(f"      ... and {len(differ_positions) - 50} more positions")

    # 4c. Bytes variable in one weapon but fixed in another
    out("\n  --- 4c. Variable-in-A but Fixed-in-B ---")

    for a in wnames:
        for b in wnames:
            if a >= b:
                continue
            var_a_fixed_b = weapon_variable[a] & weapon_fixed[b][0]
            var_b_fixed_a = weapon_variable[b] & weapon_fixed[a][0]
            if var_a_fixed_b:
                out(f"    Variable in {a} but fixed in {b}: positions {sorted(var_a_fixed_b)[:20]}{'...' if len(var_a_fixed_b) > 20 else ''}")
            if var_b_fixed_a:
                out(f"    Variable in {b} but fixed in {a}: positions {sorted(var_b_fixed_a)[:20]}{'...' if len(var_b_fixed_a) > 20 else ''}")


def section_5_gap_regions(weapons):
    """Gap Region Presence Analysis."""
    out("\n" + "=" * 120)
    out("SECTION 5: GAP REGION PRESENCE ANALYSIS")
    out("=" * 120)

    gap_info = {}
    for name, w in sorted(weapons.items()):
        non_uniform = w['non_uniform_gaps']
        # Filter: skip 16-byte gaps (hash records) and focus on large gaps
        large_gaps = [(i, off, gap) for i, off, gap in non_uniform if gap > 16]
        small_gaps_16 = [(i, off, gap) for i, off, gap in non_uniform if gap == 16]
        other_gaps = [(i, off, gap) for i, off, gap in non_uniform if gap != 16 and gap <= 260]

        total_gap_bytes = sum(gap for _, _, gap in large_gaps)

        gap_info[name] = {
            'large_gaps': large_gaps,
            'small_16': small_gaps_16,
            'other': other_gaps,
            'total_gap_bytes': total_gap_bytes,
        }

        if non_uniform:
            gap_hist = Counter(gap for _, _, gap in non_uniform)
            out(f"\n  {name}: {len(non_uniform)} non-uniform M0%D gaps")
            out(f"    16-byte gaps (hash records): {len(small_gaps_16)}")
            out(f"    Large gaps (>260 bytes): {len(large_gaps)}, total = {total_gap_bytes:,} bytes")
            if large_gaps:
                for idx, off, gap in large_gaps[:10]:
                    out(f"      Marker #{idx} at 0x{off:X}: gap = {gap:,} bytes ({gap/1024:.1f} KB)")
                if len(large_gaps) > 10:
                    out(f"      ... and {len(large_gaps) - 10} more")
            out(f"    Gap size histogram (top 10): {dict(gap_hist.most_common(10))}")
        else:
            out(f"\n  {name}: ZERO non-uniform gaps (all M0%D markers at 260-byte spacing)")

    # Hypothesis: weapons with gap regions = weapons where attack states lack guard
    out("\n  --- Correlation: Gap Regions vs Unguarded States ---")

    out(f"\n  {'Weapon':<22s} {'GapBytes':>10s} {'#LargeGaps':>11s} {'#Unguarded':>11s} {'#Guarded':>9s} {'Has260B':>8s}")
    out("  " + "-" * 80)

    for name, w in sorted(weapons.items()):
        gi = gap_info[name]
        # Count guarded/unguarded states
        guarded = 0
        unguarded = 0
        for s in w['states']:
            has_guard = any(t[2] == 0 for t in s['transitions'])
            if has_guard:
                guarded += 1
            elif s['transitions']:
                unguarded += 1

        has_260 = "YES" if w['condition_blocks'] else "NO"
        out(f"  {name:<22s} {gi['total_gap_bytes']:>10,d} {len(gi['large_gaps']):>11d} "
            f"{unguarded:>11d} {guarded:>9d} {has_260:>8s}")


def section_6_summary(weapons):
    """Guard Mechanism Summary Table."""
    out("\n" + "=" * 120)
    out("SECTION 6: GUARD MECHANISM SUMMARY TABLE")
    out("=" * 120)

    out(f"\n  {'Weapon':<22s} {'GuardMechanism':<50s} {'#Guarded':>9s} {'#Blocked':>9s} "
        f"{'CondBlocks':>11s} {'%Guard':>7s}")
    out("  " + "-" * 120)

    for name, w in sorted(weapons.items()):
        states = w['states']
        blocks = w['condition_blocks']
        gi = w['guard_label_idx']

        # Count guard in inline transitions
        inline_guard_states = sum(1 for s in states if any(t[2] == 0 for t in s['transitions']))
        inline_blocked_states = sum(1 for s in states if s['transitions'] and not any(t[2] == 0 for t in s['transitions']))

        # Count guard in condition blocks
        guard_cond_blocks = sum(1 for off, b in blocks if gi is not None and b[216] == gi)
        total_cond_blocks = len(blocks)
        pct_guard = f"{guard_cond_blocks * 100 / total_cond_blocks:.1f}%" if total_cond_blocks else "N/A"

        # Determine mechanism
        mechanisms = []
        if inline_guard_states > 0:
            mechanisms.append(f"inline transitions ({inline_guard_states} states)")
        if guard_cond_blocks > 0:
            mechanisms.append(f"condition blocks ({guard_cond_blocks})")

        non_uniform = w['non_uniform_gaps']
        large_gaps = sum(1 for _, _, gap in non_uniform if gap > 260)
        if large_gaps > 0:
            mechanisms.append(f"gap regions ({large_gaps})")

        if not mechanisms:
            mechanisms.append("NONE / not present")

        mechanism_str = " + ".join(mechanisms)
        if len(mechanism_str) > 48:
            mechanism_str = mechanism_str[:48] + ".."

        out(f"  {name:<22s} {mechanism_str:<50s} {inline_guard_states:>9d} {inline_blocked_states:>9d} "
            f"{total_cond_blocks:>11d} {pct_guard:>7s}")

    # Additional notes
    out("\n  Key observations:")
    out("  " + "-" * 80)

    # Which weapons have zero condition blocks?
    no_blocks = [n for n, w in weapons.items() if not w['condition_blocks']]
    has_blocks = [n for n, w in weapons.items() if w['condition_blocks']]
    out(f"  Weapons with ZERO condition blocks: {', '.join(sorted(no_blocks))}")
    out(f"  Weapons WITH condition blocks: {', '.join(sorted(has_blocks))}")

    # Which weapons have guard in string table?
    has_guard_label = [n for n, w in weapons.items() if w['guard_label_idx'] is not None]
    no_guard_label = [n for n, w in weapons.items() if w['guard_label_idx'] is None]
    out(f"  Weapons with 'key_guard' in string table: {', '.join(sorted(has_guard_label))}")
    out(f"  Weapons WITHOUT 'key_guard': {', '.join(sorted(no_guard_label))}")


# ===========================================================================
# Main
# ===========================================================================

def main():
    out("=" * 120)
    out("DEEP WEAPON .PAAC STRUCTURAL COMPARISON")
    out(f"Generated by deep_weapon_diff.py")
    out("=" * 120)

    # Find all .paac files
    paac_files = sorted(PAAC_DIR.glob("*_upper.paac")) + sorted(PAAC_DIR.glob("*_hitaction.paac"))
    # Also check for common_skill
    for extra in PAAC_DIR.glob("common_skill*.paac"):
        if extra not in paac_files:
            paac_files.append(extra)

    seen = set()
    unique = []
    for f in paac_files:
        if f.name not in seen:
            seen.add(f.name)
            unique.append(f)

    out(f"\nFound {len(unique)} .paac files in {PAAC_DIR}")
    for f in unique:
        out(f"  {f.name}")

    # Parse all weapons
    weapons = {}
    for f in unique:
        out(f"\nParsing {f.name}...")
        weapons[f.stem] = parse_weapon(str(f))

    # Run all analysis sections
    section_1_state_records(weapons)
    section_2_inline_transitions(weapons)
    section_3_condition_blocks(weapons)
    section_4_byte_level_diff(weapons)
    section_5_gap_regions(weapons)
    section_6_summary(weapons)

    flush_output()


if __name__ == "__main__":
    main()
