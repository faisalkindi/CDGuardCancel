#!/usr/bin/env python3
"""
Reverse-engineer the condition graph section of Crimson Desert .paac files.
Analyzes sword_upper.paac condition section (0x97996 - 0x12FA79).
"""

import struct
import sys
import os
from collections import Counter, defaultdict

SWORD = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
BASIC = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\basic_upper.paac"
OUTPUT = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\condition_graph_analysis.txt"

# Condition section bounds for sword_upper
COND_START = 0x97996
COND_END = 0x12FA79

# Known string table indices
STRING_TABLE = {
    1: "key_guard",
    17: "key_guard_start",
    36: "key_norattack",
    16: "key_hardattack",
    20: "key_cancel",
    15: "key_crouch",
    25: "key_dash",
}

out_lines = []

def log(s=""):
    out_lines.append(s)
    print(s)

def hexdump(data, base_offset, length=None):
    """Classic hex dump with ASCII."""
    if length:
        data = data[:length]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {base_offset+i:08X}: {hex_part:<48s} |{ascii_part}|")
    return "\n".join(lines)

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def main():
    sword_data = read_file(SWORD)
    cond = sword_data[COND_START:COND_END]
    cond_len = len(cond)

    log("=" * 100)
    log("CRIMSON DESERT .PAAC CONDITION GRAPH REVERSE ENGINEERING")
    log("=" * 100)
    log(f"File: sword_upper.paac ({len(sword_data)} bytes)")
    log(f"Condition section: 0x{COND_START:X} - 0x{COND_END:X} ({cond_len} bytes, {cond_len/1024:.1f} KB)")
    log()

    # =========================================================================
    # 1. HEX DUMP FIRST 2KB
    # =========================================================================
    log("=" * 100)
    log("SECTION 1: HEX DUMP OF FIRST 2KB (0x97996 - 0x98196)")
    log("=" * 100)
    log()
    log("--- Raw hex dump ---")
    log(hexdump(cond, COND_START, 2048))
    log()

    log("--- Interpreted values (first 512 bytes) ---")
    log(f"{'Offset':>10s} {'Hex4':>12s} {'uint8':>6s} {'uint16':>8s} {'uint32':>12s} {'int32':>12s} {'float32':>14s}")
    for i in range(0, min(512, cond_len), 4):
        if i + 4 > cond_len:
            break
        b = cond[i:i+4]
        u8 = b[0]
        u16 = struct.unpack_from("<H", b)[0]
        u32 = struct.unpack_from("<I", b)[0]
        i32 = struct.unpack_from("<i", b)[0]
        f32 = struct.unpack_from("<f", b)[0]
        fstr = f"{f32:14.6f}" if abs(f32) < 1e10 and abs(f32) > 1e-10 else f"{f32:14.6e}"
        if f32 == 0.0:
            fstr = "      0.000000"
        log(f"  {COND_START+i:08X} {b.hex().upper():>12s} {u8:6d} {u16:8d} {u32:12d} {i32:12d} {fstr}")
    log()

    # =========================================================================
    # 2. FIND ALL -1.0 SENTINELS
    # =========================================================================
    log("=" * 100)
    log("SECTION 2: -1.0 SENTINEL ANALYSIS (0x0000_80BF little-endian)")
    log("=" * 100)
    log()

    sentinel = b'\x00\x00\x80\xbf'  # -1.0 as LE float32
    sentinel_offsets = []
    pos = 0
    while True:
        idx = cond.find(sentinel, pos)
        if idx == -1:
            break
        sentinel_offsets.append(idx)
        pos = idx + 1

    log(f"Total -1.0 sentinels found: {len(sentinel_offsets)}")
    log()

    # Show first 50 with file offsets
    log("First 50 sentinel positions (section-relative and file-absolute):")
    for i, off in enumerate(sentinel_offsets[:50]):
        log(f"  [{i:4d}] section+0x{off:06X}  file@0x{COND_START+off:08X}")
    log()

    # Distances between sentinels
    if len(sentinel_offsets) > 1:
        distances = [sentinel_offsets[i+1] - sentinel_offsets[i] for i in range(len(sentinel_offsets)-1)]
        dist_counter = Counter(distances)
        log("Inter-sentinel distance histogram (distance -> count):")
        for dist, cnt in sorted(dist_counter.items(), key=lambda x: -x[1])[:40]:
            bar = "#" * min(cnt, 80)
            log(f"  {dist:6d} bytes ({dist:5d}): {cnt:5d} {bar}")
        log()
        log(f"Min distance: {min(distances)}, Max distance: {max(distances)}, Mean: {sum(distances)/len(distances):.1f}")
        log()

        # Show distances that are multiples of 4
        log("Distances that are multiples of 4:")
        for dist, cnt in sorted(dist_counter.items(), key=lambda x: -x[1])[:20]:
            if dist % 4 == 0:
                log(f"  {dist:6d} bytes = {dist//4} dwords: {cnt} occurrences")
        log()

    # Context around first 10 sentinels
    log("Context around first 20 sentinels (32 bytes before, 32 bytes after):")
    for i, off in enumerate(sentinel_offsets[:20]):
        start = max(0, off - 32)
        end = min(cond_len, off + 4 + 32)
        log(f"\n  --- Sentinel [{i}] at section+0x{off:06X} (file@0x{COND_START+off:08X}) ---")
        log(hexdump(cond[start:end], COND_START + start))
        # Also interpret as dwords around the sentinel
        align_start = (off // 4) * 4
        dw_start = max(0, align_start - 32)
        dw_end = min(cond_len, align_start + 36)
        log(f"  Interpreted as dwords around sentinel:")
        for j in range(dw_start, dw_end, 4):
            if j + 4 > cond_len:
                break
            val = struct.unpack_from("<I", cond, j)[0]
            fval = struct.unpack_from("<f", cond, j)[0]
            marker = " <-- SENTINEL" if j == off else ""
            fstr = f"{fval:.6f}" if abs(fval) < 1e8 else f"{fval:.2e}"
            if fval == 0.0:
                fstr = "0.0"
            log(f"    +0x{j:06X}: 0x{val:08X}  uint32={val:10d}  float={fstr}{marker}")
    log()

    # =========================================================================
    # 3. FIND ALL 50.0 MARKERS
    # =========================================================================
    log("=" * 100)
    log("SECTION 3: 50.0 MARKER ANALYSIS (0x0000_4842)")
    log("=" * 100)
    log()

    marker_50 = b'\x00\x00\x48\x42'  # 50.0 as LE float32
    marker_offsets = []
    pos = 0
    while True:
        idx = cond.find(marker_50, pos)
        if idx == -1:
            break
        marker_offsets.append(idx)
        pos = idx + 1

    log(f"Total 50.0 markers found: {len(marker_offsets)}")
    log()

    if marker_offsets:
        log("All 50.0 marker positions:")
        for i, off in enumerate(marker_offsets):
            log(f"  [{i:4d}] section+0x{off:06X}  file@0x{COND_START+off:08X}")
        log()

        if len(marker_offsets) > 1:
            m_distances = [marker_offsets[i+1] - marker_offsets[i] for i in range(len(marker_offsets)-1)]
            m_dist_counter = Counter(m_distances)
            log("Inter-50.0 distance histogram:")
            for dist, cnt in sorted(m_dist_counter.items(), key=lambda x: -x[1])[:30]:
                log(f"  {dist:6d} bytes: {cnt:5d}")
            log()

        # Context around first 10
        log("Context around first 10 of 50.0 markers:")
        for i, off in enumerate(marker_offsets[:10]):
            start = max(0, off - 32)
            end = min(cond_len, off + 4 + 32)
            log(f"\n  --- 50.0 [{i}] at section+0x{off:06X} (file@0x{COND_START+off:08X}) ---")
            log(hexdump(cond[start:end], COND_START + start))
    log()

    # =========================================================================
    # 4. STRING TABLE INDEX REFERENCES
    # =========================================================================
    log("=" * 100)
    log("SECTION 4: STRING TABLE INDEX REFERENCES")
    log("=" * 100)
    log()

    # Search for uint16 values matching known string indices
    for idx, name in sorted(STRING_TABLE.items()):
        log(f"--- Searching for string index {idx} ({name}) as uint16 ---")
        matches = []
        for i in range(0, cond_len - 1):
            val = struct.unpack_from("<H", cond, i)[0]
            if val == idx:
                # Check if this looks like a deliberate reference (not random byte)
                # Only report at even offsets (aligned) or where context looks structured
                matches.append(i)

        # Filter to 4-byte aligned positions first
        aligned = [m for m in matches if m % 4 == 0]
        # Also check 2-byte aligned
        aligned2 = [m for m in matches if m % 2 == 0]

        log(f"  Total uint16 matches: {len(matches)}")
        log(f"  4-byte aligned: {len(aligned)}")
        log(f"  2-byte aligned: {len(aligned2)}")

        # Show first 10 aligned matches with context
        show = aligned[:10] if aligned else matches[:5]
        for m in show:
            start = max(0, m - 16)
            end = min(cond_len, m + 16)
            log(f"  Match at section+0x{m:06X} (file@0x{COND_START+m:08X}):")
            log(hexdump(cond[start:end], COND_START + start))
        log()

    # Also search as uint32
    log("--- Searching key indices as uint32 ---")
    for idx, name in sorted(STRING_TABLE.items()):
        target = struct.pack("<I", idx)
        matches = []
        pos = 0
        while True:
            p = cond.find(target, pos)
            if p == -1:
                break
            if p % 4 == 0:  # Only aligned
                matches.append(p)
            pos = p + 1
        log(f"  {name} (idx={idx}): {len(matches)} aligned uint32 matches")
        # Show first 5 with context
        for m in matches[:5]:
            start = max(0, m - 24)
            end = min(cond_len, m + 24)
            log(f"    At section+0x{m:06X}:")
            # Interpret as dwords
            for j in range(start - start%4, end, 4):
                if j + 4 > cond_len:
                    break
                val = struct.unpack_from("<I", cond, j)[0]
                fval = struct.unpack_from("<f", cond, j)[0]
                marker = " <-- TARGET" if j == m else ""
                fstr = f"{fval:.4f}" if abs(fval) < 1e8 else f"{fval:.2e}"
                log(f"      +0x{j:06X}: 0x{val:08X}  u32={val:6d}  f32={fstr}{marker}")
        log()

    # =========================================================================
    # 5. BASIC_UPPER.PAAC COMPARISON
    # =========================================================================
    log("=" * 100)
    log("SECTION 5: BASIC_UPPER.PAAC COMPARISON")
    log("=" * 100)
    log()

    basic_data = read_file(BASIC)
    log(f"basic_upper.paac size: {len(basic_data)} bytes (0x{len(basic_data):X})")
    log()

    # Find the condition section in basic_upper by searching for patterns
    # First, let's look at its header
    log("basic_upper.paac header (first 128 bytes):")
    log(hexdump(basic_data, 0, 128))
    log()

    # Interpret header as dwords
    log("Header as uint32s:")
    for i in range(0, min(128, len(basic_data)), 4):
        val = struct.unpack_from("<I", basic_data, i)[0]
        fval = struct.unpack_from("<f", basic_data, i)[0]
        fstr = f"{fval:.4f}" if abs(fval) < 1e8 and fval != 0 else f"{fval}"
        log(f"  +0x{i:04X}: 0x{val:08X}  u32={val:8d}  f32={fstr}")
    log()

    # Find all -1.0 sentinels in basic
    basic_sentinels = []
    pos = 0
    while True:
        idx = basic_data.find(sentinel, pos)
        if idx == -1:
            break
        basic_sentinels.append(idx)
        pos = idx + 1
    log(f"Total -1.0 sentinels in basic_upper: {len(basic_sentinels)}")

    # Find all 50.0 markers in basic
    basic_50s = []
    pos = 0
    while True:
        idx = basic_data.find(marker_50, pos)
        if idx == -1:
            break
        basic_50s.append(idx)
        pos = idx + 1
    log(f"Total 50.0 markers in basic_upper: {len(basic_50s)}")
    log()

    # Find where state section likely ends in basic
    # Look for the last 50.0 marker cluster vs scattered ones
    if basic_50s:
        log("50.0 marker distribution in basic_upper:")
        for i, off in enumerate(basic_50s):
            pct = off * 100.0 / len(basic_data)
            log(f"  [{i:3d}] offset 0x{off:06X} ({pct:.1f}%)")
        log()

    # Compare the start of what might be the condition section
    # Let's look at the last quarter of basic_upper
    basic_tail_start = len(basic_data) * 3 // 4
    log(f"basic_upper tail section (starting ~75% = 0x{basic_tail_start:X}):")
    log(f"First 512 bytes of tail:")
    log(hexdump(basic_data[basic_tail_start:], basic_tail_start, 512))
    log()

    # =========================================================================
    # 6. NODE BOUNDARY SEARCH
    # =========================================================================
    log("=" * 100)
    log("SECTION 6: NODE BOUNDARY SEARCH (looking for 104 missing nodes)")
    log("=" * 100)
    log()

    # Look for repeating patterns at regular intervals
    # Try various candidate record sizes
    log("Searching for repeating structural patterns...")
    log()

    # Method 1: Look for common byte patterns at regular intervals
    # Check if the section starts with a count field
    log("First 64 bytes interpreted as various types:")
    for i in range(0, 64, 4):
        if i + 8 > cond_len:
            break
        u32 = struct.unpack_from("<I", cond, i)[0]
        f32 = struct.unpack_from("<f", cond, i)[0]
        u16a = struct.unpack_from("<H", cond, i)[0]
        u16b = struct.unpack_from("<H", cond, i+2)[0]
        log(f"  +0x{i:04X}: u32={u32:10d}  f32={f32:12.4f}  u16pair=({u16a}, {u16b})")
    log()

    # Method 2: Look for 0x00000000 runs that might separate records
    log("Searching for zero-dword runs (potential record separators)...")
    zero_runs = []
    i = 0
    while i < cond_len - 3:
        if cond[i:i+4] == b'\x00\x00\x00\x00':
            run_start = i
            while i < cond_len - 3 and cond[i:i+4] == b'\x00\x00\x00\x00':
                i += 4
            run_len = i - run_start
            if run_len >= 8:  # At least 2 consecutive zero dwords
                zero_runs.append((run_start, run_len))
        else:
            i += 1

    log(f"Found {len(zero_runs)} zero-dword runs (>=8 bytes):")
    for start, length in zero_runs[:30]:
        log(f"  section+0x{start:06X} (file@0x{COND_START+start:08X}): {length} bytes of zeros")
    log()

    # Method 3: Look for specific uint32 values that could be node counts or IDs
    # 104 nodes, 721 total, 617 inline
    for search_val in [104, 721, 617, 467]:
        target = struct.pack("<I", search_val)
        positions = []
        pos = 0
        while True:
            p = cond.find(target, pos)
            if p == -1:
                break
            if p % 4 == 0:
                positions.append(p)
            pos = p + 1
        if positions:
            log(f"Value {search_val} as aligned uint32: found at {len(positions)} positions")
            for p in positions[:5]:
                log(f"  section+0x{p:06X}")

    log()

    # Method 4: Try to find record boundaries by looking at the sentinel pattern
    # If transitions are [threshold, -1.0, target, sequence], sentinels at offset+4 in each record
    log("Analyzing sentinel alignment patterns...")
    sentinel_mod4 = Counter(off % 4 for off in sentinel_offsets)
    sentinel_mod8 = Counter(off % 8 for off in sentinel_offsets)
    sentinel_mod16 = Counter(off % 16 for off in sentinel_offsets)
    log(f"  Sentinel offset mod 4: {dict(sorted(sentinel_mod4.items()))}")
    log(f"  Sentinel offset mod 8: {dict(sorted(sentinel_mod8.items()))}")
    log(f"  Sentinel offset mod 16: {dict(sorted(sentinel_mod16.items()))}")
    log()

    # =========================================================================
    # 7. GUARD-RELATED PATTERN SEARCH
    # =========================================================================
    log("=" * 100)
    log("SECTION 7: GUARD-RELATED PATTERNS")
    log("=" * 100)
    log()

    # Search for guard state (index 0) as uint32 target
    log("--- State index 0 (guard) as uint32 target near sentinels ---")
    zero_target = b'\x00\x00\x00\x00'
    # Look for pattern: [float32] [0xBF800000] [0x00000000] [uint32]
    # i.e., sentinel followed by zero (target state 0 = guard)
    pattern_matches = []
    for s_off in sentinel_offsets:
        if s_off + 8 <= cond_len:
            next_dword = struct.unpack_from("<I", cond, s_off + 4)[0]
            if next_dword == 0:
                pattern_matches.append(s_off)

    log(f"Sentinels followed by uint32(0): {len(pattern_matches)}")
    for m in pattern_matches[:10]:
        start = max(0, m - 32)
        end = min(cond_len, m + 36)
        log(f"\n  At section+0x{m:06X}:")
        for j in range(start - start%4, end, 4):
            if j + 4 > cond_len:
                break
            val = struct.unpack_from("<I", cond, j)[0]
            fval = struct.unpack_from("<f", cond, j)[0]
            marker = ""
            if j == m: marker = " <-- -1.0 SENTINEL"
            elif j == m + 4: marker = " <-- ZERO (guard state?)"
            fstr = f"{fval:.4f}" if abs(fval) < 1e8 else f"{fval:.2e}"
            log(f"    +0x{j:06X}: 0x{val:08X}  u32={val:6d}  f32={fstr}{marker}")
    log()

    # Search for key_guard (1) and key_guard_start (17) near each other
    log("--- Looking for key_guard(1) and key_guard_start(17) proximity ---")
    # Find all uint32(1) positions
    val1_positions = []
    for i in range(0, cond_len - 3, 4):
        if struct.unpack_from("<I", cond, i)[0] == 1:
            val1_positions.append(i)

    val17_positions = []
    for i in range(0, cond_len - 3, 4):
        if struct.unpack_from("<I", cond, i)[0] == 17:
            val17_positions.append(i)

    log(f"uint32(1) aligned positions: {len(val1_positions)}")
    log(f"uint32(17) aligned positions: {len(val17_positions)}")

    # Find pairs within 64 bytes of each other
    nearby_pairs = []
    for p1 in val1_positions:
        for p17 in val17_positions:
            if abs(p1 - p17) <= 64:
                nearby_pairs.append((p1, p17))

    log(f"Pairs of uint32(1) and uint32(17) within 64 bytes: {len(nearby_pairs)}")
    for p1, p17 in nearby_pairs[:10]:
        start = max(0, min(p1, p17) - 32)
        end = min(cond_len, max(p1, p17) + 36)
        log(f"\n  val(1)@+0x{p1:06X}, val(17)@+0x{p17:06X}:")
        for j in range(start - start%4, end, 4):
            if j + 4 > cond_len:
                break
            val = struct.unpack_from("<I", cond, j)[0]
            fval = struct.unpack_from("<f", cond, j)[0]
            marker = ""
            if j == p1: marker = " <-- uint32(1) key_guard?"
            if j == p17: marker = " <-- uint32(17) key_guard_start?"
            fstr = f"{fval:.4f}" if abs(fval) < 1e8 else f"{fval:.2e}"
            log(f"    +0x{j:06X}: 0x{val:08X}  u32={val:6d}  f32={fstr}{marker}")
    log()

    # =========================================================================
    # 8. RECORD FORMAT IDENTIFICATION
    # =========================================================================
    log("=" * 100)
    log("SECTION 8: RECORD FORMAT IDENTIFICATION")
    log("=" * 100)
    log()

    # Use the most common sentinel distance as record size
    if len(sentinel_offsets) > 1:
        distances = [sentinel_offsets[i+1] - sentinel_offsets[i] for i in range(len(sentinel_offsets)-1)]
        top_distances = Counter(distances).most_common(10)

        log("Top 10 most common inter-sentinel distances:")
        for dist, cnt in top_distances:
            log(f"  {dist} bytes ({dist//4} dwords): {cnt} occurrences")
        log()

        # For the most common distance, show aligned records
        most_common_dist = top_distances[0][0]
        log(f"Analyzing records with most common distance: {most_common_dist} bytes")
        log()

        # Find consecutive sentinels at this distance
        log(f"First 20 records with distance={most_common_dist}:")
        shown = 0
        for i in range(len(sentinel_offsets) - 1):
            if sentinel_offsets[i+1] - sentinel_offsets[i] == most_common_dist:
                off = sentinel_offsets[i]
                record = cond[off:off+most_common_dist]
                log(f"\n  Record at section+0x{off:06X}:")
                log(hexdump(record, COND_START + off))
                # Interpret as dwords
                log(f"  As dwords:")
                for j in range(0, most_common_dist, 4):
                    if j + 4 > len(record):
                        break
                    val = struct.unpack_from("<I", record, j)[0]
                    fval = struct.unpack_from("<f", record, j)[0]
                    fstr = f"{fval:.4f}" if abs(fval) < 1e8 else f"{fval:.2e}"
                    log(f"    field[{j//4}] +{j:2d}: 0x{val:08X}  u32={val:6d}  f32={fstr}")
                shown += 1
                if shown >= 20:
                    break
        log()

        # Also check second most common
        if len(top_distances) > 1:
            second_dist = top_distances[1][0]
            log(f"First 10 records with distance={second_dist} (second most common):")
            shown = 0
            for i in range(len(sentinel_offsets) - 1):
                if sentinel_offsets[i+1] - sentinel_offsets[i] == second_dist:
                    off = sentinel_offsets[i]
                    end = min(off + second_dist, cond_len)
                    record = cond[off:end]
                    log(f"\n  Record at section+0x{off:06X}:")
                    log(hexdump(record, COND_START + off))
                    log(f"  As dwords:")
                    for j in range(0, min(second_dist, len(record)), 4):
                        if j + 4 > len(record):
                            break
                        val = struct.unpack_from("<I", record, j)[0]
                        fval = struct.unpack_from("<f", record, j)[0]
                        fstr = f"{fval:.4f}" if abs(fval) < 1e8 else f"{fval:.2e}"
                        log(f"    field[{j//4}] +{j:2d}: 0x{val:08X}  u32={val:6d}  f32={fstr}")
                    shown += 1
                    if shown >= 10:
                        break
            log()

    # =========================================================================
    # ADDITIONAL: Byte frequency analysis of first 256 bytes
    # =========================================================================
    log("=" * 100)
    log("ADDITIONAL: STRUCTURAL ANALYSIS")
    log("=" * 100)
    log()

    # Look for any ASCII strings in the condition section
    log("Searching for ASCII strings (>=4 chars) in condition section...")
    strings_found = []
    i = 0
    while i < cond_len:
        if 32 <= cond[i] < 127:
            j = i
            while j < cond_len and 32 <= cond[j] < 127:
                j += 1
            if j - i >= 4:
                s = cond[i:j].decode('ascii')
                strings_found.append((i, s))
            i = j
        else:
            i += 1

    log(f"Found {len(strings_found)} ASCII strings:")
    for off, s in strings_found[:50]:
        log(f"  section+0x{off:06X}: \"{s}\"")
    log()

    # Look for common float values
    log("Float value frequency in condition section (4-byte aligned):")
    float_counter = Counter()
    for i in range(0, cond_len - 3, 4):
        fval = struct.unpack_from("<f", cond, i)[0]
        if abs(fval) < 1e10:  # reasonable float range
            # Round to avoid floating point noise
            rounded = round(fval, 4)
            float_counter[rounded] += 1

    log("Top 40 most common float values:")
    for val, cnt in float_counter.most_common(40):
        log(f"  {val:12.4f}: {cnt:5d} occurrences")
    log()

    # uint32 value frequency
    log("uint32 value frequency (4-byte aligned, values 0-1000):")
    u32_counter = Counter()
    for i in range(0, cond_len - 3, 4):
        val = struct.unpack_from("<I", cond, i)[0]
        if val <= 1000:
            u32_counter[val] += 1

    log("Top 40 most common small uint32 values:")
    for val, cnt in u32_counter.most_common(40):
        log(f"  {val:6d} (0x{val:04X}): {cnt:5d} occurrences")
    log()

    # =========================================================================
    # Look for transition-like patterns: [threshold_float, -1.0, target_uint32, seq_uint32]
    # =========================================================================
    log("=" * 100)
    log("TRANSITION PATTERN SEARCH: [float, -1.0, uint32_target, uint32_seq]")
    log("=" * 100)
    log()

    transition_like = []
    for s_off in sentinel_offsets:
        if s_off >= 4 and s_off + 12 <= cond_len:
            threshold = struct.unpack_from("<f", cond, s_off - 4)[0]
            target = struct.unpack_from("<I", cond, s_off + 4)[0]
            seq = struct.unpack_from("<I", cond, s_off + 8)[0]
            if 0 <= threshold <= 1.0 and target < 721 and seq < 10000:
                transition_like.append((s_off, threshold, target, seq))

    log(f"Transition-like patterns found: {len(transition_like)}")
    log("First 30:")
    for s_off, threshold, target, seq in transition_like[:30]:
        log(f"  sentinel@+0x{s_off:06X}: threshold={threshold:.4f}, target_state={target}, seq={seq}")
    log()

    # Target state frequency in these transitions
    if transition_like:
        target_counter = Counter(t[2] for t in transition_like)
        log("Target state frequency in transition-like patterns:")
        for val, cnt in target_counter.most_common(30):
            log(f"  state {val:4d}: {cnt:4d} transitions")
        log()

    # =========================================================================
    # Look for a different record structure: variable-length records with length prefix
    # =========================================================================
    log("=" * 100)
    log("VARIABLE-LENGTH RECORD SEARCH")
    log("=" * 100)
    log()

    # Check if the section starts with a count, then records
    # Try first 4 bytes as count
    first_u32 = struct.unpack_from("<I", cond, 0)[0]
    log(f"First uint32: {first_u32}")

    # If first value is a count, second might be a record size or first record
    if first_u32 < 100000:
        log(f"Could be a count of {first_u32} items")
        # Check if dividing remaining length by count gives reasonable record size
        remaining = cond_len - 4
        if first_u32 > 0:
            avg_size = remaining / first_u32
            log(f"Average record size if count: {avg_size:.1f} bytes")
    log()

    # Try reading as: [uint32 count] then [variable records]
    # Each record might start with a type tag or length
    log("Trying to parse as length-prefixed records from offset 0...")
    offset = 0
    records_found = 0
    record_sizes = []

    # Try: first dword is record count
    if first_u32 < 50000:
        offset = 4
        for rec_i in range(min(first_u32, 20)):
            if offset + 4 > cond_len:
                break
            # Try: each record starts with a uint32 length
            rec_len = struct.unpack_from("<I", cond, offset)[0]
            if rec_len > 0 and rec_len < 10000:
                log(f"  Record {rec_i}: offset=+0x{offset:06X}, claimed_length={rec_len}")
                record_sizes.append(rec_len)
                # Show first few bytes of this record
                show_len = min(rec_len + 4, 64)
                log(hexdump(cond[offset:offset+show_len], COND_START + offset))
                offset += 4 + rec_len
                records_found += 1
            else:
                log(f"  Record {rec_i}: offset=+0x{offset:06X}, value={rec_len} (too large, stopping)")
                break
    log()

    # =========================================================================
    # LOOK FOR BLOCK STRUCTURE: sections with sub-counts
    # =========================================================================
    log("=" * 100)
    log("BLOCK STRUCTURE SEARCH")
    log("=" * 100)
    log()

    # Try to find if the section is organized as:
    # [node_id, transition_count, transition_data...]
    # Look for small values (0-721) followed by small values (0-50) at regular patterns

    log("Scanning for [state_id (0-720), trans_count (1-50)] pairs at 4-byte aligned offsets...")
    candidate_headers = []
    for i in range(0, min(cond_len - 8, 4096), 4):  # Scan first 4KB
        val1 = struct.unpack_from("<I", cond, i)[0]
        val2 = struct.unpack_from("<I", cond, i + 4)[0]
        if 0 <= val1 <= 720 and 1 <= val2 <= 50:
            candidate_headers.append((i, val1, val2))

    log(f"Found {len(candidate_headers)} candidate [state_id, count] pairs in first 4KB:")
    for off, sid, cnt in candidate_headers[:30]:
        # Show context
        log(f"  +0x{off:06X}: state_id={sid}, count={cnt}")
        # Show next few dwords
        ctx = ""
        for j in range(off, min(off + 32, cond_len), 4):
            val = struct.unpack_from("<I", cond, j)[0]
            ctx += f" {val}"
        log(f"    next dwords:{ctx}")
    log()

    # =========================================================================
    # FINAL: Dump specific interesting regions
    # =========================================================================
    log("=" * 100)
    log("FINAL: KEY REGION DUMPS")
    log("=" * 100)
    log()

    # Dump last 256 bytes of condition section
    log("Last 256 bytes of condition section:")
    tail_start = max(0, cond_len - 256)
    log(hexdump(cond[tail_start:], COND_START + tail_start))
    log()

    # Dump bytes around the 25% mark
    mark_25 = cond_len // 4
    log(f"Bytes around 25% mark (section+0x{mark_25:06X}):")
    log(hexdump(cond[mark_25:mark_25+128], COND_START + mark_25))
    log()

    # Dump bytes around the 50% mark
    mark_50 = cond_len // 2
    log(f"Bytes around 50% mark (section+0x{mark_50:06X}):")
    log(hexdump(cond[mark_50:mark_50+128], COND_START + mark_50))
    log()

    # =========================================================================
    # Save output
    # =========================================================================
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    print(f"\n\nResults saved to {OUTPUT}")
    print(f"Total output: {len(out_lines)} lines")

if __name__ == "__main__":
    main()
