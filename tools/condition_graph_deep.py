#!/usr/bin/env python3
"""
Deep reverse engineering of the condition graph section of Crimson Desert .paac files.
Builds on initial analysis findings:
  - Section is NOT 4-byte aligned (starts at 0x97996, which is ...6)
  - Repeating block pattern with magic bytes: 82F58FEF, 6D678102, "M0%D", FFFF7F7F
  - -1.0 sentinels (0x0000_80BF) appear 8543 times with common gaps 4,52,12,8,128,40,16
  - 256 (0x100) appears 3270 times as uint32 - likely a struct field
  - 641 (0x281) appears 322 times - suspicious
"""

import struct
import sys
import os
from collections import Counter, defaultdict

SWORD = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
BASIC = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\basic_upper.paac"
OUTPUT = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\condition_graph_analysis.txt"

COND_START = 0x97996
COND_END = 0x12FA79

# Full string table from prior analysis
STRING_TABLE = {
    0: "key_guard",  # Need to verify index 0 vs 1
    1: "key_guard",
    15: "key_crouch",
    16: "key_hardattack",
    17: "key_guard_start",
    20: "key_cancel",
    25: "key_dash",
    36: "key_norattack",
}

out_lines = []

def log(s=""):
    out_lines.append(s)
    print(s)

def hexdump(data, base_offset, length=None):
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

def interpret_dwords(data, base_off, start, end):
    """Interpret aligned dwords in a range."""
    lines = []
    for j in range(start, min(end, len(data)), 4):
        if j + 4 > len(data):
            break
        val = struct.unpack_from("<I", data, j)[0]
        fval = struct.unpack_from("<f", data, j)[0]
        fstr = f"{fval:.4f}" if abs(fval) < 1e8 and fval != 0 else f"{fval}"
        if abs(fval) >= 1e8:
            fstr = f"{fval:.2e}"
        lines.append(f"    +0x{j:06X} (file 0x{base_off+j:08X}): 0x{val:08X}  u32={val:6d}  f32={fstr}")
    return "\n".join(lines)


def main():
    sword_data = read_file(SWORD)
    cond = sword_data[COND_START:COND_END]
    cond_len = len(cond)

    log("=" * 120)
    log("CRIMSON DESERT .PAAC CONDITION GRAPH — DEEP REVERSE ENGINEERING")
    log("=" * 120)
    log(f"File: sword_upper.paac ({len(sword_data)} bytes)")
    log(f"Condition section: 0x{COND_START:X} - 0x{COND_END:X} ({cond_len} bytes, {cond_len/1024:.1f} KB)")
    log(f"Note: section starts at byte ...6 (NOT 4-byte aligned)")
    log()

    # ==========================================================================
    # SECTION 1: REPEATING MAGIC PATTERN ANALYSIS
    # ==========================================================================
    log("=" * 120)
    log("SECTION 1: REPEATING MAGIC PATTERN ANALYSIS")
    log("=" * 120)
    log()

    # From hex dump, we see repeating blocks containing these magic bytes:
    # 82 F5 8F EF  (as float = -4.0204..e29, as uint32 = 0xEF8FF582)
    # 6D 67 81 02  (as uint32 = 0x0281676D = 41911149)
    # "M0%D"       (0x44253044 / 0x4D302544)
    # FF FF 7F 7F  (as float = 3.4028..e38 = FLT_MAX, as uint32 = 0x7F7FFFFF)

    magic_ef = b'\x82\xF5\x8F\xEF'
    magic_mg = b'\x6D\x67\x81\x02'  # "mg.." = 0x0281676D
    magic_m0 = b'\x4D\x30\x25\x44'  # "M0%D"
    magic_fltmax = b'\xFF\xFF\x7F\x7F'  # FLT_MAX

    for name, pattern in [("0xEF8FF582", magic_ef), ("0x0281676D (mg..)", magic_mg),
                           ("M0%D", magic_m0), ("FLT_MAX (7F7FFFFF)", magic_fltmax)]:
        offsets = []
        pos = 0
        while True:
            idx = cond.find(pattern, pos)
            if idx == -1:
                break
            offsets.append(idx)
            pos = idx + 1
        log(f"Magic {name}: {len(offsets)} occurrences")
        if offsets:
            # Show first 10
            for i, off in enumerate(offsets[:10]):
                log(f"  [{i:3d}] section+0x{off:06X} (file 0x{COND_START+off:08X})")
            if len(offsets) > 10:
                log(f"  ... and {len(offsets)-10} more")
            # Inter-distances
            if len(offsets) > 1:
                dists = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
                dc = Counter(dists)
                log(f"  Inter-occurrence distances (top 10): {dc.most_common(10)}")
        log()

    # ==========================================================================
    # SECTION 2: BLOCK BOUNDARY DETECTION
    # The hex dump shows clear repeating blocks. Let's find them precisely.
    # Pattern observed: each block seems to contain "M0%D" exactly once.
    # ==========================================================================
    log("=" * 120)
    log("SECTION 2: BLOCK BOUNDARY DETECTION (using M0%D marker)")
    log("=" * 120)
    log()

    m0_offsets = []
    pos = 0
    while True:
        idx = cond.find(magic_m0, pos)
        if idx == -1:
            break
        m0_offsets.append(idx)
        pos = idx + 1

    log(f"Found {len(m0_offsets)} M0%D markers")
    if m0_offsets:
        dists = [m0_offsets[i+1] - m0_offsets[i] for i in range(len(m0_offsets)-1)]
        dc = Counter(dists)
        log(f"Inter-M0%D distances: {dc.most_common(20)}")
        log(f"Min: {min(dists)}, Max: {max(dists)}, Mean: {sum(dists)/len(dists):.1f}")
        log()

        # Show first 20 blocks with their M0%D offset and what's around them
        log("First 30 M0%D markers with ±80 byte context (as dwords):")
        for i, off in enumerate(m0_offsets[:30]):
            block_size = dists[i] if i < len(dists) else 0
            log(f"\n  --- M0%D #{i} at section+0x{off:06X} (file 0x{COND_START+off:08X}), "
                f"next block in {block_size} bytes ---")
            # Show raw hex ±40 bytes
            start = max(0, off - 40)
            end = min(cond_len, off + 40)
            log(hexdump(cond[start:end], COND_START + start))
        log()

    # ==========================================================================
    # SECTION 3: BLOCK STRUCTURE — PRECISE FIELD MAPPING
    # Let's align blocks to M0%D and look at fixed offsets relative to it
    # ==========================================================================
    log("=" * 120)
    log("SECTION 3: BLOCK FIELD MAPPING (relative to M0%D)")
    log("=" * 120)
    log()

    if m0_offsets:
        # For each M0%D, dump the block from -128 to +64 as interpreted fields
        log("Field values at fixed offsets relative to M0%D (first 30 blocks):")
        log()

        # First, let's find what offset M0%D is at within each block
        # Check bytes immediately after M0%D
        log("Bytes at M0%D+4 to M0%D+16 for first 30 blocks:")
        for i, off in enumerate(m0_offsets[:30]):
            if off + 16 <= cond_len:
                after = cond[off+4:off+16]
                log(f"  Block {i:3d}: {after.hex(' ').upper()}")
        log()

        # Now check common fields at negative offsets from M0%D
        # The consistent pattern from the hex dump shows:
        # -128 or so: 82 F5 8F EF
        # -80 or so: 00 00 80 BF (sentinel)
        # -64 or so: FF FF 7F 7F (FLT_MAX)
        # -48: 17 00 00 00 (= 23 decimal? or string index 17?)
        # -32: 6D 67 81 02

        # Let's measure the distance from each magic to the nearest M0%D
        log("Distance from 0xEF8FF582 to nearest following M0%D:")
        ef_offsets = []
        pos = 0
        while True:
            idx = cond.find(magic_ef, pos)
            if idx == -1:
                break
            ef_offsets.append(idx)
            pos = idx + 1

        ef_to_m0_dists = []
        for ef_off in ef_offsets[:100]:
            # Find next M0%D after this
            for m0_off in m0_offsets:
                if m0_off > ef_off:
                    ef_to_m0_dists.append(m0_off - ef_off)
                    break
        if ef_to_m0_dists:
            dc = Counter(ef_to_m0_dists)
            log(f"  Distance histogram: {dc.most_common(10)}")
        log()

        log("Distance from 0x0281676D to nearest following M0%D:")
        mg_offsets = []
        pos = 0
        while True:
            idx = cond.find(magic_mg, pos)
            if idx == -1:
                break
            mg_offsets.append(idx)
            pos = idx + 1

        mg_to_m0_dists = []
        for mg_off in mg_offsets[:100]:
            for m0_off in m0_offsets:
                if m0_off > mg_off:
                    mg_to_m0_dists.append(m0_off - mg_off)
                    break
        if mg_to_m0_dists:
            dc = Counter(mg_to_m0_dists)
            log(f"  Distance histogram: {dc.most_common(10)}")
        log()

        log("Distance from FLT_MAX to nearest following M0%D:")
        fm_offsets = []
        pos = 0
        while True:
            idx = cond.find(magic_fltmax, pos)
            if idx == -1:
                break
            fm_offsets.append(idx)
            pos = idx + 1

        fm_to_m0_dists = []
        for fm_off in fm_offsets[:200]:
            for m0_off in m0_offsets:
                if m0_off > fm_off:
                    fm_to_m0_dists.append(m0_off - fm_off)
                    break
        if fm_to_m0_dists:
            dc = Counter(fm_to_m0_dists)
            log(f"  Distance histogram: {dc.most_common(10)}")
        log()

    # ==========================================================================
    # SECTION 4: IDENTIFY THE FIXED-SIZE BLOCK TEMPLATE
    # ==========================================================================
    log("=" * 120)
    log("SECTION 4: FIXED-SIZE BLOCK TEMPLATE IDENTIFICATION")
    log("=" * 120)
    log()

    if len(m0_offsets) >= 2:
        # Most common block size
        dists = [m0_offsets[i+1] - m0_offsets[i] for i in range(len(m0_offsets)-1)]
        top_size = Counter(dists).most_common(1)[0][0]
        log(f"Most common inter-M0%D distance: {top_size} bytes")
        log()

        # Find blocks of this exact size and overlay them to find fixed bytes
        blocks_of_size = []
        for i in range(len(m0_offsets)-1):
            if m0_offsets[i+1] - m0_offsets[i] == top_size:
                start = m0_offsets[i]
                blocks_of_size.append(cond[start:start+top_size])

        log(f"Blocks of size {top_size}: {len(blocks_of_size)}")

        if blocks_of_size:
            # Find bytes that are the same across all blocks
            log(f"\nFixed byte positions in {top_size}-byte block (same across all {len(blocks_of_size)} blocks):")
            fixed_positions = []
            for pos in range(top_size):
                values = set(b[pos] if pos < len(b) else -1 for b in blocks_of_size)
                if len(values) == 1 and -1 not in values:
                    fixed_positions.append((pos, list(values)[0]))

            log(f"  {len(fixed_positions)} fixed byte positions out of {top_size}")
            for pos, val in fixed_positions:
                log(f"    byte[{pos:3d}] = 0x{val:02X} ({val:3d})")
            log()

            # Show first 5 blocks of this size as hex
            log(f"First 5 blocks of size {top_size}:")
            for i, block in enumerate(blocks_of_size[:5]):
                m0_idx = [j for j in range(len(m0_offsets)-1) if m0_offsets[j+1]-m0_offsets[j]==top_size][i]
                abs_off = COND_START + m0_offsets[m0_idx]
                log(f"\n  Block {i} (from M0%D #{m0_idx} at file 0x{abs_off:08X}):")
                log(hexdump(block, abs_off, top_size))
            log()

        # Now also look at the VARIABLE-SIZE blocks
        log("Block size distribution:")
        for sz, cnt in Counter(dists).most_common(30):
            log(f"  {sz:6d} bytes: {cnt:4d} blocks")
        log()

        # Check if variable sizes are multiples of some base
        log("Block sizes modulo analysis:")
        for mod in [4, 8, 16, 32, 64]:
            residues = Counter(d % mod for d in dists)
            log(f"  mod {mod:3d}: {dict(sorted(residues.items()))}")
        log()

    # ==========================================================================
    # SECTION 5: ANALYZE THE VARIABLE PART OF EACH BLOCK
    # What comes BETWEEN the fixed template?
    # ==========================================================================
    log("=" * 120)
    log("SECTION 5: VARIABLE BLOCK CONTENT ANALYSIS")
    log("=" * 120)
    log()

    if m0_offsets:
        # For each block, extract the part between M0%D+fixed_header and next block
        # First, find where the "variable" part starts/ends
        # Look at the first 2KB of the condition section byte by byte to find the block template

        # Let's look at what PRECEDES the first M0%D
        first_m0 = m0_offsets[0]
        log(f"Bytes before first M0%D (section start to first M0%D at +0x{first_m0:06X}):")
        log(f"  {first_m0} bytes of preamble")
        log(hexdump(cond[:min(first_m0, 256)], COND_START, min(first_m0, 256)))
        log()

        # Look at what's AFTER the last M0%D
        last_m0 = m0_offsets[-1]
        log(f"Bytes after last M0%D (at +0x{last_m0:06X} to end):")
        remaining = cond_len - last_m0
        log(f"  {remaining} bytes of tail after last M0%D")
        if remaining < 1024:
            log(hexdump(cond[last_m0:], COND_START + last_m0))
        else:
            log(hexdump(cond[last_m0:last_m0+256], COND_START + last_m0))
            log(f"  ... ({remaining - 256} more bytes)")
        log()

    # ==========================================================================
    # SECTION 6: TWO-BYTE FIELD ANALYSIS (the section is NOT 4-byte aligned!)
    # Since the section starts at ...6, let's try 2-byte alignment
    # ==========================================================================
    log("=" * 120)
    log("SECTION 6: UINT16 FIELD ANALYSIS (2-byte aligned)")
    log("=" * 120)
    log()

    # The hex dump shows lots of small 2-byte values like:
    # 01 00, 02 00, 03 00, 04 00, FF FF, 00 00
    # and patterns like: XX YY FF FF (uint16 + 0xFFFF)

    # Find all uint16 values at 2-byte aligned offsets
    u16_counter = Counter()
    for i in range(0, cond_len - 1, 2):
        val = struct.unpack_from("<H", cond, i)[0]
        u16_counter[val] += 1

    log("Top 50 most common uint16 values (2-byte aligned):")
    for val, cnt in u16_counter.most_common(50):
        log(f"  0x{val:04X} ({val:6d}): {cnt:6d} occurrences")
    log()

    # Look for uint16 pairs that are common
    u16_pair_counter = Counter()
    for i in range(0, cond_len - 3, 2):
        v1 = struct.unpack_from("<H", cond, i)[0]
        v2 = struct.unpack_from("<H", cond, i+2)[0]
        u16_pair_counter[(v1, v2)] += 1

    log("Top 30 most common consecutive uint16 pairs:")
    for (v1, v2), cnt in u16_pair_counter.most_common(30):
        log(f"  (0x{v1:04X}, 0x{v2:04X}) = ({v1:5d}, {v2:5d}): {cnt:5d} occurrences")
    log()

    # ==========================================================================
    # SECTION 7: PATTERN BETWEEN CONSECUTIVE -1.0 SENTINELS
    # ==========================================================================
    log("=" * 120)
    log("SECTION 7: PATTERN ANALYSIS BETWEEN CONSECUTIVE -1.0 SENTINELS")
    log("=" * 120)
    log()

    sentinel = b'\x00\x00\x80\xbf'
    sentinel_offsets = []
    pos = 0
    while True:
        idx = cond.find(sentinel, pos)
        if idx == -1:
            break
        sentinel_offsets.append(idx)
        pos = idx + 1

    log(f"Total sentinels: {len(sentinel_offsets)}")

    # Group sentinels into clusters (gaps <= 4 bytes = same cluster)
    clusters = []
    if sentinel_offsets:
        current_cluster = [sentinel_offsets[0]]
        for i in range(1, len(sentinel_offsets)):
            if sentinel_offsets[i] - sentinel_offsets[i-1] <= 8:
                current_cluster.append(sentinel_offsets[i])
            else:
                clusters.append(current_cluster)
                current_cluster = [sentinel_offsets[i]]
        clusters.append(current_cluster)

    log(f"Sentinel clusters (gap <= 8 bytes): {len(clusters)}")
    cluster_size_counter = Counter(len(c) for c in clusters)
    log(f"Cluster size distribution: {dict(sorted(cluster_size_counter.items()))}")
    log()

    # Show first 20 clusters with context
    log("First 20 sentinel clusters with context:")
    for i, cluster in enumerate(clusters[:20]):
        first = cluster[0]
        last = cluster[-1]
        start = max(0, first - 16)
        end = min(cond_len, last + 20)
        log(f"\n  Cluster {i} ({len(cluster)} sentinels): section+0x{first:06X} to +0x{last:06X}")
        log(hexdump(cond[start:end], COND_START + start))
    log()

    # Inter-cluster distances
    if len(clusters) > 1:
        cluster_dists = [clusters[i+1][0] - clusters[i][-1] for i in range(len(clusters)-1)]
        log("Inter-cluster distance histogram:")
        dc = Counter(cluster_dists)
        for d, c in sorted(dc.items(), key=lambda x: -x[1])[:30]:
            log(f"  {d:6d} bytes: {c:4d}")
        log()

    # ==========================================================================
    # SECTION 8: DEEP LOOK AT THE REPEATING BLOCK STRUCTURE
    # Using 82F58FEF as block internal marker (appears exactly once per block?)
    # ==========================================================================
    log("=" * 120)
    log("SECTION 8: BLOCK STRUCTURE USING 0xEF8FF582 MARKER")
    log("=" * 120)
    log()

    # Check if 82F58FEF count matches M0%D count
    log(f"0xEF8FF582 count: {len(ef_offsets)}")
    log(f"M0%D count: {len(m0_offsets)}")
    log(f"FLT_MAX count: {len(fm_offsets)}")
    log(f"0x0281676D count: {len(mg_offsets)}")
    log()

    # Check if these markers interleave: EF, then FLT_MAX, then MG, then M0
    log("Checking interleaving pattern of magic markers (first 10 blocks):")
    for i in range(min(10, len(m0_offsets))):
        m0 = m0_offsets[i]
        # Find nearest EF before this M0
        prev_ef = [e for e in ef_offsets if e < m0]
        prev_mg = [e for e in mg_offsets if e < m0]
        prev_fm = [e for e in fm_offsets if e < m0]
        if prev_ef and prev_mg and prev_fm:
            ef = prev_ef[-1]
            mg = prev_mg[-1]
            fm = prev_fm[-1]
            log(f"  Block {i}: EF@+{ef:06X} (+{m0-ef}), FM@+{fm:06X} (+{m0-fm}), MG@+{mg:06X} (+{m0-mg}), M0@+{m0:06X}")
    log()

    # ==========================================================================
    # SECTION 9: WHAT'S THE ACTUAL BLOCK BOUNDARY?
    # Let's try to detect transitions between blocks by looking for
    # a "header" pattern that precedes each M0%D
    # ==========================================================================
    log("=" * 120)
    log("SECTION 9: PRECISE BLOCK HEADER DETECTION")
    log("=" * 120)
    log()

    # From the hex dump, each block seems to have a pattern like:
    # ... XX XX FF FF YY YY FF FF 00 00 01 00 02 [29|00] ...
    # followed by some bytes, then 00 00 80 BF, then M0%D

    # Let's look at the bytes just before each M0%D (offset -40 to 0)
    log("Bytes at M0%D-48 to M0%D-1 for first 20 blocks:")
    for i, off in enumerate(m0_offsets[:20]):
        if off >= 48:
            before = cond[off-48:off]
            log(f"  Block {i:3d} (M0%D@+{off:06X}): {before.hex(' ').upper()}")
    log()

    # And the bytes from M0%D+0 to M0%D+24
    log("Bytes at M0%D to M0%D+24 for first 20 blocks:")
    for i, off in enumerate(m0_offsets[:20]):
        if off + 24 <= cond_len:
            after = cond[off:off+24]
            log(f"  Block {i:3d}: {after.hex(' ').upper()}")
    log()

    # ==========================================================================
    # SECTION 10: LOOK FOR THE VARIABLE-LENGTH DATA BETWEEN BLOCKS
    # The variable block size suggests each block has a fixed header + variable tail
    # ==========================================================================
    log("=" * 120)
    log("SECTION 10: VARIABLE-LENGTH TAIL ANALYSIS")
    log("=" * 120)
    log()

    if len(m0_offsets) >= 2:
        # For each block, what's between M0%D+fixed and next_block_start?
        # Need to figure out where the fixed part ends.
        # Look for a count field that could indicate variable-length data

        # Let's examine what's at M0%D+8 (after the 4-byte magic and next 4 bytes)
        log("Values at specific offsets from M0%D (first 50 blocks):")
        log(f"{'Block':>5} {'M0+4':>12} {'M0+5':>6} {'M0+6':>6} {'M0+7':>6} {'M0+8':>6} {'M0+9':>6} {'M0+10':>6} {'M0+11':>6}")
        for i, off in enumerate(m0_offsets[:50]):
            if off + 12 <= cond_len:
                vals = [cond[off+j] for j in range(4, 12)]
                log(f"  {i:3d}   0x{vals[0]:02X}{vals[1]:02X}{vals[2]:02X}{vals[3]:02X}  "
                    f"{vals[0]:5d} {vals[1]:5d} {vals[2]:5d} {vals[3]:5d} "
                    f"{vals[4]:5d} {vals[5]:5d} {vals[6]:5d} {vals[7]:5d}")
        log()

        # Check bytes at M0%D+4 as uint16 - this seems to always be 0x0002
        log("M0%D+4 as uint16 frequency:")
        m0_plus4 = Counter()
        for off in m0_offsets:
            if off + 6 <= cond_len:
                val = struct.unpack_from("<H", cond, off + 4)[0]
                m0_plus4[val] += 1
        log(f"  {dict(sorted(m0_plus4.items(), key=lambda x: -x[1]))}")
        log()

        # Check M0%D+6 as uint16
        log("M0%D+6 as uint16 frequency:")
        m0_plus6 = Counter()
        for off in m0_offsets:
            if off + 8 <= cond_len:
                val = struct.unpack_from("<H", cond, off + 6)[0]
                m0_plus6[val] += 1
        log(f"  {dict(sorted(m0_plus6.items(), key=lambda x: -x[1]))}")
        log()

        # Check M0%D+8 as uint8
        log("M0%D+8 (single byte) frequency:")
        m0_plus8 = Counter()
        for off in m0_offsets:
            if off + 9 <= cond_len:
                m0_plus8[cond[off + 8]] += 1
        log(f"  {dict(sorted(m0_plus8.items(), key=lambda x: -x[1]))}")
        log()

    # ==========================================================================
    # SECTION 11: THE PREAMBLE — WHAT COMES BEFORE THE FIRST M0%D?
    # This likely has structure info (counts, types, etc.)
    # ==========================================================================
    log("=" * 120)
    log("SECTION 11: PREAMBLE ANALYSIS (before first M0%D)")
    log("=" * 120)
    log()

    first_m0 = m0_offsets[0] if m0_offsets else cond_len
    log(f"Preamble: section offset 0 to +0x{first_m0:06X} ({first_m0} bytes)")
    log()

    # Note: the condition section starts mid-byte-stream from the prior section
    # The "80 3F" at the very start is likely the tail end of the state section
    # Let's look for the TRUE start of the condition section

    log("Full preamble hex dump:")
    log(hexdump(cond[:first_m0], COND_START, first_m0))
    log()

    log("Preamble interpreted as uint16 pairs:")
    for i in range(0, first_m0, 2):
        if i + 2 > first_m0:
            break
        val = struct.unpack_from("<H", cond, i)[0]
        log(f"  +0x{i:04X}: 0x{val:04X} ({val:5d})")
    log()

    # ==========================================================================
    # SECTION 12: LOOK FOR THE "TAIL" STRUCTURE AFTER THE LAST M0%D
    # This tells us what terminates the block list
    # ==========================================================================
    log("=" * 120)
    log("SECTION 12: TAIL STRUCTURE (after last M0%D)")
    log("=" * 120)
    log()

    last_m0 = m0_offsets[-1] if m0_offsets else 0
    tail = cond[last_m0:]
    log(f"Last M0%D at section+0x{last_m0:06X}")
    log(f"Tail length: {len(tail)} bytes")
    log()
    log("Full tail hex dump (first 512 bytes):")
    log(hexdump(tail[:512], COND_START + last_m0))
    log()

    # ==========================================================================
    # SECTION 13: COMPARE WITH BASIC_UPPER — FIND ITS CONDITION SECTION
    # ==========================================================================
    log("=" * 120)
    log("SECTION 13: BASIC_UPPER.PAAC COMPARISON")
    log("=" * 120)
    log()

    basic_data = read_file(BASIC)
    log(f"basic_upper.paac: {len(basic_data)} bytes (0x{len(basic_data):X})")

    # Find M0%D markers in basic
    basic_m0 = []
    pos = 0
    while True:
        idx = basic_data.find(magic_m0, pos)
        if idx == -1:
            break
        basic_m0.append(idx)
        pos = idx + 1
    log(f"M0%D markers in basic_upper: {len(basic_m0)}")

    # Find EF markers
    basic_ef = []
    pos = 0
    while True:
        idx = basic_data.find(magic_ef, pos)
        if idx == -1:
            break
        basic_ef.append(idx)
        pos = idx + 1
    log(f"0xEF8FF582 markers in basic_upper: {len(basic_ef)}")

    # Find FLT_MAX
    basic_fm = []
    pos = 0
    while True:
        idx = basic_data.find(magic_fltmax, pos)
        if idx == -1:
            break
        basic_fm.append(idx)
        pos = idx + 1
    log(f"FLT_MAX markers in basic_upper: {len(basic_fm)}")
    log()

    if basic_m0:
        basic_dists = [basic_m0[i+1] - basic_m0[i] for i in range(len(basic_m0)-1)]
        log(f"basic_upper inter-M0%D distances: {Counter(basic_dists).most_common(10)}")
        log()

        # Show first 5 basic blocks
        log("First 5 M0%D blocks in basic_upper:")
        for i, off in enumerate(basic_m0[:5]):
            start = max(0, off - 80)
            end = min(len(basic_data), off + 40)
            log(f"\n  M0%D #{i} at file 0x{off:06X}:")
            log(hexdump(basic_data[start:end], start))
        log()

        # Where does the first M0%D appear proportionally?
        pct = basic_m0[0] * 100.0 / len(basic_data)
        log(f"First M0%D in basic at {pct:.1f}% of file (offset 0x{basic_m0[0]:X})")
        pct_sword = m0_offsets[0] * 100.0 / len(sword_data) if m0_offsets else 0
        log(f"First M0%D in sword at {pct_sword:.1f}% of file (offset 0x{COND_START+m0_offsets[0]:X})")
        log()

    # ==========================================================================
    # SECTION 14: BYTE-LEVEL PATTERN AROUND FLT_MAX (transition condition?)
    # FLT_MAX (0x7F7FFFFF) likely means "no threshold" / "always true"
    # ==========================================================================
    log("=" * 120)
    log("SECTION 14: FLT_MAX CONTEXT ANALYSIS (possible condition thresholds)")
    log("=" * 120)
    log()

    log("Context ±20 bytes around first 20 FLT_MAX occurrences:")
    for i, off in enumerate(fm_offsets[:20]):
        start = max(0, off - 20)
        end = min(cond_len, off + 24)
        log(f"\n  FLT_MAX #{i} at section+0x{off:06X}:")
        log(hexdump(cond[start:end], COND_START + start))
    log()

    # What uint16 value appears 2 bytes before FLT_MAX?
    log("uint16 at FLT_MAX-2 frequency:")
    fm_before = Counter()
    for off in fm_offsets:
        if off >= 2:
            val = struct.unpack_from("<H", cond, off - 2)[0]
            fm_before[val] += 1
    for val, cnt in fm_before.most_common(15):
        log(f"  0x{val:04X} ({val:5d}): {cnt}")
    log()

    # What uint16 value appears right after FLT_MAX?
    log("uint16 at FLT_MAX+4 frequency:")
    fm_after = Counter()
    for off in fm_offsets:
        if off + 6 <= cond_len:
            val = struct.unpack_from("<H", cond, off + 4)[0]
            fm_after[val] += 1
    for val, cnt in fm_after.most_common(15):
        log(f"  0x{val:04X} ({val:5d}): {cnt}")
    log()

    # ==========================================================================
    # SECTION 15: LOOK AT THE 0x17 (23) VALUE — APPEARS CONSISTENTLY
    # ==========================================================================
    log("=" * 120)
    log("SECTION 15: VALUE 0x17 (23) ANALYSIS — APPEARS IN EVERY BLOCK")
    log("=" * 120)
    log()

    # From the hex dump: "17 00 00 00" appears in every block
    # This is at a fixed offset from the M0%D-relative markers
    pattern_17 = b'\x17\x00\x00\x00'
    p17_offsets = []
    pos = 0
    while True:
        idx = cond.find(pattern_17, pos)
        if idx == -1:
            break
        p17_offsets.append(idx)
        pos = idx + 1

    log(f"Occurrences of 0x17000000: {len(p17_offsets)}")

    # Distance from each 0x17 to nearest M0%D
    if p17_offsets and m0_offsets:
        p17_to_m0 = []
        for p in p17_offsets[:200]:
            for m in m0_offsets:
                if m > p:
                    p17_to_m0.append(m - p)
                    break
        dc = Counter(p17_to_m0)
        log(f"Distance from 0x17 to next M0%D: {dc.most_common(10)}")
    log()

    # ==========================================================================
    # SECTION 16: COMPREHENSIVE BLOCK FIELD TABLE
    # Now that we know blocks are M0%D-anchored, create a CSV-like table
    # ==========================================================================
    log("=" * 120)
    log("SECTION 16: BLOCK FIELD TABLE (M0%D-relative)")
    log("=" * 120)
    log()

    if len(m0_offsets) >= 2:
        # For the most common block size, create a field table
        # Read each block as bytes and interpret at known offsets
        top_size = Counter(dists).most_common(1)[0][0]

        # For ALL blocks (not just same-size), analyze fields at consistent offsets
        # We know M0%D is the anchor. Let's read fields relative to it.

        # First, figure out where the block STARTS relative to M0%D
        # Look backwards from M0%D for a marker

        # In the hex dump, each block has:
        # [~128 bytes of fixed template] [variable tail] [next block]
        # The "80 BF" pattern and "M0%D" pattern are within the fixed part

        # Let's create a summary of key field values for each block
        log(f"Key fields for first 50 blocks:")
        log(f"{'#':>4} {'M0@':>10} {'BlkSz':>6} {'M0+4':>8} {'M0+6':>6} {'M0+8':>4}")
        for i in range(min(50, len(m0_offsets))):
            off = m0_offsets[i]
            blk_sz = m0_offsets[i+1] - off if i+1 < len(m0_offsets) else 0
            if off + 12 <= cond_len:
                v4 = struct.unpack_from("<H", cond, off+4)[0]
                v6 = struct.unpack_from("<H", cond, off+6)[0]
                v8 = cond[off+8]
                log(f"  {i:3d} +{off:08X} {blk_sz:6d} 0x{v4:04X} 0x{v6:04X} 0x{v8:02X}")
        log()

    # ==========================================================================
    # SECTION 17: LOOK FOR THE "29 05 0B 0C" PATTERN
    # From hex dump: 02 29 05 0B 0C appears in many blocks — looks like opcodes
    # ==========================================================================
    log("=" * 120)
    log("SECTION 17: OPCODE-LIKE PATTERN ANALYSIS (02 29 05 0B 0C)")
    log("=" * 120)
    log()

    pattern_a = b'\x02\x29\x05\x0B\x0C'
    pattern_b = b'\x02\x00\x05\x0B\x0C'  # variant without 0x29

    for name, pat in [("02 29 05 0B 0C", pattern_a), ("02 00 05 0B 0C", pattern_b)]:
        offsets = []
        pos = 0
        while True:
            idx = cond.find(pat, pos)
            if idx == -1:
                break
            offsets.append(idx)
            pos = idx + 1
        log(f"Pattern '{name}': {len(offsets)} occurrences")
        if offsets:
            for i, off in enumerate(offsets[:10]):
                # Show ±16 bytes
                start = max(0, off - 8)
                end = min(cond_len, off + len(pat) + 16)
                log(f"  [{i}] section+0x{off:06X}: {cond[start:end].hex(' ').upper()}")
    log()

    # Look at byte at the position 2 bytes before "05 0B 0C" pattern
    pat_50b = b'\x05\x0B\x0C'
    offsets_50b = []
    pos = 0
    while True:
        idx = cond.find(pat_50b, pos)
        if idx == -1:
            break
        offsets_50b.append(idx)
        pos = idx + 1

    log(f"Pattern '05 0B 0C': {len(offsets_50b)} occurrences")
    if offsets_50b:
        # What byte(s) precede this?
        before_counter = Counter()
        for off in offsets_50b:
            if off >= 2:
                before_counter[cond[off-2:off].hex()] += 1
        log(f"2 bytes before '05 0B 0C': {before_counter.most_common(15)}")
        log()

        # What follows?
        after_counter = Counter()
        for off in offsets_50b:
            end = off + 3
            if end + 4 <= cond_len:
                after_counter[cond[end:end+4].hex()] += 1
        log(f"4 bytes after '05 0B 0C': {after_counter.most_common(15)}")
    log()

    # ==========================================================================
    # SECTION 18: FULL ANNOTATED DUMP OF 3 COMPLETE BLOCKS
    # ==========================================================================
    log("=" * 120)
    log("SECTION 18: ANNOTATED DUMP OF 3 COMPLETE BLOCKS")
    log("=" * 120)
    log()

    if len(m0_offsets) >= 4:
        for block_idx in [0, 1, 2]:
            m0_off = m0_offsets[block_idx]
            if block_idx + 1 < len(m0_offsets):
                next_m0 = m0_offsets[block_idx + 1]
            else:
                next_m0 = min(m0_off + 512, cond_len)

            # Back up from M0%D to find block start
            # From the pattern, the block seems to start ~128 bytes before M0%D
            # Look for the EF marker
            block_start = m0_off  # default
            for ef in reversed(ef_offsets):
                if ef < m0_off and m0_off - ef < 200:
                    # Back up more — EF is not the start either
                    # The block likely starts at EF - some_offset
                    block_start = ef - 80  # rough estimate
                    break

            if block_idx == 0:
                # First block: start from section start or from before EF
                block_start = max(0, block_start)
            else:
                # Start from previous M0%D's end region
                block_start = m0_offsets[block_idx - 1] + 10  # approximate

            block_end = next_m0 + 10  # slightly past next M0%D
            block_data = cond[block_start:min(block_end, cond_len)]

            log(f"=== BLOCK {block_idx} ===")
            log(f"  M0%D at section+0x{m0_off:06X}")
            log(f"  Dump range: section+0x{block_start:06X} to +0x{min(block_end,cond_len):06X} ({min(block_end,cond_len)-block_start} bytes)")
            log()
            log(hexdump(block_data, COND_START + block_start))
            log()

            # Also show as uint16 stream
            log(f"  As uint16 stream:")
            for j in range(0, len(block_data) - 1, 2):
                val = struct.unpack_from("<H", block_data, j)[0]
                abs_off = COND_START + block_start + j
                if val == 0:
                    continue  # skip zeros for readability
                log(f"    file 0x{abs_off:08X} (+{block_start+j:06X}): u16=0x{val:04X} ({val:5d})")
            log()

    # ==========================================================================
    # SECTION 19: CROSS-REFERENCE: DO ANY M0%D BLOCKS REFERENCE STATE INDICES?
    # State indices are 0-720. Look for patterns in the variable part.
    # ==========================================================================
    log("=" * 120)
    log("SECTION 19: STATE INDEX CROSS-REFERENCE IN BLOCKS")
    log("=" * 120)
    log()

    if len(m0_offsets) >= 2:
        # For each block, check if any uint16 in the variable part is a valid state index
        log("Scanning blocks for uint16 state references (0-720):")
        state_refs_per_block = []
        for i in range(min(len(m0_offsets), 50)):
            off = m0_offsets[i]
            end = m0_offsets[i+1] if i+1 < len(m0_offsets) else min(off + 512, cond_len)
            # Scan the block for uint16 values 0-720
            refs = []
            for j in range(off, min(end, cond_len) - 1, 2):
                val = struct.unpack_from("<H", cond, j)[0]
                if 0 <= val <= 720 and val > 0:
                    refs.append((j - off, val))
            state_refs_per_block.append(refs)
            if refs:
                log(f"  Block {i:3d}: {len(refs)} potential state refs")
                for rel_off, val in refs[:10]:
                    log(f"    M0+{rel_off:4d}: state {val}")
                if len(refs) > 10:
                    log(f"    ... and {len(refs)-10} more")
        log()

    # ==========================================================================
    # SECTION 20: LOOK FOR "02 00 00 00 01" PATTERN — BLOCK TYPE HEADER?
    # From hex: M0%D is followed by "02 00 00 00 01" in many blocks
    # ==========================================================================
    log("=" * 120)
    log("SECTION 20: M0%D HEADER BYTE ANALYSIS")
    log("=" * 120)
    log()

    if m0_offsets:
        # Dump the first 20 bytes after each M0%D for first 50 blocks
        log("First 20 bytes after M0%D for all blocks:")
        for i, off in enumerate(m0_offsets):
            if off + 24 <= cond_len:
                after = cond[off+4:off+24]  # skip M0%D itself
                log(f"  Block {i:3d} (+{off:06X}): {after.hex(' ').upper()}")
        log()

    # ==========================================================================
    # SECTION 21: EXAMINE THE BLOCK BETWEEN FLT_MAX AND NEXT SENTINEL CLUSTER
    # This is likely where the actual condition data lives
    # ==========================================================================
    log("=" * 120)
    log("SECTION 21: DATA BETWEEN FLT_MAX AND SENTINEL CLUSTERS")
    log("=" * 120)
    log()

    # For each block, find: FLT_MAX ... sentinel_cluster ... end
    # The pattern seems to be:
    # ... 82F58FEF ... [floats/zeros] ... 0000_80BF ... FFFF_7F7F ...
    # ... 0000_80BF 0000_80BF ... 17_00_00_00 ... 0000_80BF 6D678102 ...
    # ... [some bytes] ... 0000_80BF ... [variable data] ... [next block]

    log("Value 0x17 (23) context — could be a condition type enum:")
    for i, off in enumerate(p17_offsets[:20]):
        if off + 20 <= cond_len and off >= 8:
            before = cond[off-8:off]
            after = cond[off:off+20]
            log(f"  [{i:3d}] +{off:06X}: before={before.hex(' ')}  this+after={after.hex(' ')}")
    log()

    # ==========================================================================
    # SECTION 22: SCAN ALL PAAC FILES FOR M0%D COUNT VS FILE SIZE
    # ==========================================================================
    log("=" * 120)
    log("SECTION 22: ALL PAAC FILES — M0%D COUNT VS FILE SIZE")
    log("=" * 120)
    log()

    paac_dir = os.path.dirname(SWORD)
    for fname in sorted(os.listdir(paac_dir)):
        if fname.endswith('.paac'):
            fpath = os.path.join(paac_dir, fname)
            data = read_file(fpath)
            count = 0
            pos = 0
            while True:
                idx = data.find(magic_m0, pos)
                if idx == -1:
                    break
                count += 1
                pos = idx + 1
            # Also count EF and sentinels
            ef_count = 0
            pos = 0
            while True:
                idx = data.find(magic_ef, pos)
                if idx == -1:
                    break
                ef_count += 1
                pos = idx + 1
            sent_count = 0
            pos = 0
            while True:
                idx = data.find(b'\x00\x00\x80\xbf', pos)
                if idx == -1:
                    break
                sent_count += 1
                pos = idx + 1
            log(f"  {fname:35s}: {len(data):10d} bytes, M0%D={count:4d}, EF={ef_count:4d}, -1.0={sent_count:5d}")
    log()

    # ==========================================================================
    # SAVE
    # ==========================================================================
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    print(f"\n\nResults saved to {OUTPUT}")
    print(f"Total output: {len(out_lines)} lines")

if __name__ == "__main__":
    main()
