#!/usr/bin/env python3
"""
FINAL deep analysis of the .paac condition graph 260-byte block structure.

Key findings from prior analysis:
  - 651 M0%D markers in condition section, 623 at exact 260-byte spacing
  - 260-byte block anchored at M0%D (bytes [0:4] = "M0%D" = 0x44253044)
  - 185 out of 260 bytes are FIXED across all 623 uniform blocks
  - Magic markers at fixed offsets within each block:
    - byte[0:4]   = M0%D (0x44253044)
    - byte[84:88]  = 0xEF8FF582  (offset from M0%D = +84)
    - byte[112:116] = -1.0 sentinel (0x0000_80BF)
    - byte[120:124] = FLT_MAX (0xFFFF7F7F)
    - byte[136]     = 0x17 (23 decimal)
    - byte[148:152] = 0x0281676D  (offset from M0%D = +148)

Now: map EVERY variable byte, identify field types, cross-reference values.
"""

import struct
import os
from collections import Counter, defaultdict

SWORD = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
BASIC = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\basic_upper.paac"
OUTPUT = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\condition_graph_analysis.txt"

COND_START = 0x97996
COND_END = 0x12FA79

# Corrected tail-field offsets inside each 260-byte M0%D block.
# Earlier analysis treated several tail fields as starting 4 bytes too early.
SOURCE_ID_OFF = 212
LABEL_INDEX_OFF = 216
OPCODE_OFF = 224
PARAM_START_OFF = 229

STRING_TABLE = {
    1: "key_guard",
    8: "key_fistattack",
    9: "equip_shield",
    10: "key_skill_12",
    12: "key_skill_1",
    13: "key_skill_12_start",
    14: "key_skill_7",
    15: "key_crouch",
    16: "key_hardattack",
    17: "key_guard_start",
    18: "key_skill_2",
    19: "key_run",
    20: "key_cancel",
    21: "CharacterHit",
    22: "off",
    25: "key_dash",
    27: "key_skill_9",
    28: "key_skill_4",
    29: "key_skill_17",
    31: "key_skill_3",
    33: "key_skill_18",
    36: "key_norattack",
    37: "key_skill_8",
    40: "key_skill_8_combo",
    43: "key_kickattack",
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


def main():
    sword_data = read_file(SWORD)
    cond = sword_data[COND_START:COND_END]
    cond_len = len(cond)

    log("=" * 120)
    log("CRIMSON DESERT .PAAC CONDITION GRAPH — DEFINITIVE BLOCK STRUCTURE ANALYSIS")
    log("=" * 120)
    log(f"File: sword_upper.paac ({len(sword_data)} bytes)")
    log(f"Condition section: 0x{COND_START:X} - 0x{COND_END:X} ({cond_len} bytes)")
    log()

    # Find all M0%D markers
    magic_m0 = b'\x4D\x30\x25\x44'
    m0_offsets = []
    pos = 0
    while True:
        idx = cond.find(magic_m0, pos)
        if idx == -1:
            break
        m0_offsets.append(idx)
        pos = idx + 1

    log(f"Total M0%D markers: {len(m0_offsets)}")

    # Get the 623 uniform 260-byte blocks
    dists = [m0_offsets[i+1] - m0_offsets[i] for i in range(len(m0_offsets)-1)]
    uniform_blocks = []  # (index, section_offset, block_data)
    for i in range(len(m0_offsets)-1):
        if dists[i] == 260:
            off = m0_offsets[i]
            uniform_blocks.append((i, off, cond[off:off+260]))

    log(f"Uniform 260-byte blocks: {len(uniform_blocks)}")
    log()

    # ==========================================================================
    # 1. MAP EVERY BYTE OF THE 260-BYTE BLOCK
    # ==========================================================================
    log("=" * 120)
    log("1. COMPLETE 260-BYTE BLOCK FIELD MAP")
    log("=" * 120)
    log()

    # For each byte position, collect all values across blocks
    byte_stats = []
    for pos in range(260):
        values = [b[2][pos] for b in uniform_blocks]
        unique = set(values)
        byte_stats.append({
            'pos': pos,
            'unique_count': len(unique),
            'values': Counter(values),
            'all_same': len(unique) == 1,
            'fixed_val': values[0] if len(unique) == 1 else None,
        })

    # Identify variable byte ranges
    variable_ranges = []
    i = 0
    while i < 260:
        if not byte_stats[i]['all_same']:
            start = i
            while i < 260 and not byte_stats[i]['all_same']:
                i += 1
            variable_ranges.append((start, i - 1))
        else:
            i += 1

    log("VARIABLE BYTE RANGES (bytes that differ across blocks):")
    for start, end in variable_ranges:
        length = end - start + 1
        log(f"  bytes[{start:3d}:{end+1:3d}] ({length:2d} bytes)")
    log()

    # Now annotate the full block structure
    log("ANNOTATED 260-BYTE BLOCK TEMPLATE:")
    log("(V = variable across blocks, F = fixed/constant)")
    log()

    # Group into logical fields
    # First, let's print the fixed template with variable positions marked
    block0 = uniform_blocks[0][2]
    for i in range(0, 260, 16):
        chunk = block0[i:min(i+16, 260)]
        hex_parts = []
        var_mask = []
        for j, b in enumerate(chunk):
            pos = i + j
            if byte_stats[pos]['all_same']:
                hex_parts.append(f"{b:02X}")
                var_mask.append("F ")
            else:
                hex_parts.append(f"{b:02X}")
                var_mask.append("V ")
        log(f"  [{i:3d}] {' '.join(hex_parts)}")
        log(f"        {' '.join(var_mask)}")
    log()

    # ==========================================================================
    # 2. VARIABLE FIELD VALUE ANALYSIS
    # ==========================================================================
    log("=" * 120)
    log("2. VARIABLE FIELD VALUE ANALYSIS")
    log("=" * 120)
    log()

    for start, end in variable_ranges:
        length = end - start + 1
        log(f"--- Field at byte[{start}:{end+1}] ({length} bytes) ---")

        if length == 1:
            vals = Counter(b[2][start] for b in uniform_blocks)
            log(f"  uint8 values: {dict(sorted(vals.items(), key=lambda x: -x[1]))}")
        elif length == 2:
            vals = Counter(struct.unpack_from("<H", b[2], start)[0] for b in uniform_blocks)
            log(f"  uint16 values (top 20): {vals.most_common(20)}")
        elif length == 4:
            u32vals = Counter(struct.unpack_from("<I", b[2], start)[0] for b in uniform_blocks)
            f32vals = Counter()
            for b in uniform_blocks:
                f = struct.unpack_from("<f", b[2], start)[0]
                if abs(f) < 1e10:
                    f32vals[round(f, 4)] += 1
            log(f"  uint32 values (top 20): {u32vals.most_common(20)}")
            log(f"  float32 values (top 10): {f32vals.most_common(10)}")
        else:
            # Multi-byte: try as groups of 2 and 4
            if length <= 8:
                log(f"  Raw values (first 30 blocks):")
                for idx, (bi, off, data) in enumerate(uniform_blocks[:30]):
                    log(f"    Block {bi:3d}: {data[start:end+1].hex(' ').upper()}")
            else:
                # Show as uint16 pairs
                log(f"  As uint16 stream (first 20 blocks):")
                for idx, (bi, off, data) in enumerate(uniform_blocks[:20]):
                    vals = []
                    for j in range(start, end+1, 2):
                        if j + 2 <= 260:
                            vals.append(struct.unpack_from("<H", data, j)[0])
                    log(f"    Block {bi:3d}: {' '.join(f'{v:5d}' for v in vals)}")
        log()

    # ==========================================================================
    # 3. IDENTIFY THE "OPCODE" REGION (bytes ~208-256)
    # ==========================================================================
    log("=" * 120)
    log("3. OPCODE / TRANSITION REGION ANALYSIS (bytes 208-260)")
    log("=" * 120)
    log()

    # From the hex dumps, the tail region of each block looks like:
    # [uint16 XXXX] [FF FF] [uint16 YYYY] [FF FF] [00 00] [01 00]
    # [02 29] [05 0B 0C] [uint8 N] [00] [uint8 M] [01 02 05 FF FF 00 00 FF 03 05 04]
    # [00 00 00 80 BF] [4 bytes] [4 bytes] [4 bytes]

    log("Bytes 208-260 for first 50 blocks:")
    for idx, (bi, off, data) in enumerate(uniform_blocks[:50]):
        tail = data[208:260]
        log(f"  Block {bi:3d}: {tail.hex(' ').upper()}")
    log()

    # The variable bytes in the tail region
    log("DECOMPOSING THE TAIL (bytes 208-260):")
    log()

    # byte 212-213: uint16 — looks like a source node/state identifier
    log("byte[212:214] as uint16 (possible source state/transition ID):")
    v208 = Counter(struct.unpack_from("<H", b[2], SOURCE_ID_OFF)[0] for b in uniform_blocks)
    log(f"  Top 20: {v208.most_common(20)}")
    log(f"  Total unique: {len(v208)}")
    min_v = min(v208.keys())
    max_v = max(v208.keys())
    log(f"  Range: {min_v} - {max_v}")
    log()

    # byte 214-215: should be FF FF
    log("byte[214:216] frequency:")
    v210 = Counter(struct.unpack_from("<H", b[2], SOURCE_ID_OFF + 2)[0] for b in uniform_blocks)
    log(f"  {dict(v210)}")
    log()

    # byte 216-217: uint16
    log("byte[216:218] as uint16 (possible label/key index?):")
    v212 = Counter(struct.unpack_from("<H", b[2], LABEL_INDEX_OFF)[0] for b in uniform_blocks)
    log(f"  Top 20: {v212.most_common(20)}")
    # Check if these map to string table
    log(f"  Note: string table has indices 0-44")
    log()

    # byte 218-219: should be FF FF
    log("byte[218:220] frequency:")
    v214 = Counter(struct.unpack_from("<H", b[2], LABEL_INDEX_OFF + 2)[0] for b in uniform_blocks)
    log(f"  {dict(v214)}")
    log()

    # byte 220-221: 00 00
    log("byte[220:222] frequency:")
    v216 = Counter(struct.unpack_from("<H", b[2], 220)[0] for b in uniform_blocks)
    log(f"  {dict(v216)}")
    log()

    # byte 222-223: 01 00
    log("byte[222:224] frequency:")
    v218 = Counter(struct.unpack_from("<H", b[2], 222)[0] for b in uniform_blocks)
    log(f"  {dict(v218)}")
    log()

    # byte 224: the first opcode byte
    log("byte[224] frequency (condition type?):")
    v220 = Counter(b[2][224] for b in uniform_blocks)
    log(f"  {dict(sorted(v220.items()))}")
    log()

    # byte 225: the second opcode byte
    log("byte[225] frequency:")
    v221 = Counter(b[2][225] for b in uniform_blocks)
    log(f"  {dict(sorted(v221.items()))}")
    log()

    # byte 226: fixed suffix byte 0?
    log("byte[226] frequency:")
    v222 = Counter(b[2][226] for b in uniform_blocks)
    log(f"  {dict(sorted(v222.items()))}")
    log()

    # byte 227: fixed suffix byte 1?
    log("byte[227] frequency:")
    v223 = Counter(b[2][227] for b in uniform_blocks)
    log(f"  {dict(sorted(v223.items()))}")
    log()

    # byte 228: fixed suffix byte 2?
    log("byte[228] frequency:")
    v224 = Counter(b[2][228] for b in uniform_blocks)
    log(f"  {dict(sorted(v224.items()))}")
    log()

    # bytes 229-231: variable condition parameters
    log("byte[229] frequency (sub-condition type?):")
    v225 = Counter(b[2][229] for b in uniform_blocks)
    log(f"  {dict(sorted(v225.items()))}")
    log()

    log("byte[230] frequency:")
    v226 = Counter(b[2][230] for b in uniform_blocks)
    log(f"  {dict(sorted(v226.items()))}")
    log()

    log("byte[231] frequency:")
    v227 = Counter(b[2][231] for b in uniform_blocks)
    log(f"  {dict(sorted(v227.items()))}")
    log()

    # bytes 228-239 region
    log("bytes[228:240] (fixed template?):")
    for idx, (bi, off, data) in enumerate(uniform_blocks[:10]):
        log(f"  Block {bi:3d}: {data[228:240].hex(' ').upper()}")
    log()

    # ==========================================================================
    # 4. FIELD AT byte[4:8] — likely a type or version
    # ==========================================================================
    log("=" * 120)
    log("4. HEADER FIELDS (bytes 4-36)")
    log("=" * 120)
    log()

    log("byte[4:6] as uint16 (always 0x0002 = 2?):")
    v4 = Counter(struct.unpack_from("<H", b[2], 4)[0] for b in uniform_blocks)
    log(f"  {dict(v4)}")
    log()

    log("byte[6:8] as uint16:")
    v6 = Counter(struct.unpack_from("<H", b[2], 6)[0] for b in uniform_blocks)
    log(f"  {dict(v6)}")
    log()

    log("byte[8] (single byte):")
    v8 = Counter(b[2][8] for b in uniform_blocks)
    log(f"  {dict(sorted(v8.items()))}")
    log()

    log("byte[9] (single byte):")
    v9 = Counter(b[2][9] for b in uniform_blocks)
    log(f"  {dict(sorted(v9.items()))}")
    log()

    log("byte[10:12] as uint16:")
    v10 = Counter(struct.unpack_from("<H", b[2], 10)[0] for b in uniform_blocks)
    log(f"  Top 15: {v10.most_common(15)}")
    log()

    log("byte[12:16] as uint32:")
    v12 = Counter(struct.unpack_from("<I", b[2], 12)[0] for b in uniform_blocks)
    log(f"  Top 15: {v12.most_common(15)}")
    log()

    log("byte[16:20] as uint32:")
    v16 = Counter(struct.unpack_from("<I", b[2], 16)[0] for b in uniform_blocks)
    log(f"  Top 15: {v16.most_common(15)}")
    log()

    log("byte[20:24] as uint32 (hash value?):")
    v20 = Counter(struct.unpack_from("<I", b[2], 20)[0] for b in uniform_blocks)
    log(f"  Unique values: {len(v20)}")
    log(f"  Top 10: {v20.most_common(10)}")
    log()

    log("byte[24:28] as uint32:")
    v24 = Counter(struct.unpack_from("<I", b[2], 24)[0] for b in uniform_blocks)
    log(f"  Top 10: {v24.most_common(10)}")
    log()

    log("byte[28:32] as uint32:")
    v28 = Counter(struct.unpack_from("<I", b[2], 28)[0] for b in uniform_blocks)
    log(f"  Top 10: {v28.most_common(10)}")
    log()

    log("byte[32:36] as uint32 (0xFFFFFFFF = -1?):")
    v32 = Counter(struct.unpack_from("<I", b[2], 32)[0] for b in uniform_blocks)
    log(f"  {dict(v32.most_common(10))}")
    log()

    # ==========================================================================
    # 5. THE 0xEF8FF582 AND HASH REGION (bytes 80-96)
    # ==========================================================================
    log("=" * 120)
    log("5. HASH/MAGIC REGION (bytes 76-100)")
    log("=" * 120)
    log()

    log("byte[76:80] as uint32 (variable — could be hash or ID):")
    v76 = Counter(struct.unpack_from("<I", b[2], 76)[0] for b in uniform_blocks)
    log(f"  Unique values: {len(v76)}")
    log(f"  Top 10: {v76.most_common(10)}")
    log()

    log("byte[80:84] as uint32 (mostly 0?):")
    v80 = Counter(struct.unpack_from("<I", b[2], 80)[0] for b in uniform_blocks)
    log(f"  {dict(v80.most_common(10))}")
    log()

    log("byte[84:88] = 0xEF8FF582 (FIXED magic)")
    log()

    log("byte[88:92] as uint32:")
    v88 = Counter(struct.unpack_from("<I", b[2], 88)[0] for b in uniform_blocks)
    log(f"  {dict(v88.most_common(10))}")
    log()

    # ==========================================================================
    # 6. THE KEY FIELD — byte[148:152] region (0x0281676D)
    # ==========================================================================
    log("=" * 120)
    log("6. THE 0x0281676D REGION (bytes 144-160)")
    log("=" * 120)
    log()

    log("byte[144:148] as uint32 (0x0000_80BF = -1.0 FIXED)")
    log()

    log("byte[148:152] as uint32 (mostly 0x0281676D?):")
    v148 = Counter(struct.unpack_from("<I", b[2], 148)[0] for b in uniform_blocks)
    log(f"  {dict(v148.most_common(10))}")
    log()

    log("byte[152:156] as uint32 (variable — state reference?):")
    v152 = Counter(struct.unpack_from("<I", b[2], 152)[0] for b in uniform_blocks)
    log(f"  Unique: {len(v152)}")
    log(f"  Top 20: {v152.most_common(20)}")
    # Check if any match state indices (0-720)
    state_matches = [(v, c) for v, c in v152.items() if 0 <= v <= 720]
    log(f"  Values in state range (0-720): {state_matches}")
    log()

    log("byte[156:160] as uint32:")
    v156 = Counter(struct.unpack_from("<I", b[2], 156)[0] for b in uniform_blocks)
    log(f"  Top 10: {v156.most_common(10)}")
    log()

    # ==========================================================================
    # 7. THE TRANSITION/CONDITION TAIL (bytes 196-260) — BYTE BY BYTE
    # ==========================================================================
    log("=" * 120)
    log("7. FULL TAIL ANALYSIS (bytes 196-260) — CONDITION ENCODING")
    log("=" * 120)
    log()

    # Let me look at the entire tail as a formatted table
    log("Full byte-by-byte tail for 20 blocks (bytes 196-260):")
    log()
    header = "Block  " + " ".join(f"{i:3d}" for i in range(196, 260))
    log(header)
    log("-" * len(header))
    for idx, (bi, off, data) in enumerate(uniform_blocks[:20]):
        vals = " ".join(f" {data[i]:02X}" for i in range(196, 260))
        log(f"  {bi:3d}  {vals}")
    log()

    # ==========================================================================
    # 8. CROSS-REFERENCE: byte[208:210] vs state indices
    # ==========================================================================
    log("=" * 120)
    log("8. CROSS-REFERENCE: BLOCK FIELD byte[212:214] vs STATE INDICES")
    log("=" * 120)
    log()

    # Collect all byte[212:214] values
    block_state_ids = [(bi, struct.unpack_from("<H", data, SOURCE_ID_OFF)[0]) for bi, off, data in uniform_blocks]
    all_ids = [v for _, v in block_state_ids]
    id_counter = Counter(all_ids)

    log(f"Total unique byte[208:210] values: {len(id_counter)}")
    log(f"Range: {min(all_ids)} to {max(all_ids)}")
    log(f"Values in state index range (0-720): {sum(1 for v in all_ids if v <= 720)}")
    log(f"Values > 720: {sum(1 for v in all_ids if v > 720)}")
    log()

    # Are they sequential?
    sorted_ids = sorted(set(all_ids))
    log(f"Sorted unique values (first 50): {sorted_ids[:50]}")
    log()

    # ==========================================================================
    # 9. CROSS-REFERENCE: byte[212:214] — could be label index
    # ==========================================================================
    log("=" * 120)
    log("9. CROSS-REFERENCE: byte[216:218] — LABEL/KEY INDEX")
    log("=" * 120)
    log()

    label_vals = Counter(struct.unpack_from("<H", b[2], LABEL_INDEX_OFF)[0] for b in uniform_blocks)
    log(f"byte[216:218] value distribution:")
    for val, cnt in sorted(label_vals.items(), key=lambda x: -x[1]):
        label = ""
        if val in STRING_TABLE:
            label = f" <-- {STRING_TABLE[val]}"
        log(f"  {val:5d} (0x{val:04X}): {cnt:4d} blocks{label}")
    log()

    # ==========================================================================
    # 10. CORRELATION ANALYSIS: Which blocks have which label values?
    # ==========================================================================
    log("=" * 120)
    log("10. BLOCKS GROUPED BY byte[216:218] (label index)")
    log("=" * 120)
    log()

    # Group blocks by their byte[216:218] value
    by_label = defaultdict(list)
    for bi, off, data in uniform_blocks:
        label = struct.unpack_from("<H", data, LABEL_INDEX_OFF)[0]
        by_label[label].append((bi, off, data))

    for label_val in sorted(by_label.keys()):
        blocks = by_label[label_val]
        label_name = STRING_TABLE.get(label_val, "")
        log(f"Label {label_val} ({label_name}): {len(blocks)} blocks")
        if label_val in STRING_TABLE and len(blocks) <= 30:
            # Show key fields for these blocks
            for bi, off, data in blocks:
                state_id = struct.unpack_from("<H", data, SOURCE_ID_OFF)[0]
                hash_val = struct.unpack_from("<I", data, 20)[0]
                b221 = data[225]
                b225 = data[229]
                b226 = data[230]
                b227 = data[231]
                log(f"  Block {bi:3d}: state_id=0x{state_id:04X}({state_id}), "
                    f"hash=0x{hash_val:08X}, b221=0x{b221:02X}, "
                    f"b225=0x{b225:02X}, b226=0x{b226:02X}, b227=0x{b227:02X}")
        log()

    # ==========================================================================
    # 11. THE NON-UNIFORM BLOCKS — WHAT ARE THE EXCEPTIONS?
    # ==========================================================================
    log("=" * 120)
    log("11. NON-UNIFORM BLOCKS (not 260 bytes)")
    log("=" * 120)
    log()

    for i in range(len(m0_offsets)-1):
        d = dists[i]
        if d != 260:
            off = m0_offsets[i]
            end = m0_offsets[i+1]
            log(f"Block {i}: M0%D at +{off:06X}, size={d} bytes")
            # Show first 80 bytes
            log(hexdump(cond[off:min(off+80, cond_len)], COND_START + off, 80))
            # And the tail before next M0%D
            tail_start = max(off, end - 48)
            log(f"  Tail (last 48 bytes before next M0%D):")
            log(hexdump(cond[tail_start:end], COND_START + tail_start))
            log()

    # Also show what's after the LAST M0%D
    last_off = m0_offsets[-1]
    tail_len = cond_len - last_off
    log(f"AFTER LAST M0%D at +{last_off:06X}: {tail_len} bytes remaining")
    log(f"First 160 bytes of tail:")
    log(hexdump(cond[last_off:min(last_off+160, cond_len)], COND_START + last_off, 160))
    log()

    # ==========================================================================
    # 12. THE PREAMBLE STRUCTURE
    # ==========================================================================
    log("=" * 120)
    log("12. PREAMBLE STRUCTURE (130 bytes before first M0%D)")
    log("=" * 120)
    log()

    preamble = cond[:m0_offsets[0]]
    log(f"Preamble: {len(preamble)} bytes")
    log()

    # The preamble starts with what looks like the tail of the state section:
    # 80 3F = 0.5f (or half of a prior record)
    # Then: FB 61 1E 04 = hash/ID
    # Then zeros, then:
    # 80 3F 00 00... = 0.5f again
    # Then: 04 00 01 00 70 02 00 00 = small values
    # Then: FF FF blocks with 01 00 00 00 XX 00 pattern

    log("Preamble as uint16 pairs:")
    for i in range(0, len(preamble), 4):
        if i + 4 > len(preamble):
            break
        v1 = struct.unpack_from("<H", preamble, i)[0]
        v2 = struct.unpack_from("<H", preamble, i+2)[0]
        u32 = struct.unpack_from("<I", preamble, i)[0]
        f32 = struct.unpack_from("<f", preamble, i)[0]
        fstr = f"{f32:.4f}" if abs(f32) < 1e8 else f"{f32:.2e}"
        log(f"  +{i:3d}: ({v1:5d}, {v2:5d})  u32={u32:10d}  f32={fstr}  hex={preamble[i:i+4].hex(' ').upper()}")
    log()

    # The pattern at offset 36 onwards:
    # FF FF FF FF  FF FF FF FF  FF FF FF FF  01 00 00 00
    # 01 00  FF FF FF FF FF FF FF FF FF FF FF FF  01 00 00 00
    # 02 00  FF FF ...
    # 03 00  FF FF ...
    # 00 00
    # This looks like: [4x FFFF padding] then entries [uint16 index, 12x FF padding, uint32(1)]

    log("Preamble entry table (starting at offset ~36):")
    off = 36
    # First 12 bytes are FFFFFFFF x3
    log(f"  Prefix: {preamble[off:off+16].hex(' ').upper()}")
    off += 16

    # Then entries
    entry_idx = 0
    while off + 16 <= len(preamble):
        entry = preamble[off:off+16]
        idx = struct.unpack_from("<H", entry, 0)[0]
        log(f"  Entry {entry_idx}: index={idx}, data={entry.hex(' ').upper()}")
        off += 16
        entry_idx += 1
        if off + 2 <= len(preamble):
            next_val = struct.unpack_from("<H", preamble, off)[0]
            if next_val == 0 and off + 2 == len(preamble):
                log(f"  Terminator: {preamble[off:].hex(' ').upper()}")
                break
    log()

    # ==========================================================================
    # 13. BLOCK byte[152:156] — THE VARIABLE UINT32 AFTER 0x0281676D
    # Cross-reference with state section data
    # ==========================================================================
    log("=" * 120)
    log("13. byte[152:156] — POSSIBLE TARGET STATE / TRANSITION ID")
    log("=" * 120)
    log()

    for idx, (bi, off, data) in enumerate(uniform_blocks[:50]):
        state_id = struct.unpack_from("<H", data, SOURCE_ID_OFF)[0]
        label_idx = struct.unpack_from("<H", data, LABEL_INDEX_OFF)[0]
        v152 = struct.unpack_from("<I", data, 152)[0]
        hash20 = struct.unpack_from("<I", data, 20)[0]
        v76 = struct.unpack_from("<I", data, 76)[0]
        log(f"  Block {bi:3d}: state_id={state_id:5d}, label={label_idx:3d}, "
            f"v152=0x{v152:08X}({v152:6d}), hash20=0x{hash20:08X}, v76=0x{v76:08X}")
    log()

    # ==========================================================================
    # 14. THE LARGE TAIL SECTION — ENTIRELY DIFFERENT FORMAT
    # ==========================================================================
    log("=" * 120)
    log("14. TAIL SECTION DEEP DIVE (after last M0%D block)")
    log("=" * 120)
    log()

    # The tail after the last M0%D (at +0x0805E6) is 97021 bytes
    # This is a completely different format from the 260-byte blocks
    tail_start = m0_offsets[-1]
    tail = cond[tail_start:]
    log(f"Tail starts at section+0x{tail_start:06X} (file 0x{COND_START+tail_start:08X})")
    log(f"Tail size: {len(tail)} bytes")
    log()

    # Scan for sub-section boundaries in the tail
    # Look for M0%D in the tail (we know there's one at the start)
    tail_m0 = []
    pos = 0
    while True:
        idx = tail.find(magic_m0, pos)
        if idx == -1:
            break
        tail_m0.append(idx)
        pos = idx + 1

    log(f"M0%D markers in tail: {len(tail_m0)} at offsets {tail_m0[:20]}")
    log()

    # Look for 1.0f (0x3F800000) markers — the hex dump showed "80 3F" patterns
    marker_1f = b'\x00\x00\x80\x3F'
    tail_1f = []
    pos = 0
    while True:
        idx = tail.find(marker_1f, pos)
        if idx == -1:
            break
        tail_1f.append(idx)
        pos = idx + 1
    log(f"1.0f markers in tail: {len(tail_1f)}")
    if tail_1f:
        log(f"  First 20 offsets: {tail_1f[:20]}")
    log()

    # The tail hex shows patterns like:
    # 60 00 00 00 00 00 02 00 00 00 01 00 00 00
    # 36 00 00 00 00 00 02 00
    # This looks like: [uint16 index] [00 00 00 00] [uint16 type] [00] [uint16 flags]

    # Let's parse the first few hundred bytes of the tail more carefully
    log("Tail parsed as potential records:")
    log()

    # First entry: M0%D + data
    t_off = 0
    log(f"Tail entry 0 (M0%D header):")
    log(hexdump(tail[0:96], COND_START + tail_start, 96))
    log()
    log(f"  M0%D[0:4], then byte[4]={tail[4]:02X} byte[5]={tail[5]:02X} byte[6]={tail[6]:02X}")
    log(f"  uint16[4:6]={struct.unpack_from('<H', tail, 4)[0]}")
    log(f"  This last block has byte[4:6] = 0x{tail[4]:02X}{tail[5]:02X} = 0x001E = 30")
    log()

    # Find patterns: look for 0x0002 as uint16 (appeared in block headers)
    log("Scanning tail for pattern [uint8/uint16] [00 00 00 00] [02 00]:")
    matches = []
    for i in range(len(tail) - 8):
        if tail[i+2:i+6] == b'\x00\x00\x00\x00' and tail[i+6:i+8] == b'\x02\x00':
            matches.append(i)
    log(f"  Found {len(matches)} matches")
    for m in matches[:20]:
        log(f"    tail+{m:5d}: {tail[m:m+16].hex(' ').upper()}")
    log()

    # ==========================================================================
    # 15. SUMMARY OF DISCOVERED STRUCTURE
    # ==========================================================================
    log("=" * 120)
    log("15. SUMMARY — DISCOVERED BLOCK STRUCTURE")
    log("=" * 120)
    log()

    log("260-BYTE CONDITION NODE BLOCK (M0%D-anchored):")
    log()
    log("OFFSET  SIZE  TYPE       FIXED?  DESCRIPTION")
    log("-" * 80)
    log("[  0:4 ]   4  magic      FIXED   'M0%D' (0x44253044) — block signature")
    log("[  4:6 ]   2  uint16     FIXED   version/type = 2")
    log("[  6:8 ]   2  uint16     FIXED   always 0")
    log("[  8   ]   1  uint8      VAR     flags (mostly 1)")
    log("[  9   ]   1  uint8      VAR     sub-flags (0x02, 0x08, 0x10, etc)")
    log("[ 10:12]   2  uint16     VAR     parameter A")
    log("[ 12:16]   4  uint32     MOSTLY0 parameter B")
    log("[ 16:20]   4  uint32     MOSTLY0 parameter C")
    log("[ 20:24]   4  uint32     VAR     HASH / animation ID")
    log("[ 24:28]   4  uint32     MOSTLY0 secondary hash")
    log("[ 28:32]   4  uint32     MOSTLY0 (reserved)")
    log("[ 32:36]   4  uint32     FIXED   0xFFFFFFFF sentinel")
    log("[ 36:76]  40  pad        FIXED   40 bytes of zeros")
    log("[ 76:80]   4  uint32     VAR     timing/priority value")
    log("[ 80:84]   4  uint32     FIXED   0x00000000")
    log("[ 84:88]   4  magic      FIXED   0xEF8FF582 — internal marker")
    log("[ 88:112] 24  pad        FIXED   24 bytes of zeros")
    log("[112:116]  4  float32    FIXED   -1.0 (0x0000_80BF) sentinel")
    log("[116:120]  4  uint32     FIXED   0x00000000")
    log("[120:124]  4  float32    FIXED   FLT_MAX (0xFFFF7F7F) — 'no threshold'")
    log("[124:128]  4  float32    FIXED   -1.0 sentinel")
    log("[128:132]  4  float32    FIXED   -1.0 sentinel")
    log("[132:136]  4  uint32     FIXED   0x00000000")
    log("[136:140]  4  uint32     FIXED   0x00000017 (23) — condition graph type enum")
    log("[140:144]  4  uint32     FIXED   0x00000000")
    log("[144:148]  4  float32    FIXED   -1.0 sentinel")
    log("[148:152]  4  uint32     ~FIXED  0x0281676D — hash/type marker")
    log("[152:156]  4  uint32     VAR     ** TARGET STATE / TRANSITION REF **")
    log("[156:172] 16  pad        FIXED   zeros")
    log("[172:176]  4  uint32     FIXED   0x00000004 — field count?")
    log("[176:196] 20  pad        FIXED   zeros")
    log("[196:200]  4  uint32     FIXED   0x00000000")
    log("[200:204]  4  float32    FIXED   -1.0 sentinel")
    log("[204:208]  4  uint32     FIXED   0x00000000")
    log("[208:212]  4  uint32     VAR?    reserved / pre-condition slot")
    log("[212:214]  2  uint16     VAR     ** SOURCE STATE/NODE ID **")
    log("[214:216]  2  uint16     FIXED   0xFFFF sentinel")
    log("[216:218]  2  uint16     VAR     ** LABEL INDEX ** (string table ref)")
    log("[218:220]  2  uint16     FIXED   0xFFFF sentinel")
    log("[220:222]  2  uint16     FIXED   0x0000")
    log("[222:224]  2  uint16     FIXED   0x0001")
    log("[224:226]  2  uint16     VAR     condition opcode (0x2902 / 0x2903 / 0x0002)")
    log("[226:229]  3  bytes      FIXED   [0x05, 0x0B, 0x0C] — opcode suffix")
    log("[229:232]  3  bytes      VAR     condition parameters")
    log("[232:238]  6  bytes      ~FIXED  [0x01, 0x02, 0x05, 0xFF, 0xFF, 0x00]")
    log("[238:240]  2  bytes      FIXED   [0x00, 0xFF]")
    log("[240:244]  4  bytes      FIXED   [0x03, 0x05, 0x04, 0x00]")
    log("[244:248]  4  float32    FIXED   -1.0 sentinel")
    log("[248:252]  4  uint32     VAR     post-condition value A")
    log("[252:256]  4  bytes      VAR     post-condition value B (flags/bitfield)")
    log("[256:260]  4  bytes      VAR     post-condition value C")
    log()

    log("KEY FINDINGS:")
    log()
    log("1. Each 260-byte block is a CONDITION NODE linking a state to a transition trigger.")
    log("2. byte[212:214] = source state/node identifier (uint16)")
    log("3. byte[216:218] = string table label index = condition operand / key ref")
    log("4. byte[152:156] = possible target state reference")
    log("5. byte[224:232] = condition opcode + parameters")
    log("6. 623 uniform blocks + ~28 non-uniform blocks + 97KB tail section")
    log("7. The tail section (97KB) uses a DIFFERENT format (variable-length records)")
    log()

    log("LABEL INDEX DISTRIBUTION (= which input keys have conditions):")
    for val, cnt in sorted(label_vals.items(), key=lambda x: -x[1]):
        name = STRING_TABLE.get(val, f"label_{val}")
        log(f"  {val:3d} ({name:20s}): {cnt:4d} blocks")
    log()

    # ==========================================================================
    # Save
    # ==========================================================================
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    print(f"\n\nResults saved to {OUTPUT}")
    print(f"Total output: {len(out_lines)} lines")

if __name__ == "__main__":
    main()
