#!/usr/bin/env python3
"""
Deep analysis of gap regions in .paac condition sections.
Analyzes sword_upper.paac and battleaxe_upper.paac gap bytecode.
"""

import struct
import sys
import math
from pathlib import Path
from collections import Counter

BASE = Path(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel")
SWORD = BASE / "extracted" / "actionchart" / "bin__" / "upperaction" / "1_pc" / "1_phm" / "sword_upper.paac"
BATTLEAXE = BASE / "extracted" / "actionchart" / "bin__" / "upperaction" / "1_pc" / "1_phm" / "battleaxe_upper.paac"
OUTPUT = BASE / "tools" / "gap_analysis_results.txt"

# Gap definitions: (file, label, file_offset, size)
GAPS = [
    ("sword", "common_upper_branchset", 0xF4C60, 107156),
    ("sword", "BothHands", 0xBFED4, 216460),
    ("battleaxe", "common_upper_branchset", None, None),  # will be discovered
]

# Known sword node IDs
KNOWN_NODES = {0, 88, 94, 100, 106, 112, 137, 286, 344, 349, 430, 875, 1055, 1073, 1100}

lines = []

def out(s=""):
    print(s)
    lines.append(s)

def hex_dump(data, offset=0, max_bytes=320, annotations=None):
    """Hex dump with optional annotations."""
    annotations = annotations or {}
    result = []
    for i in range(0, min(len(data), max_bytes), 16):
        hex_part = " ".join(f"{data[i+j]:02X}" if i+j < len(data) else "  " for j in range(16))
        ascii_part = "".join(chr(data[i+j]) if 32 <= data[i+j] < 127 else "." for j in range(16) if i+j < len(data))
        line = f"  {offset+i:08X}: {hex_part}  |{ascii_part}|"
        # Check for annotations at this offset range
        for off, note in annotations.items():
            if i <= off < i + 16:
                line += f"  <- {note}"
                break
        result.append(line)
    return "\n".join(result)

def find_gap_in_battleaxe(data):
    """Find the common_upper_branchset gap in battleaxe by searching for the label."""
    # Search for "common_upper_branchset" string
    label = b"common_upper_branchset"
    idx = data.find(label)
    if idx == -1:
        return None, None
    # The gap likely starts near this label - scan backwards to find the M0%D or gap start
    # Actually, let's search for the pattern more carefully
    # Look for all occurrences
    positions = []
    start = 0
    while True:
        pos = data.find(label, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    out(f"  Found '{label.decode()}' at positions: {[hex(p) for p in positions]}")

    # For each position, try to determine the gap boundaries
    # Look backwards from label for a recognizable header pattern
    if positions:
        # Use the first occurrence - look at surrounding context
        pos = positions[0]
        # Dump context around the label
        ctx_start = max(0, pos - 64)
        out(f"  Context around label at 0x{pos:X}:")
        out(hex_dump(data[ctx_start:ctx_start+256], ctx_start))

    return positions[0] if positions else None, None

def parse_header_fields(data, gap_start, gap_size, label):
    """Parse first 260 bytes of gap as potential header fields."""
    out(f"\n  --- Header Field Analysis (first 260 bytes) ---")
    header = data[:260]

    # Check for M0%D magic
    magic = header[:4]
    out(f"  Magic: {magic} (hex: {magic.hex()})")

    # Parse at every 4-byte aligned offset
    out(f"\n  Offset  | uint8  | uint16LE | uint32LE   | float32    | Interpretation")
    out(f"  -------+--------+----------+------------+------------+----------------")

    interesting = {}
    for off in range(4, min(260, len(header)), 4):
        if off + 4 > len(header):
            break
        u8 = header[off]
        u16 = struct.unpack_from('<H', header, off)[0]
        u32 = struct.unpack_from('<I', header, off)[0]
        f32 = struct.unpack_from('<f', header, off)[0]

        interp = []
        if 1 <= u32 <= 5000:
            interp.append(f"COUNT?")
            # Test if count * record_size = gap_size - header_overhead
            for hdr_sz in [260, 128, 64, 32, 16, 4]:
                remaining = gap_size - hdr_sz
                if remaining > 0 and u32 > 0 and remaining % u32 == 0:
                    rec_sz = remaining // u32
                    if 1 <= rec_sz <= 500:
                        interp.append(f"{u32}×{rec_sz}={remaining} (hdr={hdr_sz})")
        if 0 < u32 < gap_size:
            interp.append(f"OFFSET?")
        if f32 == -1.0:
            interp.append("SENTINEL -1.0f")
        elif f32 == 0.0:
            interp.append("zero float")
        elif f32 == 1.0:
            interp.append("1.0f")
        elif 0.0 < f32 < 100.0 and not math.isnan(f32) and not math.isinf(f32):
            interp.append(f"small float")

        if interp or off <= 0x60:
            interpretation = "; ".join(interp) if interp else ""
            out(f"  0x{off:04X} | {u8:6d} | {u16:8d} | {u32:10d} | {f32:10.4f} | {interpretation}")
            if interp:
                interesting[off] = interpretation

    # Specifically test offset 0x54
    if len(header) > 0x58:
        val_54 = struct.unpack_from('<I', header, 0x54)[0]
        out(f"\n  Header[0x54] = {val_54}")
        out(f"  Testing val × record_size = gap_size:")
        for rs in range(1, 501):
            total = val_54 * rs
            if abs(total - gap_size) < 260:  # Allow header overhead
                out(f"    {val_54} × {rs} = {total} (gap={gap_size}, diff={gap_size-total})")

    return interesting

def find_sentinel_positions(data, gap_size):
    """Find all sentinel float positions."""
    sentinels = {
        "-1.0f": struct.pack('<f', -1.0),
        "FLT_MAX": b'\xff\xff\x7f\x7f',
        "0.0f": struct.pack('<f', 0.0),
        "1.0f": struct.pack('<f', 1.0),
    }

    results = {}
    for name, pattern in sentinels.items():
        positions = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1 or pos >= gap_size:
                break
            positions.append(pos)
            start = pos + 1
        results[name] = positions
        out(f"  {name}: {len(positions)} occurrences")
        if len(positions) > 0 and len(positions) <= 30:
            out(f"    Positions: {[hex(p) for p in positions]}")
        elif len(positions) > 30:
            # Show spacing analysis
            spacings = [positions[i+1] - positions[i] for i in range(min(len(positions)-1, 200))]
            spacing_counts = Counter(spacings)
            top_spacings = spacing_counts.most_common(10)
            out(f"    First 5 positions: {[hex(p) for p in positions[:5]]}")
            out(f"    Top spacings: {[(s, c) for s, c in top_spacings]}")

    return results

def find_zero_runs(data, gap_size, min_len=8):
    """Find runs of zero bytes."""
    runs = []
    i = 0
    while i < min(len(data), gap_size):
        if data[i] == 0:
            j = i
            while j < min(len(data), gap_size) and data[j] == 0:
                j += 1
            if j - i >= min_len:
                runs.append((i, j - i))
            i = j
        else:
            i += 1
    return runs

def xor_autocorrelation(data, max_period=600, min_period=16, window=20000):
    """Sliding-window XOR autocorrelation to find record size."""
    window = min(window, len(data))
    best_period = 0
    best_score = float('inf')
    scores = []

    for period in range(min_period, max_period + 1):
        xor_sum = 0
        count = 0
        for i in range(min(window - period, 15000)):
            xor_sum += bin(data[i] ^ data[i + period]).count('1')  # popcount of XOR
            count += 1
        if count > 0:
            score = xor_sum / count
            scores.append((period, score))
            if score < best_score:
                best_score = score
                best_period = period

    # Sort by score and show top 20
    scores.sort(key=lambda x: x[1])
    return best_period, best_score, scores[:20]

def extract_records(data, period, count=10, start_offset=0):
    """Extract records at given period."""
    records = []
    for i in range(count):
        off = start_offset + i * period
        if off + period > len(data):
            break
        records.append(data[off:off+period])
    return records

def find_fixed_vs_variable(records, period):
    """Identify fixed and variable bytes across records."""
    if not records:
        return [], []
    fixed = []
    variable = []
    for byte_pos in range(min(period, len(records[0]))):
        values = set()
        for rec in records:
            if byte_pos < len(rec):
                values.add(rec[byte_pos])
        if len(values) == 1:
            fixed.append(byte_pos)
        else:
            variable.append(byte_pos)
    return fixed, variable

def search_inline_transitions(data, gap_size):
    """Search for inline transition signatures."""
    matches = []
    for i in range(0, min(len(data), gap_size) - 16, 4):
        # [float32 thresh 0.0-2.0] [float32 -1.0] [uint32 target <50000] [uint32 seq <5000]
        thresh = struct.unpack_from('<f', data, i)[0]
        neg1 = struct.unpack_from('<f', data, i+4)[0]
        target = struct.unpack_from('<I', data, i+8)[0]
        seq = struct.unpack_from('<I', data, i+12)[0]

        if 0.0 <= thresh <= 2.0 and neg1 == -1.0 and target < 50000 and seq < 5000:
            verified = target in KNOWN_NODES
            matches.append((i, thresh, target, seq, verified))

    return matches

def compute_entropy(data, window=256):
    """Compute Shannon entropy per window."""
    entropies = []
    for i in range(0, len(data), window):
        chunk = data[i:i+window]
        if len(chunk) < window // 2:
            break
        counts = Counter(chunk)
        total = len(chunk)
        entropy = 0.0
        for c in counts.values():
            p = c / total
            if p > 0:
                entropy -= p * math.log2(p)
        entropies.append(entropy)
    return entropies

def entropy_heatmap(entropies, width=80):
    """Create character-based entropy heatmap."""
    chars = " ._-=+*#@"  # low to high entropy
    result_lines = []
    for i in range(0, len(entropies), width):
        row = entropies[i:i+width]
        line = ""
        for e in row:
            idx = min(int(e / 8.0 * len(chars)), len(chars) - 1)
            line += chars[idx]
        offset = i * 256
        result_lines.append(f"  {offset:08X}: |{line}|")
    return "\n".join(result_lines)


def analyze_gap(file_data, file_name, gap_label, gap_offset, gap_size):
    """Full analysis of a single gap region."""
    out(f"\n{'='*80}")
    out(f"GAP ANALYSIS: {file_name} / {gap_label}")
    out(f"  File offset: 0x{gap_offset:X}, Size: {gap_size} bytes ({gap_size/1024:.1f} KB)")
    out(f"{'='*80}")

    gap_data = file_data[gap_offset:gap_offset + gap_size]
    if len(gap_data) < gap_size:
        out(f"  WARNING: Only got {len(gap_data)} bytes (expected {gap_size})")
        gap_size = len(gap_data)

    # === 1. Header Analysis ===
    out(f"\n[1] HEADER ANALYSIS")
    out(f"\n  First 320 bytes hex dump:")

    # Build annotations
    annotations = {}
    if len(gap_data) >= 4:
        annotations[0] = f"Magic: {gap_data[:4]}"

    out(hex_dump(gap_data, gap_offset, 320, annotations))

    parse_header_fields(gap_data, gap_offset, gap_size, gap_label)

    # === 2. Structural Segmentation ===
    out(f"\n[2] STRUCTURAL SEGMENTATION")

    sentinel_info = find_sentinel_positions(gap_data, gap_size)

    # Zero runs
    zero_runs = find_zero_runs(gap_data, gap_size)
    out(f"\n  Zero-byte runs (>= 8 bytes): {len(zero_runs)}")
    if zero_runs:
        out(f"  Run lengths: {Counter(r[1] for r in zero_runs).most_common(15)}")
        if len(zero_runs) <= 30:
            for off, length in zero_runs:
                out(f"    @0x{off:06X}: {length} zeros")
        else:
            out(f"    First 10:")
            for off, length in zero_runs[:10]:
                out(f"    @0x{off:06X}: {length} zeros")

    # Segment map: identify data vs padding
    out(f"\n  Segment map (first 4KB):")
    seg_size = 64
    for i in range(0, min(4096, gap_size), seg_size):
        chunk = gap_data[i:i+seg_size]
        nz = sum(1 for b in chunk if b != 0)
        bar = '#' * (nz * 40 // seg_size) + '.' * (40 - nz * 40 // seg_size)
        out(f"    {i:06X}: [{bar}] {nz}/{seg_size} non-zero")

    # === 3. Sub-Record Discovery ===
    out(f"\n[3] SUB-RECORD DISCOVERY (XOR Autocorrelation)")

    # Skip potential header for autocorrelation
    skip = 260 if gap_size > 2000 else 0
    acorr_data = gap_data[skip:]
    best_period, best_score, top_scores = xor_autocorrelation(acorr_data)

    out(f"  Best period: {best_period} bytes (avg XOR bits: {best_score:.3f})")
    out(f"  Top 20 candidate periods:")
    for period, score in top_scores:
        marker = " <<<" if period == best_period else ""
        # Check if it's a multiple/divisor of best
        if period != best_period:
            if best_period % period == 0:
                marker = f" (1/{best_period//period} of best)"
            elif period % best_period == 0:
                marker = f" ({period//best_period}x best)"
        out(f"    Period {period:4d}: score {score:.3f}{marker}")

    # Extract records at best period
    if best_period > 0 and gap_size > best_period * 3:
        records = extract_records(acorr_data, best_period, count=10)
        out(f"\n  Extracted {len(records)} records at period {best_period}:")

        # Print side by side (first 64 bytes)
        show_bytes = min(64, best_period)
        out(f"\n  First {show_bytes} bytes of each record:")
        out(f"  {'Offset':>8s} | " + " | ".join(f"Rec{i:2d}" for i in range(min(len(records), 10))))
        for byte_pos in range(show_bytes):
            vals = [f"{rec[byte_pos]:02X}" if byte_pos < len(rec) else "  " for rec in records[:10]]
            out(f"  {byte_pos:8d} | " + " |   ".join(vals))

        # Fixed vs variable
        fixed, variable = find_fixed_vs_variable(records, best_period)
        out(f"\n  Fixed bytes: {len(fixed)}/{best_period} ({100*len(fixed)/best_period:.1f}%)")
        out(f"  Variable bytes: {len(variable)}/{best_period} ({100*len(variable)/best_period:.1f}%)")
        if fixed and len(fixed) <= 100:
            out(f"  Fixed positions: {fixed}")
            out(f"  Fixed values: {[f'{records[0][p]:02X}' for p in fixed[:60]]}")
        if variable and len(variable) <= 100:
            out(f"  Variable positions: {variable}")

    # === 5. Inline Transition Search ===
    out(f"\n[5] INLINE TRANSITION SEARCH")
    transitions = search_inline_transitions(gap_data, gap_size)
    out(f"  Found {len(transitions)} candidate transitions")
    verified = [t for t in transitions if t[4]]
    out(f"  Verified (target in known nodes): {len(verified)}")

    if verified:
        out(f"\n  VERIFIED inline transitions:")
        for off, thresh, target, seq, v in verified[:50]:
            out(f"    @0x{off:06X}: thresh={thresh:.3f}, target_node={target}, seq={seq}")

    if transitions and not verified:
        out(f"\n  Top 30 unverified candidates:")
        for off, thresh, target, seq, v in transitions[:30]:
            out(f"    @0x{off:06X}: thresh={thresh:.3f}, target_node={target}, seq={seq}")

    # === 6. Entropy Map ===
    out(f"\n[6] ENTROPY MAP (256-byte windows)")
    entropies = compute_entropy(gap_data)
    if entropies:
        avg_e = sum(entropies) / len(entropies)
        min_e = min(entropies)
        max_e = max(entropies)
        out(f"  Avg entropy: {avg_e:.2f} bits, Min: {min_e:.2f}, Max: {max_e:.2f}")

        # Find high/low regions
        high_regions = [(i*256, e) for i, e in enumerate(entropies) if e > 6.0]
        low_regions = [(i*256, e) for i, e in enumerate(entropies) if e < 2.0]
        out(f"  High entropy windows (>6.0): {len(high_regions)}")
        out(f"  Low entropy windows (<2.0): {len(low_regions)}")

        out(f"\n  Heatmap (space=0, @=8 bits):")
        out(entropy_heatmap(entropies))

    return gap_data


def discover_battleaxe_gap(data):
    """Find common_upper_branchset gap in battleaxe."""
    # Search for the label string
    label = b"common_upper_branchset"
    positions = []
    start = 0
    while True:
        pos = data.find(label, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1

    if not positions:
        out("  Could not find 'common_upper_branchset' in battleaxe!")
        return None, None

    out(f"  Found label at: {[hex(p) for p in positions]}")

    # The gap region likely starts with M0%D magic or a recognizable header
    # near the label. Let's look backwards from the label for context.
    pos = positions[0]

    # Scan backwards from label to find start of this block
    # The label is likely embedded in the header of the gap
    # Let's look at what's before the label
    pre_start = max(0, pos - 128)
    out(f"  Context before label:")
    out(hex_dump(data[pre_start:pos+64], pre_start, pos - pre_start + 64))

    # Look for M0%D near the label
    search_start = max(0, pos - 512)
    m0d_pos = data.rfind(b'M0%D', search_start, pos)
    if m0d_pos == -1:
        # Try searching forward
        m0d_pos = data.find(b'M0%D', pos, pos + 512)

    if m0d_pos != -1:
        out(f"  Nearest M0%D at: 0x{m0d_pos:X}")

    # Actually, let's find ALL M0%D blocks and identify which one corresponds to the gap
    # The gap is a non-uniform block between uniform 260-byte M0%D blocks
    # We need to find a stretch where the distance between consecutive M0%D markers is > 260

    m0d_positions = []
    s = 0
    while True:
        p = data.find(b'M0%D', s)
        if p == -1:
            break
        m0d_positions.append(p)
        s = p + 1

    out(f"  Total M0%D markers: {len(m0d_positions)}")

    # Find gaps > 260 between consecutive M0%D markers
    large_gaps = []
    for i in range(len(m0d_positions) - 1):
        dist = m0d_positions[i+1] - m0d_positions[i]
        if dist > 300:  # significantly more than 260
            large_gaps.append((m0d_positions[i], dist, i))

    out(f"  Large gaps (>300 bytes between M0%D markers): {len(large_gaps)}")
    for gstart, gsize, idx in large_gaps:
        out(f"    M0%D[{idx}] at 0x{gstart:X}, next at 0x{gstart+gsize:X}, gap={gsize} bytes")
        # Check if label is in this gap
        if gstart <= pos < gstart + gsize:
            out(f"    ^^^ Contains 'common_upper_branchset' label!")

    # Find the gap that contains the label
    for gstart, gsize, idx in large_gaps:
        if gstart <= pos < gstart + gsize:
            return gstart, gsize

    # If label not in a gap, use the largest gap
    if large_gaps:
        gstart, gsize, idx = max(large_gaps, key=lambda x: x[1])
        out(f"  Using largest gap: 0x{gstart:X}, size={gsize}")
        return gstart, gsize

    return None, None


def main():
    out("=" * 80)
    out("PAAC GAP BYTECODE DEEP ANALYSIS")
    out("=" * 80)

    # Load files
    sword_data = SWORD.read_bytes()
    battleaxe_data = BATTLEAXE.read_bytes()
    out(f"Loaded sword_upper.paac: {len(sword_data)} bytes")
    out(f"Loaded battleaxe_upper.paac: {len(battleaxe_data)} bytes")

    # === Analyze sword gaps ===

    # Gap 1: common_upper_branchset at 0xF4C60, 107156 bytes
    sword_gap1_data = analyze_gap(sword_data, "sword", "common_upper_branchset", 0xF4C60, 107156)

    # Gap 2: BothHands at 0xBFED4, 216460 bytes
    sword_gap2_data = analyze_gap(sword_data, "sword", "BothHands", 0xBFED4, 216460)

    # === Discover and analyze battleaxe gap ===
    out(f"\n{'='*80}")
    out("DISCOVERING BATTLEAXE GAP")
    out(f"{'='*80}")

    ba_gap_offset, ba_gap_size = discover_battleaxe_gap(battleaxe_data)

    ba_gap_data = None
    if ba_gap_offset is not None and ba_gap_size is not None:
        out(f"\n  Battleaxe gap: offset=0x{ba_gap_offset:X}, size={ba_gap_size}")
        ba_gap_data = analyze_gap(battleaxe_data, "battleaxe", "common_upper_branchset", ba_gap_offset, ba_gap_size)
    else:
        out("  Could not determine battleaxe gap boundaries!")
        # Try known offset from user info: 22100 bytes
        out("  Searching for any large non-M0%D region...")

    # === 4. Cross-Gap Comparison ===
    out(f"\n{'='*80}")
    out("[4] CROSS-GAP COMPARISON: sword vs battleaxe common_upper_branchset")
    out(f"{'='*80}")

    if sword_gap1_data is not None and ba_gap_data is not None:
        sword_hdr = sword_gap1_data[:260]
        ba_hdr = ba_gap_data[:260]

        out(f"\n  Byte-level diff of first {min(260, len(ba_hdr))} bytes:")
        diff_count = 0
        for i in range(min(260, len(sword_hdr), len(ba_hdr))):
            if sword_hdr[i] != ba_hdr[i]:
                # Also show as uint32 if aligned
                s_ctx = ""
                b_ctx = ""
                if i % 4 == 0 and i + 4 <= len(sword_hdr):
                    s_u32 = struct.unpack_from('<I', sword_hdr, i)[0]
                    b_u32 = struct.unpack_from('<I', ba_hdr, i)[0]
                    s_f32 = struct.unpack_from('<f', sword_hdr, i)[0]
                    b_f32 = struct.unpack_from('<f', ba_hdr, i)[0]
                    s_ctx = f" (u32={s_u32}, f32={s_f32:.4f})"
                    b_ctx = f" (u32={b_u32}, f32={b_f32:.4f})"
                out(f"    @0x{i:03X}: sword=0x{sword_hdr[i]:02X}{s_ctx}  ba=0x{ba_hdr[i]:02X}{b_ctx}")
                diff_count += 1
        out(f"  Total differing bytes: {diff_count}/260")

        # Check header[0x54] ratio
        if len(sword_hdr) >= 0x58 and len(ba_hdr) >= 0x58:
            s_val = struct.unpack_from('<I', sword_hdr, 0x54)[0]
            b_val = struct.unpack_from('<I', ba_hdr, 0x54)[0]
            out(f"\n  Header[0x54]: sword={s_val}, battleaxe={b_val}")
            if b_val > 0:
                out(f"  Ratio: {s_val/b_val:.4f}")
                sword_gap_size = 107156
                ba_gap_size_actual = len(ba_gap_data)
                if ba_gap_size_actual > 0:
                    out(f"  Gap size ratio: {sword_gap_size/ba_gap_size_actual:.4f}")
                    out(f"  Match? {'YES' if abs(s_val/b_val - sword_gap_size/ba_gap_size_actual) < 0.01 else 'NO'}")

    # === Summary ===
    out(f"\n{'='*80}")
    out("SUMMARY")
    out(f"{'='*80}")
    out(f"Analyzed 3 gap regions across 2 files.")
    out(f"Results saved to: {OUTPUT}")

    # Write output
    OUTPUT.write_text("\n".join(lines), encoding='utf-8')
    out(f"\nDone. Output saved to {OUTPUT}")


if __name__ == "__main__":
    main()
