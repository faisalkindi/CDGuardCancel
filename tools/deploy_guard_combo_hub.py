#!/usr/bin/env python3
"""
CDAnimCancel - Guard Cancel from Combo Hub
Deploys a PAZ patch that inserts guard sub-blocks into State 328 (combo hub)
of sword_upper.paac, allowing block (LB) to cancel sword attack combos.

Usage: py -3 tools/deploy_guard_combo_hub.py
"""

import struct
import os
import sys
import shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paz_parse import parse_pamt

try:
    import lz4.block
except ImportError:
    print("ERROR: lz4 not installed. Run: py -3 -m pip install lz4")
    input("Press Enter to close...")
    sys.exit(1)

# ── Paths ──────────────────────────────────────────────────────────────────────
PAZ_PATH  = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.paz"
PAMT_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.pamt"
PAPGT_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\meta\0.papgt"

# ── sword_upper.paac record ───────────────────────────────────────────────────
SWORD_PAZ_OFFSET   = 225322576
SWORD_COMP_SIZE    = 224084
SWORD_DECOMP_SIZE  = 1243769

# ── State offsets (in decompressed data) ──────────────────────────────────────
STATE7_FILE_OFFSET   = 0x036285
STATE7_GUARD_INTERNAL = 0x0665   # guard blocks start at state7 + 0x0665
STATE328_FILE_OFFSET = 0x08D2A7
STATE328_SIZE        = 42865     # 0xA771 bytes
STATE328_FOOTER_INTERNAL = 0xA719  # insert point (before footer)

GUARD_BLOCK_SIZE = 88   # each guard sub-block
GUARD_BLOCK_COUNT = 3
GUARD_TOTAL_SIZE = GUARD_BLOCK_SIZE * GUARD_BLOCK_COUNT  # 264

# ── hashlittle (Bob Jenkins' lookup3) ─────────────────────────────────────────
def hashlittle(data, initval):
    length = len(data)
    a = b = c = (0xDEADBEEF + length + initval) & 0xFFFFFFFF
    i = 0
    while length > 12:
        a = (a + (data[i] | (data[i+1]<<8) | (data[i+2]<<16) | (data[i+3]<<24))) & 0xFFFFFFFF
        b = (b + (data[i+4] | (data[i+5]<<8) | (data[i+6]<<16) | (data[i+7]<<24))) & 0xFFFFFFFF
        c = (c + (data[i+8] | (data[i+9]<<8) | (data[i+10]<<16) | (data[i+11]<<24))) & 0xFFFFFFFF
        a=(a-c)&0xFFFFFFFF; a^=((c<<4)|(c>>28))&0xFFFFFFFF; c=(c+b)&0xFFFFFFFF
        b=(b-a)&0xFFFFFFFF; b^=((a<<6)|(a>>26))&0xFFFFFFFF; a=(a+c)&0xFFFFFFFF
        c=(c-b)&0xFFFFFFFF; c^=((b<<8)|(b>>24))&0xFFFFFFFF; b=(b+a)&0xFFFFFFFF
        a=(a-c)&0xFFFFFFFF; a^=((c<<16)|(c>>16))&0xFFFFFFFF; c=(c+b)&0xFFFFFFFF
        b=(b-a)&0xFFFFFFFF; b^=((a<<19)|(a>>13))&0xFFFFFFFF; a=(a+c)&0xFFFFFFFF
        c=(c-b)&0xFFFFFFFF; c^=((b<<4)|(b>>28))&0xFFFFFFFF; b=(b+a)&0xFFFFFFFF
        i += 12; length -= 12
    if length > 0:
        if length >= 1:  c = (c + data[i]) & 0xFFFFFFFF
        if length >= 2:  c = (c + (data[i+1] << 8)) & 0xFFFFFFFF
        if length >= 3:  c = (c + (data[i+2] << 16)) & 0xFFFFFFFF
        if length >= 4:  c = (c + (data[i+3] << 24)) & 0xFFFFFFFF
        if length >= 5:  b = (b + data[i+4]) & 0xFFFFFFFF
        if length >= 6:  b = (b + (data[i+5] << 8)) & 0xFFFFFFFF
        if length >= 7:  b = (b + (data[i+6] << 16)) & 0xFFFFFFFF
        if length >= 8:  b = (b + (data[i+7] << 24)) & 0xFFFFFFFF
        if length >= 9:  a = (a + data[i+8]) & 0xFFFFFFFF
        if length >= 10: a = (a + (data[i+9] << 8)) & 0xFFFFFFFF
        if length >= 11: a = (a + (data[i+10] << 16)) & 0xFFFFFFFF
        if length >= 12: a = (a + (data[i+11] << 24)) & 0xFFFFFFFF
        c ^= b; c = (c - ((b<<14) | (b>>18))) & 0xFFFFFFFF
        a ^= c; a = (a - ((c<<11) | (c>>21))) & 0xFFFFFFFF
        b ^= a; b = (b - ((a<<25) | (a>>7))) & 0xFFFFFFFF
        c ^= b; c = (c - ((b<<16) | (b>>16))) & 0xFFFFFFFF
        a ^= c; a = (a - ((c<<4) | (c>>28))) & 0xFFFFFFFF
        b ^= a; b = (b - ((a<<14) | (a>>18))) & 0xFFFFFFFF
        c ^= b; c = (c - ((b<<24) | (b>>8))) & 0xFFFFFFFF
    return c


def main():
    print("=" * 60)
    print("  CDAnimCancel - Guard Cancel from Combo Hub")
    print("  PAZ Patch Deployer")
    print("=" * 60)
    print()

    # ── Verify files exist ────────────────────────────────────────────────
    for path in [PAZ_PATH, PAMT_PATH, PAPGT_PATH]:
        if not os.path.isfile(path):
            print(f"ERROR: File not found: {path}")
            input("Press Enter to close...")
            sys.exit(1)

    old_paz_size = os.path.getsize(PAZ_PATH)
    print(f"[1/11] PAZ file size: {old_paz_size:,} bytes")

    # ── Step 1: Read and decompress sword_upper ───────────────────────────
    print(f"[2/11] Reading compressed sword_upper from PAZ offset {SWORD_PAZ_OFFSET}...")
    with open(PAZ_PATH, "rb") as f:
        f.seek(SWORD_PAZ_OFFSET)
        comp_data = f.read(SWORD_COMP_SIZE)

    if len(comp_data) != SWORD_COMP_SIZE:
        print(f"ERROR: Read {len(comp_data)} bytes, expected {SWORD_COMP_SIZE}")
        input("Press Enter to close...")
        sys.exit(1)

    print(f"       Decompressing ({SWORD_COMP_SIZE:,} -> {SWORD_DECOMP_SIZE:,})...")
    decomp = bytearray(lz4.block.decompress(comp_data, uncompressed_size=SWORD_DECOMP_SIZE))

    if len(decomp) != SWORD_DECOMP_SIZE:
        print(f"ERROR: Decompressed to {len(decomp)}, expected {SWORD_DECOMP_SIZE}")
        input("Press Enter to close...")
        sys.exit(1)
    print("       OK")

    # ── Step 2: Verify State 7's guard blocks ─────────────────────────────
    guard_src_offset = STATE7_FILE_OFFSET + STATE7_GUARD_INTERNAL  # 0x0368EA
    print(f"[3/11] Verifying State 7 guard blocks at file offset 0x{guard_src_offset:06X}...")

    guard_blocks_raw = bytes(decomp[guard_src_offset : guard_src_offset + GUARD_TOTAL_SIZE])

    # Each block should start with FF FF FF FF FF FF FF FF separator
    for i in range(GUARD_BLOCK_COUNT):
        block_start = i * GUARD_BLOCK_SIZE
        separator = guard_blocks_raw[block_start : block_start + 8]
        if separator != b'\xFF' * 8:
            print(f"ERROR: Guard block {i} separator mismatch at +{block_start}: {separator.hex()}")
            input("Press Enter to close...")
            sys.exit(1)
    print("       All 3 guard blocks verified (FF FF FF FF FF FF FF FF separators)")

    # Print original timing windows
    for i in range(GUARD_BLOCK_COUNT):
        block_start = i * GUARD_BLOCK_SIZE
        # Timing floats are typically at fixed offsets within the block
        # Search for float pairs in the block
        block = guard_blocks_raw[block_start : block_start + GUARD_BLOCK_SIZE]
        floats_found = []
        for off in range(8, GUARD_BLOCK_SIZE - 4, 4):
            val = struct.unpack_from("<f", block, off)[0]
            if 0.01 < val < 100.0:
                floats_found.append((off, val))
        print(f"       Block {i} floats: {[(f'@{o}={v:.3f}') for o, v in floats_found]}")

    # ── Step 3: Copy and modify guard blocks ──────────────────────────────
    print(f"[4/11] Copying guard blocks and modifying timing to 0.0 - 99.0...")
    guard_blocks = bytearray(guard_blocks_raw)

    # Modify timing windows in each block
    # Expected timing floats per the spec:
    #   Block 0: 0.667 - 1.133
    #   Block 1: 1.133 - 2.767
    #   Block 2: 0.067 - 0.400
    # We need to find and replace these with 0.0 and 99.0

    timing_pairs = [
        (0.667, 1.133),
        (1.133, 2.767),
        (0.067, 0.400),
    ]

    zero_f = struct.pack("<f", 0.0)
    ninety_nine_f = struct.pack("<f", 99.0)

    for i in range(GUARD_BLOCK_COUNT):
        block_start = i * GUARD_BLOCK_SIZE
        block = guard_blocks[block_start : block_start + GUARD_BLOCK_SIZE]
        start_val, end_val = timing_pairs[i]

        start_bytes = struct.pack("<f", start_val)
        end_bytes = struct.pack("<f", end_val)

        # Find and replace start timing
        start_found = False
        end_found = False
        for off in range(8, GUARD_BLOCK_SIZE - 4, 4):
            val = struct.unpack_from("<f", block, off)[0]
            if abs(val - start_val) < 0.002 and not start_found:
                guard_blocks[block_start + off : block_start + off + 4] = zero_f
                start_found = True
                print(f"       Block {i}: replaced start {val:.3f} -> 0.0 at block offset +{off}")
            elif abs(val - end_val) < 0.002 and not end_found:
                guard_blocks[block_start + off : block_start + off + 4] = ninety_nine_f
                end_found = True
                print(f"       Block {i}: replaced end {val:.3f} -> 99.0 at block offset +{off}")

        if not start_found or not end_found:
            print(f"WARNING: Block {i} - start_found={start_found}, end_found={end_found}")
            print(f"         Falling back to brute-force: replacing ALL timing-range floats")
            # Fallback: find any float in the expected range and replace
            # The timing window floats are the only small positive floats in these blocks
            small_floats = []
            for off in range(8, GUARD_BLOCK_SIZE - 4, 4):
                val = struct.unpack_from("<f", guard_blocks, block_start + off)[0]
                if 0.01 < val < 10.0:
                    small_floats.append((off, val))
            if len(small_floats) >= 2:
                # Smallest = start, next = end
                small_floats.sort(key=lambda x: x[1])
                off_s, val_s = small_floats[0]
                off_e, val_e = small_floats[1]
                guard_blocks[block_start + off_s : block_start + off_s + 4] = zero_f
                guard_blocks[block_start + off_e : block_start + off_e + 4] = ninety_nine_f
                print(f"         Block {i}: replaced {val_s:.3f} -> 0.0, {val_e:.3f} -> 99.0")

    # ── Step 4: Insert into State 328 ─────────────────────────────────────
    insert_file_offset = STATE328_FILE_OFFSET + STATE328_FOOTER_INTERNAL  # 0x0979C0
    print(f"[5/11] Inserting {GUARD_TOTAL_SIZE} bytes into State 328 at file offset 0x{insert_file_offset:06X}...")

    # Verify the insert point makes sense - check what's there
    pre_insert = decomp[insert_file_offset : insert_file_offset + 16]
    print(f"       Data at insert point: {pre_insert.hex()}")

    new_decomp = bytearray()
    new_decomp.extend(decomp[:insert_file_offset])
    new_decomp.extend(guard_blocks)
    new_decomp.extend(decomp[insert_file_offset:])

    new_decomp_size = len(new_decomp)
    print(f"       New decompressed size: {new_decomp_size:,} (was {SWORD_DECOMP_SIZE:,}, delta +{GUARD_TOTAL_SIZE})")

    # ── Step 5: Verify structural integrity ───────────────────────────────
    print(f"[6/11] Verifying modified data...")
    # Check that State 7 is still intact (before insert point)
    s7_check = new_decomp[STATE7_FILE_OFFSET : STATE7_FILE_OFFSET + 4]
    print(f"       State 7 header bytes: {s7_check.hex()}")

    # Check that State 328 header is still intact
    s328_check = new_decomp[STATE328_FILE_OFFSET : STATE328_FILE_OFFSET + 4]
    print(f"       State 328 header bytes: {s328_check.hex()}")

    # Verify guard blocks were inserted
    inserted = new_decomp[insert_file_offset : insert_file_offset + 8]
    if inserted == b'\xFF' * 8:
        print("       Guard block separator at insert point: OK")
    else:
        print(f"WARNING: Expected FF*8 at insert point, got: {inserted.hex()}")

    # ── Step 6: Recompress ────────────────────────────────────────────────
    print(f"[7/11] Recompressing with LZ4...")
    new_comp = lz4.block.compress(bytes(new_decomp), mode='default', acceleration=1, store_size=False)
    new_comp_size = len(new_comp)
    delta = new_comp_size - SWORD_COMP_SIZE
    print(f"       New compressed size: {new_comp_size:,} (was {SWORD_COMP_SIZE:,}, delta {delta:+,})")

    # ── Step 7: Create backups ────────────────────────────────────────────
    print(f"[8/11] Creating backups...")
    for path in [PAZ_PATH, PAMT_PATH, PAPGT_PATH]:
        bak = path + ".bak"
        if not os.path.isfile(bak):
            print(f"       Backing up {os.path.basename(path)} -> .bak")
            shutil.copy2(path, bak)
        else:
            print(f"       {os.path.basename(path)}.bak already exists, skipping")

    # ── Step 8: PAZ-shift write ───────────────────────────────────────────
    print(f"[9/11] Writing patched PAZ (shift delta = {delta:+,})...")
    paz_tmp = PAZ_PATH + ".tmp"
    with open(PAZ_PATH, "rb") as fin, open(paz_tmp, "wb") as fout:
        # Before sword_upper
        fin.seek(0)
        before = fin.read(SWORD_PAZ_OFFSET)
        fout.write(before)
        print(f"       Wrote prefix: {len(before):,} bytes")

        # New compressed data
        fout.write(new_comp)
        print(f"       Wrote new sword_upper: {new_comp_size:,} bytes")

        # After sword_upper (skip old compressed data)
        fin.seek(SWORD_PAZ_OFFSET + SWORD_COMP_SIZE)
        after = fin.read()
        fout.write(after)
        print(f"       Wrote suffix: {len(after):,} bytes")

    new_paz_size = os.path.getsize(paz_tmp)
    print(f"       New PAZ size: {new_paz_size:,} (was {old_paz_size:,}, delta {new_paz_size - old_paz_size:+,})")

    os.replace(paz_tmp, PAZ_PATH)
    print("       PAZ replaced atomically")

    # ── Step 9: Update PAMT ───────────────────────────────────────────────
    print(f"[10/11] Updating PAMT...")
    pamt = bytearray(open(PAMT_PATH, "rb").read())

    # Find sword_upper's record: exact 12-byte triplet
    target_triplet = struct.pack("<III", SWORD_PAZ_OFFSET, SWORD_COMP_SIZE, SWORD_DECOMP_SIZE)
    record_pos = pamt.find(target_triplet)
    if record_pos < 0:
        print("ERROR: Could not find sword_upper record in PAMT!")
        print("       Looking for:", target_triplet.hex())
        input("Press Enter to close...")
        sys.exit(1)
    print(f"       Found sword_upper record at PAMT offset {record_pos}")

    # Update compressed size and decompressed size
    struct.pack_into("<I", pamt, record_pos + 4, new_comp_size)
    struct.pack_into("<I", pamt, record_pos + 8, new_decomp_size)
    print(f"       Updated comp_size: {SWORD_COMP_SIZE} -> {new_comp_size}")
    print(f"       Updated decomp_size: {SWORD_DECOMP_SIZE} -> {new_decomp_size}")

    # Shift subsequent file records using PROPERLY PARSED PAMT entries
    # (byte-scanning caused 12K false positives and crashed the game)
    print("       Parsing PAMT entries for precise shifting...")
    paz_dir = os.path.dirname(PAZ_PATH)
    all_entries = parse_pamt(PAMT_PATH, paz_dir=paz_dir)
    print(f"       Parsed {len(all_entries):,} PAMT entries")

    shift_count = 0
    skipped = 0
    for e in all_entries:
        if e.paz_index != 0:  # sword_upper is in PAZ index 0
            continue
        if e.offset <= SWORD_PAZ_OFFSET:
            continue
        # Find this entry's exact record in PAMT by triplet match
        triplet = struct.pack("<III", e.offset, e.comp_size, e.orig_size)
        pos = pamt.find(triplet)
        if pos < 0:
            skipped += 1
            continue
        new_off = e.offset + delta
        struct.pack_into("<I", pamt, pos, new_off)
        shift_count += 1

    if skipped:
        print(f"       WARNING: {skipped} entries not found in PAMT (may have been updated)")
    print(f"       Shifted {shift_count} subsequent file records by {delta:+,}")

    # Update PAZ file size in PAMT header
    # PAMT header: [hash:4][paz_count:4][version:4][zero:4][PAZ table...]
    # PAZ table: entry0=[hash:4][size:4], entry1=[sep:4][hash:4][size:4], ...
    # sword_upper is in PAZ index 0, so size field is at offset 16+4=20
    paz_count = struct.unpack_from("<I", pamt, 4)[0]
    paz_size_off = 16 + 4  # first entry: hash at 16, size at 20
    old_size_in_pamt = struct.unpack_from("<I", pamt, paz_size_off)[0]
    struct.pack_into("<I", pamt, paz_size_off, new_paz_size)
    print(f"       Updated PAZ size in PAMT[0]: {old_size_in_pamt:,} -> {new_paz_size:,}")

    # Recompute PAMT hash
    old_pamt_hash = struct.unpack_from("<I", pamt, 0)[0]
    new_pamt_hash = hashlittle(bytes(pamt[12:]), 0xC5EDE)
    struct.pack_into("<I", pamt, 0, new_pamt_hash)
    print(f"       PAMT hash: 0x{old_pamt_hash:08X} -> 0x{new_pamt_hash:08X}")

    # Write PAMT atomically
    pamt_tmp = PAMT_PATH + ".tmp"
    with open(pamt_tmp, "wb") as f:
        f.write(pamt)
    os.replace(pamt_tmp, PAMT_PATH)
    print("       PAMT replaced atomically")

    # ── Step 10: Update PAPGT ─────────────────────────────────────────────
    print(f"[11/11] Updating PAPGT...")
    papgt = bytearray(open(PAPGT_PATH, "rb").read())

    # Find old PAMT hash in PAPGT and replace with new
    old_hash_bytes = struct.pack("<I", old_pamt_hash)
    new_hash_bytes = struct.pack("<I", new_pamt_hash)

    hash_pos = papgt.find(old_hash_bytes)
    if hash_pos < 0:
        print(f"WARNING: Could not find old PAMT hash 0x{old_pamt_hash:08X} in PAPGT")
        print("         PAPGT may already be updated or have a different format")
    else:
        papgt[hash_pos : hash_pos + 4] = new_hash_bytes
        print(f"       Replaced PAMT hash ref at PAPGT offset {hash_pos}")

    # Recompute PAPGT file hash
    old_papgt_hash = struct.unpack_from("<I", papgt, 4)[0]
    new_papgt_hash = hashlittle(bytes(papgt[12:]), 0xC5EDE)
    struct.pack_into("<I", papgt, 4, new_papgt_hash)
    print(f"       PAPGT hash: 0x{old_papgt_hash:08X} -> 0x{new_papgt_hash:08X}")

    # Write PAPGT atomically
    papgt_tmp = PAPGT_PATH + ".tmp"
    with open(papgt_tmp, "wb") as f:
        f.write(papgt)
    os.replace(papgt_tmp, PAPGT_PATH)
    print("       PAPGT replaced atomically")

    # ── Done ──────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  DEPLOYMENT COMPLETE")
    print(f"  Inserted {GUARD_TOTAL_SIZE} bytes of guard sub-blocks into State 328")
    print(f"  Timing windows set to 0.0 - 99.0 (always active)")
    print(f"  PAZ delta: {delta:+,} bytes")
    print(f"  {shift_count} PAMT records shifted")
    print("=" * 60)
    print()
    print("  Backups saved as .bak files. To restore:")
    print(f"    copy /Y \"{PAZ_PATH}.bak\" \"{PAZ_PATH}\"")
    print(f"    copy /Y \"{PAMT_PATH}.bak\" \"{PAMT_PATH}\"")
    print(f"    copy /Y \"{PAPGT_PATH}.bak\" \"{PAPGT_PATH}\"")
    print()

    input("Press Enter to close...")


if __name__ == "__main__":
    main()
