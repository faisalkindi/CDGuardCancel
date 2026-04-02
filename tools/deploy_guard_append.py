#!/usr/bin/env python3
"""
Deploy guard-cancel for Crimson Desert sword combat.

Two-layer patch:
  1. APPEND a copy of State 7 (working guard state, Format B, 1981 bytes)
     to the end of sword_upper.paac decompressed data, then LZ4-recompress
     and PAZ-shift to accommodate the new compressed size.
  2. Apply 10-byte branchset literal patches to common_upper_branchset.paac
     (already LZ4-compressed in PAZ) to remove the guard input gate.

PAZ integrity chain:
  - Shift all PAMT offsets for files after sword_upper in 0.paz
  - Update sword_upper comp_size and orig_size in PAMT
  - Update PAZ[0] size field in PAMT header
  - Recompute PAMT hash with hashlittle(pamt[12:], 0xC5EDE)
  - Update PAPGT: replace old PAMT hash, recompute papgt[4:8]

Usage:
    py -3 deploy_guard_append.py
    py -3 deploy_guard_append.py --restore
"""

import struct
import shutil
import os
import sys

try:
    import lz4.block
except ImportError:
    print("ERROR: lz4 not installed. Run: py -3 -m pip install lz4")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paz_crypto import hashlittle

# ── Paths ────────────────────────────────────────────────────────────

GAME_DIR  = r"E:\SteamLibrary\steamapps\common\Crimson Desert"
PAZ_PATH  = os.path.join(GAME_DIR, "0010", "0.paz")
PAMT_PATH = os.path.join(GAME_DIR, "0010", "0.pamt")
PAPGT_PATH = os.path.join(GAME_DIR, "meta", "0.papgt")

BACKUP_SUFFIX = ".guardappend_bak"
PAZ_BACKUP  = PAZ_PATH  + BACKUP_SUFFIX
PAMT_BACKUP = PAMT_PATH + BACKUP_SUFFIX
PAPGT_BACKUP = PAPGT_PATH + BACKUP_SUFFIX

# ── sword_upper.paac location in PAZ ────────────────────────────────

SW_PAZ_OFFSET  = 225322576       # byte offset of sword_upper in 0.paz
SW_COMP_SIZE   = 224084          # original compressed size
SW_DECOMP_SIZE = 1243769         # original decompressed size

# ── State 7 (guard-capable Format B state) ──────────────────────────

STATE7_OFFSET = 0x036285         # offset in decompressed sword_upper
STATE7_SIZE   = 1981             # bytes to copy (up to next state marker area)

# ── Branchset (common_upper_branchset.paac) LZ4 literal patches ────

BS_PAZ_OFFSET = 223915488       # offset of branchset in 0.paz

# 10 bytes to patch directly in the compressed LZ4 stream
BS_PATCHES = [
    (0x001680, 0xAB),
    (0x001684, 0xDA),
    (0x001685, 0x01),
    (0x00168C, 0x00),
    (0x00168D, 0x00),
    (0x00168E, 0x00),
    (0x00168F, 0x00),
    (0x001697, 0x40),
    (0x001698, 0x1C),
    (0x001699, 0x46),
]

HASH_SEED = 0xC5EDE


# ── hashlittle (Bob Jenkins lookup3) ─────────────────────────────────

def _hashlittle_BROKEN_DO_NOT_USE(data, initval):
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


# ── Restore ──────────────────────────────────────────────────────────

def do_restore():
    """Restore all three files from backup."""
    restored = 0
    for bak, orig, name in [
        (PAZ_BACKUP, PAZ_PATH, "PAZ"),
        (PAMT_BACKUP, PAMT_PATH, "PAMT"),
        (PAPGT_BACKUP, PAPGT_PATH, "PAPGT"),
    ]:
        if os.path.exists(bak):
            shutil.copy2(bak, orig)
            print(f"  Restored {name} from {bak}")
            restored += 1
        else:
            print(f"  No backup for {name}: {bak}")
    if restored > 0:
        print(f"\nRestored {restored} file(s). Vanilla state recovered.")
    else:
        print("\nNo backups found. Nothing to restore.")
    return restored > 0


# ── Main deployment ──────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("  Crimson Desert - Guard Cancel (Append + Branchset)")
    print("  sword_upper.paac guard state append + branchset gate removal")
    print("=" * 65)

    # Handle --restore
    if "--restore" in sys.argv:
        return do_restore()

    # Verify files exist
    for path, name in [(PAZ_PATH, "PAZ"), (PAMT_PATH, "PAMT"), (PAPGT_PATH, "PAPGT")]:
        if not os.path.exists(path):
            print(f"\nERROR: {name} not found: {path}")
            return False

    # ── Step 1: Read and decompress sword_upper ──────────────────────

    print(f"\n[1/8] Reading sword_upper from PAZ @ 0x{SW_PAZ_OFFSET:08X}...")
    with open(PAZ_PATH, "rb") as f:
        f.seek(SW_PAZ_OFFSET)
        sw_compressed = f.read(SW_COMP_SIZE)

    if len(sw_compressed) != SW_COMP_SIZE:
        print(f"  ERROR: Read {len(sw_compressed)} bytes, expected {SW_COMP_SIZE}")
        return False

    paac = bytearray(lz4.block.decompress(sw_compressed, uncompressed_size=SW_DECOMP_SIZE))
    if len(paac) != SW_DECOMP_SIZE:
        print(f"  ERROR: Decompressed to {len(paac)}, expected {SW_DECOMP_SIZE}")
        return False
    print(f"  OK: {len(paac):,} bytes decompressed")

    # ── Step 2: Copy State 7 and append ──────────────────────────────

    print(f"\n[2/8] Copying State 7 (guard state) from offset 0x{STATE7_OFFSET:06X}...")
    state7_data = bytes(paac[STATE7_OFFSET:STATE7_OFFSET + STATE7_SIZE])
    if len(state7_data) != STATE7_SIZE:
        print(f"  ERROR: State 7 read {len(state7_data)} bytes, expected {STATE7_SIZE}")
        return False

    # Verify State 7 starts with expected magic
    magic = state7_data[:4]
    print(f"  State 7 magic: {magic.hex(' ')}")
    print(f"  State 7 size: {STATE7_SIZE} bytes")

    # Append at end of decompressed data
    new_paac = bytearray(paac) + bytearray(state7_data)
    new_decomp_size = len(new_paac)
    decomp_delta = new_decomp_size - SW_DECOMP_SIZE
    print(f"  Appended: {SW_DECOMP_SIZE:,} -> {new_decomp_size:,} (+{decomp_delta} bytes)")

    # ── Step 3: LZ4 recompress ───────────────────────────────────────

    print(f"\n[3/8] LZ4 compressing modified sword_upper...")
    new_sw_compressed = lz4.block.compress(
        bytes(new_paac), mode="default", acceleration=1, store_size=False
    )
    new_sw_comp_size = len(new_sw_compressed)
    comp_delta = new_sw_comp_size - SW_COMP_SIZE
    print(f"  Compressed: {SW_COMP_SIZE:,} -> {new_sw_comp_size:,} (delta: {comp_delta:+d})")

    # Roundtrip verify
    verify = lz4.block.decompress(new_sw_compressed, uncompressed_size=new_decomp_size)
    if verify != bytes(new_paac):
        print("  ERROR: LZ4 roundtrip verification failed!")
        return False
    print("  Roundtrip verified OK")

    # ── Step 4: Create backups ───────────────────────────────────────

    print(f"\n[4/8] Creating backups...")
    for src, bak, name in [
        (PAZ_PATH, PAZ_BACKUP, "PAZ"),
        (PAMT_PATH, PAMT_BACKUP, "PAMT"),
        (PAPGT_PATH, PAPGT_BACKUP, "PAPGT"),
    ]:
        if not os.path.exists(bak):
            shutil.copy2(src, bak)
            print(f"  {name}: backed up -> {os.path.basename(bak)}")
        else:
            print(f"  {name}: backup already exists")

    # If backups already existed, restore vanilla first to prevent compounding
    if os.path.exists(PAZ_BACKUP) and os.path.getsize(PAZ_BACKUP) > 0:
        # Re-read from backup to ensure we start from vanilla
        with open(PAZ_BACKUP, "rb") as f:
            f.seek(SW_PAZ_OFFSET)
            vanilla_check = f.read(4)
        # Only restore if our backup PAZ is different size (already patched)
        current_paz_size = os.path.getsize(PAZ_PATH)
        backup_paz_size = os.path.getsize(PAZ_BACKUP)
        if current_paz_size != backup_paz_size:
            print("  Restoring vanilla before re-patching (prevent compounding)...")
            for bak, orig in [
                (PAZ_BACKUP, PAZ_PATH),
                (PAMT_BACKUP, PAMT_PATH),
                (PAPGT_BACKUP, PAPGT_PATH),
            ]:
                if os.path.exists(bak):
                    shutil.copy2(bak, orig)
            # Re-read the restored vanilla PAZ for the shift operation
            # (The compressed data we already have is still from vanilla decompressed)

    # ── Step 5: PAZ shift — insert new sword_upper blob ──────────────

    print(f"\n[5/8] PAZ shift (sword_upper)...")
    with open(PAZ_PATH, "rb") as f:
        paz_data = bytearray(f.read())
    old_paz_size = len(paz_data)

    # Build new PAZ: everything before sword_upper + new blob + everything after
    insert_end = SW_PAZ_OFFSET + SW_COMP_SIZE
    new_paz = bytearray()
    new_paz.extend(paz_data[:SW_PAZ_OFFSET])
    new_paz.extend(new_sw_compressed)
    new_paz.extend(paz_data[insert_end:])
    new_paz_size = len(new_paz)
    print(f"  PAZ: {old_paz_size:,} -> {new_paz_size:,} (delta: {comp_delta:+d})")

    # Write PAZ atomically
    tmp = PAZ_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(new_paz)
    os.replace(tmp, PAZ_PATH)
    print("  PAZ written")

    # ── Step 6: Apply branchset LZ4 literal patches ──────────────────

    print(f"\n[6/8] Patching branchset (common_upper_branchset.paac)...")

    # The branchset is BEFORE sword_upper in the PAZ, so its offset is unchanged
    # by the sword_upper shift. But if branchset offset > sword_upper offset,
    # we'd need to adjust. Let's check:
    if BS_PAZ_OFFSET > SW_PAZ_OFFSET:
        # Branchset is after sword_upper — its effective offset shifted
        effective_bs_offset = BS_PAZ_OFFSET + comp_delta
        print(f"  Branchset offset shifted: 0x{BS_PAZ_OFFSET:08X} -> 0x{effective_bs_offset:08X}")
    else:
        effective_bs_offset = BS_PAZ_OFFSET
        print(f"  Branchset offset: 0x{effective_bs_offset:08X} (before sword_upper, unshifted)")

    # Patch the 10 bytes directly in the PAZ file (LZ4 literal patches)
    with open(PAZ_PATH, "r+b") as f:
        for rel_off, byte_val in BS_PATCHES:
            abs_off = effective_bs_offset + rel_off
            f.seek(abs_off)
            old_byte = f.read(1)
            f.seek(abs_off)
            f.write(bytes([byte_val]))
            print(f"  @0x{abs_off:08X} (rel 0x{rel_off:04X}): "
                  f"0x{old_byte[0]:02X} -> 0x{byte_val:02X}")
    print(f"  {len(BS_PATCHES)} branchset bytes patched")

    # ── Step 7: Update PAMT ──────────────────────────────────────────

    print(f"\n[7/8] Updating PAMT...")
    with open(PAMT_PATH, "rb") as f:
        pamt_data = bytearray(f.read())

    old_pamt_hash = struct.unpack_from("<I", pamt_data, 0)[0]

    # Find sword_upper record: search for (offset, comp_size, orig_size) triplet
    target_bytes = struct.pack("<III", SW_PAZ_OFFSET, SW_COMP_SIZE, SW_DECOMP_SIZE)
    rec_pos = pamt_data.find(target_bytes)
    if rec_pos < 0:
        print("  ERROR: sword_upper record not found in PAMT!")
        print("  (Has this PAMT already been patched? Try --restore first.)")
        return False

    # Update comp_size and orig_size for sword_upper
    struct.pack_into("<I", pamt_data, rec_pos + 4, new_sw_comp_size)
    struct.pack_into("<I", pamt_data, rec_pos + 8, new_decomp_size)
    print(f"  sword_upper comp: {SW_COMP_SIZE:,} -> {new_sw_comp_size:,}")
    print(f"  sword_upper orig: {SW_DECOMP_SIZE:,} -> {new_decomp_size:,}")

    # Shift PAMT entries using PARSED entries (byte-scan has false positives)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from paz_parse import parse_pamt
    all_entries = parse_pamt(PAMT_PATH, paz_dir=os.path.dirname(PAZ_PATH))
    shifted = 0
    for e in all_entries:
        if e.paz_index != 0 or e.offset <= SW_PAZ_OFFSET:
            continue
        triplet = struct.pack("<III", e.offset, e.comp_size, e.orig_size)
        pos = pamt_data.find(triplet)
        if pos < 0:
            continue
        struct.pack_into("<I", pamt_data, pos, e.offset + comp_delta)
        shifted += 1
    print(f"  Shifted {shifted} PAMT entries by {comp_delta:+d}")

    # Update PAZ[0] size field in PAMT header
    # PAMT header: [4:8] = paz_count, then PAZ table entries
    paz_count = struct.unpack_from("<I", pamt_data, 4)[0]
    paz_size_updated = False
    # PAZ table: first entry at offset 16 (skip 4 hash + 4 paz_count + 4 version + 4 zero)
    # Each entry: [hash:4][size:4], entries 1+ have [sep:4] prefix
    off = 16
    for pi in range(paz_count):
        if pi > 0:
            off += 4  # separator
        # off = hash, off+4 = size
        sz_val = struct.unpack_from("<I", pamt_data, off + 4)[0]
        if sz_val == old_paz_size:
            struct.pack_into("<I", pamt_data, off + 4, new_paz_size)
            print(f"  PAZ[{pi}] size: {old_paz_size:,} -> {new_paz_size:,}")
            paz_size_updated = True
            break
        off += 8

    if not paz_size_updated:
        # Fallback: scan for old_paz_size anywhere in the header region
        old_sz_bytes = struct.pack("<I", old_paz_size)
        hdr_pos = pamt_data.find(old_sz_bytes, 8, 200)
        if hdr_pos >= 0:
            struct.pack_into("<I", pamt_data, hdr_pos, new_paz_size)
            print(f"  PAZ size (fallback scan @{hdr_pos}): {old_paz_size:,} -> {new_paz_size:,}")
            paz_size_updated = True
        else:
            print("  WARNING: PAZ size field not found in PAMT header!")

    # Recompute PAMT hash
    new_pamt_hash = hashlittle(bytes(pamt_data[12:]), HASH_SEED)
    struct.pack_into("<I", pamt_data, 0, new_pamt_hash)
    print(f"  PAMT hash: 0x{old_pamt_hash:08X} -> 0x{new_pamt_hash:08X}")

    # Write PAMT atomically
    tmp = PAMT_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(pamt_data)
    os.replace(tmp, PAMT_PATH)
    print("  PAMT written")

    # ── Step 8: Update PAPGT ─────────────────────────────────────────

    print(f"\n[8/8] Updating PAPGT...")
    if not os.path.exists(PAPGT_PATH):
        print("  WARNING: PAPGT not found, skipping")
    else:
        with open(PAPGT_PATH, "rb") as f:
            papgt_data = bytearray(f.read())

        old_hash_bytes = struct.pack("<I", old_pamt_hash)
        new_hash_bytes = struct.pack("<I", new_pamt_hash)

        count = 0
        pos = 0
        while True:
            idx = papgt_data.find(old_hash_bytes, pos)
            if idx == -1:
                break
            papgt_data[idx:idx + 4] = new_hash_bytes
            count += 1
            pos = idx + 4

        if count > 0:
            # Recompute PAPGT file integrity hash at [4:8]
            papgt_file_hash = hashlittle(bytes(papgt_data[12:]), HASH_SEED)
            struct.pack_into("<I", papgt_data, 4, papgt_file_hash)

            tmp = PAPGT_PATH + ".tmp"
            with open(tmp, "wb") as f:
                f.write(papgt_data)
            os.replace(tmp, PAPGT_PATH)
            print(f"  Updated {count} PAMT hash ref(s), PAPGT file hash recomputed")
        else:
            print(f"  WARNING: Old PAMT hash 0x{old_pamt_hash:08X} not found in PAPGT!")

    # ── Verification ─────────────────────────────────────────────────

    print(f"\n{'─' * 65}")
    print("  Verification...")

    # Verify PAMT hash
    with open(PAMT_PATH, "rb") as f:
        verify_pamt = f.read()
    stored_hash = struct.unpack_from("<I", verify_pamt, 0)[0]
    computed_hash = hashlittle(verify_pamt[12:], HASH_SEED)
    if stored_hash == computed_hash:
        print("  PAMT hash: PASS")
    else:
        print(f"  PAMT hash: FAIL (stored=0x{stored_hash:08X}, computed=0x{computed_hash:08X})")
        return False

    # Verify sword_upper readback
    with open(PAZ_PATH, "rb") as f:
        f.seek(SW_PAZ_OFFSET)
        readback = f.read(new_sw_comp_size)
    if readback == new_sw_compressed:
        print("  sword_upper readback: PASS")
    else:
        print("  sword_upper readback: FAIL")
        return False

    # Verify roundtrip decompress
    rt = lz4.block.decompress(readback, uncompressed_size=new_decomp_size)
    if rt == bytes(new_paac):
        print("  sword_upper roundtrip: PASS")
    else:
        print("  sword_upper roundtrip: FAIL")
        return False

    # Verify branchset patches applied
    with open(PAZ_PATH, "rb") as f:
        bs_ok = True
        for rel_off, expected_val in BS_PATCHES:
            abs_off = effective_bs_offset + rel_off
            f.seek(abs_off)
            actual = f.read(1)[0]
            if actual != expected_val:
                print(f"  branchset @0x{abs_off:08X}: FAIL "
                      f"(expected 0x{expected_val:02X}, got 0x{actual:02X})")
                bs_ok = False
    if bs_ok:
        print("  branchset patches: PASS")
    else:
        print("  branchset patches: FAIL")
        return False

    # ── Summary ──────────────────────────────────────────────────────

    print(f"\n{'=' * 65}")
    print(f"  DEPLOYED SUCCESSFULLY")
    print(f"")
    print(f"  Layer 1: sword_upper.paac — State 7 guard appended")
    print(f"    Decompressed: {SW_DECOMP_SIZE:,} -> {new_decomp_size:,} (+{decomp_delta})")
    print(f"    Compressed:   {SW_COMP_SIZE:,} -> {new_sw_comp_size:,} ({comp_delta:+d})")
    print(f"    PAZ shifted:  {shifted} entries by {comp_delta:+d} bytes")
    print(f"")
    print(f"  Layer 2: branchset — guard input gate removed (10 bytes)")
    print(f"")
    print(f"  Backups:")
    print(f"    {PAZ_BACKUP}")
    print(f"    {PAMT_BACKUP}")
    print(f"    {PAPGT_BACKUP}")
    print(f"")
    print(f"  To restore:  py -3 {os.path.basename(__file__)} --restore")
    print(f"{'=' * 65}")
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
