#!/usr/bin/env python3
"""
Deploy guard-cancel patch for sword_upper.paac — PAZ-append method.

Instead of requiring exact LZ4 size match, appends the new compressed data
at the end of the PAZ and updates the PAMT entry to point to it.

This handles any compressed size difference safely.
"""

import struct
import shutil
import os
import sys
import hashlib

try:
    import lz4.block
except ImportError:
    print("ERROR: lz4 not installed. Run: py -3 -m pip install lz4")
    sys.exit(1)

PAZ_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.paz"
PAZ_BACKUP = PAZ_PATH + ".bak"
PAMT_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.pamt"
PAMT_BACKUP = PAMT_PATH + ".bak"

# Original slot info
ORIG_PAZ_OFFSET = 225322576
ORIG_COMP_SIZE = 224084
DECOMP_SIZE = 1243769

# PAMT entry location (found by searching for PAZ offset bytes)
PAMT_ENTRY_OFFSET_FIELD = 6215914  # where the 4-byte PAZ offset is stored
PAMT_COMPSIZE_FIELD = 6215918       # where the 4-byte compressed size is stored

# Guard transition: [thresh=0.0] [sentinel=-1.0] [target=0] [seq=0]
GUARD_BYTES = b'\x00\x00\x00\x00\x00\x00\x80\xBF\x00\x00\x00\x00\x00\x00\x00\x00'

# Patch targets in decompressed sword_upper.paac
PATCHES = [
    {
        'name': 'State 301 (main attack)',
        'offset': 0x07DF1D,
        'expected': b'\x00\x00\x00\x00\x00\x00\x80\xBF\x70\x00\x00\x00\x0B\x00\x00\x00',
        'desc': 'target=112 -> guard (target=0)',
    },
    {
        'name': 'State 328 (combo hub)',
        'offset': 0x08D4D0,
        'expected': b'\x89\x88\x88\x3D\x00\x00\x80\xBF\x31\x04\x00\x00\x03\x00\x00\x00',
        'desc': 'target=1073 -> guard (target=0)',
    },
]


def main():
    print("=" * 60)
    print("  Guard Cancel — PAZ Append Deploy")
    print("  Patches sword_upper.paac (2 attack states)")
    print("=" * 60)

    # Check files exist
    for path, name in [(PAZ_PATH, "PAZ"), (PAMT_PATH, "PAMT")]:
        if not os.path.exists(path):
            print(f"\nERROR: {name} not found: {path}")
            return False

    # Step 1: Read and decompress
    print(f"\n[1/6] Reading sword_upper from PAZ...")
    with open(PAZ_PATH, 'rb') as f:
        f.seek(ORIG_PAZ_OFFSET)
        compressed = f.read(ORIG_COMP_SIZE)

    paac = bytearray(lz4.block.decompress(compressed, uncompressed_size=DECOMP_SIZE))
    assert len(paac) == DECOMP_SIZE, f"Decomp size mismatch: {len(paac)}"
    print(f"  OK: {len(paac)} bytes decompressed")

    # Step 2: Verify patch targets
    print(f"\n[2/6] Verifying patch targets...")
    for patch in PATCHES:
        actual = bytes(paac[patch['offset']:patch['offset'] + 16])
        if actual == GUARD_BYTES:
            print(f"  {patch['name']}: Already patched!")
            patch['skip'] = True
        elif actual == patch['expected']:
            print(f"  {patch['name']}: OK (vanilla)")
            patch['skip'] = False
        else:
            print(f"  {patch['name']}: MISMATCH at 0x{patch['offset']:06X}")
            print(f"    Expected: {patch['expected'].hex(' ')}")
            print(f"    Actual:   {actual.hex(' ')}")

            # Check if it's already a guard transition with different seq
            if actual[:12] == GUARD_BYTES[:12]:
                print(f"    Looks like guard with different seq — treating as patched")
                patch['skip'] = True
            else:
                print(f"    Game may have updated. Aborting.")
                return False

    to_apply = [p for p in PATCHES if not p.get('skip')]
    if not to_apply:
        print("\n  Already patched. Nothing to do.")
        return True

    # Step 3: Apply patches
    print(f"\n[3/6] Applying {len(to_apply)} patches...")
    for patch in to_apply:
        paac[patch['offset']:patch['offset'] + 16] = GUARD_BYTES
        print(f"  {patch['name']}: {patch['desc']}")

    # Step 4: Compress
    print(f"\n[4/6] Compressing with LZ4...")
    new_compressed = lz4.block.compress(bytes(paac), mode='default', acceleration=1, store_size=False)
    print(f"  New compressed size: {len(new_compressed)} (original was {ORIG_COMP_SIZE}, delta={len(new_compressed)-ORIG_COMP_SIZE:+d})")

    # Verify roundtrip
    verify = lz4.block.decompress(new_compressed, uncompressed_size=DECOMP_SIZE)
    assert verify == bytes(paac), "Roundtrip failed!"
    print(f"  Roundtrip verified")

    # Step 5: Backup
    print(f"\n[5/6] Creating backups...")
    if not os.path.exists(PAZ_BACKUP):
        print(f"  Backing up PAZ -> {PAZ_BACKUP}")
        shutil.copy2(PAZ_PATH, PAZ_BACKUP)
    else:
        print(f"  PAZ backup exists")

    if not os.path.exists(PAMT_BACKUP):
        print(f"  Backing up PAMT -> {PAMT_BACKUP}")
        shutil.copy2(PAMT_PATH, PAMT_BACKUP)
    else:
        print(f"  PAMT backup exists")

    # Step 6: Write
    print(f"\n[6/6] Writing patched data...")

    if len(new_compressed) == ORIG_COMP_SIZE:
        # Lucky — exact size match, in-place replacement
        print(f"  Exact size match! In-place replacement at offset {ORIG_PAZ_OFFSET}")
        with open(PAZ_PATH, 'r+b') as f:
            f.seek(ORIG_PAZ_OFFSET)
            f.write(new_compressed)
        new_offset = ORIG_PAZ_OFFSET
        new_size = len(new_compressed)
    else:
        # Append at end of PAZ and update PAMT
        with open(PAZ_PATH, 'rb') as f:
            f.seek(0, 2)
            paz_end = f.tell()

        new_offset = paz_end
        new_size = len(new_compressed)
        print(f"  Appending {new_size} bytes at PAZ offset {new_offset} (0x{new_offset:X})")

        with open(PAZ_PATH, 'r+b') as f:
            f.seek(new_offset)
            f.write(new_compressed)

        # Update PAMT: change offset and compressed size
        print(f"  Updating PAMT offset: {ORIG_PAZ_OFFSET} -> {new_offset}")
        print(f"  Updating PAMT comp size: {ORIG_COMP_SIZE} -> {new_size}")

        with open(PAMT_PATH, 'r+b') as f:
            # Verify current values before overwriting
            f.seek(PAMT_ENTRY_OFFSET_FIELD)
            cur_offset = struct.unpack('<I', f.read(4))[0]
            cur_size = struct.unpack('<I', f.read(4))[0]

            if cur_offset != ORIG_PAZ_OFFSET or cur_size != ORIG_COMP_SIZE:
                # Maybe already patched — check if pointing to our appended data
                print(f"  WARNING: PAMT already modified (offset={cur_offset}, size={cur_size})")
                print(f"  Overwriting with new values anyway")

            f.seek(PAMT_ENTRY_OFFSET_FIELD)
            f.write(struct.pack('<I', new_offset))
            f.write(struct.pack('<I', new_size))

        # Update PAMT file hash (hashlittle of pamt[12:])
        print(f"  Updating PAMT file hash...")
        with open(PAMT_PATH, 'rb') as f:
            pamt_data = bytearray(f.read())

        new_hash = hashlittle(bytes(pamt_data[12:]), 0xC5EDE)
        struct.pack_into('<I', pamt_data, 0, new_hash)

        with open(PAMT_PATH, 'wb') as f:
            f.write(pamt_data)

    # Verify readback
    with open(PAZ_PATH, 'rb') as f:
        f.seek(new_offset)
        readback = f.read(new_size)
    assert readback == new_compressed, "Readback mismatch!"
    print(f"  Readback verified")

    print(f"\n{'=' * 60}")
    print(f"  PATCH APPLIED SUCCESSFULLY")
    print(f"  States: 301 (attack) + 328 (combo hub)")
    print(f"  PAZ offset: {new_offset} (comp size: {new_size})")
    print(f"  Backup: {PAZ_BACKUP} / {PAMT_BACKUP}")
    print(f"  To restore: copy .bak files back")
    print(f"{'=' * 60}")
    return True


def hashlittle(data, initval):
    """Bob Jenkins' hashlittle (lookup3) — same as used by the game."""
    length = len(data)
    a = b = c = (0xdeadbeef + length + initval) & 0xFFFFFFFF

    i = 0
    while length > 12:
        a = (a + (data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24))) & 0xFFFFFFFF
        b = (b + (data[i+4] | (data[i+5] << 8) | (data[i+6] << 16) | (data[i+7] << 24))) & 0xFFFFFFFF
        c = (c + (data[i+8] | (data[i+9] << 8) | (data[i+10] << 16) | (data[i+11] << 24))) & 0xFFFFFFFF

        a = (a - c) & 0xFFFFFFFF; a ^= ((c << 4) | (c >> 28)) & 0xFFFFFFFF; c = (c + b) & 0xFFFFFFFF
        b = (b - a) & 0xFFFFFFFF; b ^= ((a << 6) | (a >> 26)) & 0xFFFFFFFF; a = (a + c) & 0xFFFFFFFF
        c = (c - b) & 0xFFFFFFFF; c ^= ((b << 8) | (b >> 24)) & 0xFFFFFFFF; b = (b + a) & 0xFFFFFFFF
        a = (a - c) & 0xFFFFFFFF; a ^= ((c << 16) | (c >> 16)) & 0xFFFFFFFF; c = (c + b) & 0xFFFFFFFF
        b = (b - a) & 0xFFFFFFFF; b ^= ((a << 19) | (a >> 13)) & 0xFFFFFFFF; a = (a + c) & 0xFFFFFFFF
        c = (c - b) & 0xFFFFFFFF; c ^= ((b << 4) | (b >> 28)) & 0xFFFFFFFF; b = (b + a) & 0xFFFFFFFF

        i += 12
        length -= 12

    if length > 0:
        if length >= 1: c = (c + data[i]) & 0xFFFFFFFF
        if length >= 2: c = (c + (data[i+1] << 8)) & 0xFFFFFFFF
        if length >= 3: c = (c + (data[i+2] << 16)) & 0xFFFFFFFF
        if length >= 4: c = (c + (data[i+3] << 24)) & 0xFFFFFFFF
        if length >= 5: b = (b + data[i+4]) & 0xFFFFFFFF
        if length >= 6: b = (b + (data[i+5] << 8)) & 0xFFFFFFFF
        if length >= 7: b = (b + (data[i+6] << 16)) & 0xFFFFFFFF
        if length >= 8: b = (b + (data[i+7] << 24)) & 0xFFFFFFFF
        if length >= 9: a = (a + data[i+8]) & 0xFFFFFFFF
        if length >= 10: a = (a + (data[i+9] << 8)) & 0xFFFFFFFF
        if length >= 11: a = (a + (data[i+10] << 16)) & 0xFFFFFFFF
        if length >= 12: a = (a + (data[i+11] << 24)) & 0xFFFFFFFF

        c ^= b; c = (c - ((b << 14) | (b >> 18))) & 0xFFFFFFFF
        a ^= c; a = (a - ((c << 11) | (c >> 21))) & 0xFFFFFFFF
        b ^= a; b = (b - ((a << 25) | (a >> 7))) & 0xFFFFFFFF
        c ^= b; c = (c - ((b << 16) | (b >> 16))) & 0xFFFFFFFF
        a ^= c; a = (a - ((c << 4) | (c >> 28))) & 0xFFFFFFFF
        b ^= a; b = (b - ((a << 14) | (a >> 18))) & 0xFFFFFFFF
        c ^= b; c = (c - ((b << 24) | (b >> 8))) & 0xFFFFFFFF

    return c


if __name__ == "__main__":
    success = main()
    if not success:
        print("\nFailed. No changes made.")
    input("\nPress Enter to close...")
    sys.exit(0 if success else 1)
