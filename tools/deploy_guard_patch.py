#!/usr/bin/env python3
"""
Deploy the guard-cancel-during-attacks patch for sword_upper.paac.

Patches State 301 (main attack state) and State 328 (combo hub) to add
guard transitions (target=0, threshold=0.0). In-place PAZ replacement
with exact LZ4 size match (224,084 bytes).

Creates a backup of the original PAZ before patching.
"""

import struct
import shutil
import os
import sys
import lz4.block

PAZ_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.paz"
PAZ_BACKUP = PAZ_PATH + ".bak"
PAZ_OFFSET = 225322576      # sword_upper offset in 0.paz
COMP_SIZE = 224084           # compressed size in PAZ
DECOMP_SIZE = 1243769        # decompressed .paac size

# Guard transition: [thresh=0.0] [sentinel=-1.0] [target=0] [seq=0]
GUARD_BYTES = b'\x00\x00\x00\x00\x00\x00\x80\xBF\x00\x00\x00\x00\x00\x00\x00\x00'

# Patch targets (file offsets within decompressed sword_upper.paac)
PATCHES = [
    {
        'name': 'State 301 (main attack state)',
        'offset': 0x07DF1D,
        'expected': b'\x00\x00\x00\x00\x00\x00\x80\xBF\x70\x00\x00\x00\x0B\x00\x00\x00',
        'description': 'target=112 seq=11 -> target=0 (guard)',
    },
    {
        'name': 'State 328 (combo hub)',
        'offset': 0x08D4D0,
        'expected': b'\x89\x88\x88\x3D\x00\x00\x80\xBF\x31\x04\x00\x00\x03\x00\x00\x00',
        'description': 'target=1073 seq=3 -> target=0 (guard)',
    },
]


def main():
    print("=" * 70)
    print("  Crimson Desert — Guard Cancel During Attacks")
    print("  Patches sword_upper.paac in 0010/0.paz")
    print("=" * 70)

    # Verify PAZ exists
    if not os.path.exists(PAZ_PATH):
        print(f"\nERROR: PAZ file not found: {PAZ_PATH}")
        return False

    # Step 1: Read and decompress current sword_upper
    print(f"\n[1/5] Reading sword_upper from PAZ...")
    with open(PAZ_PATH, 'rb') as f:
        f.seek(PAZ_OFFSET)
        compressed = f.read(COMP_SIZE)

    if len(compressed) != COMP_SIZE:
        print(f"  ERROR: Read {len(compressed)} bytes, expected {COMP_SIZE}")
        return False

    paac = bytearray(lz4.block.decompress(compressed, uncompressed_size=DECOMP_SIZE))
    if len(paac) != DECOMP_SIZE:
        print(f"  ERROR: Decompressed to {len(paac)} bytes, expected {DECOMP_SIZE}")
        return False
    print(f"  OK: {len(paac)} bytes decompressed")

    # Step 2: Verify patch targets match expected bytes
    print(f"\n[2/5] Verifying patch targets...")
    for patch in PATCHES:
        actual = bytes(paac[patch['offset']:patch['offset'] + 16])
        if actual == GUARD_BYTES:
            print(f"  {patch['name']}: Already patched!")
            patch['skip'] = True
        elif actual == patch['expected']:
            print(f"  {patch['name']}: OK (vanilla bytes match)")
            patch['skip'] = False
        else:
            print(f"  {patch['name']}: UNEXPECTED bytes at 0x{patch['offset']:06X}")
            print(f"    Expected: {patch['expected'].hex(' ')}")
            print(f"    Actual:   {actual.hex(' ')}")
            print(f"  The .paac may have been updated. Aborting.")
            return False

    patches_to_apply = [p for p in PATCHES if not p.get('skip')]
    if not patches_to_apply:
        print("\n  All patches already applied. Nothing to do.")
        return True

    # Step 3: Apply patches
    print(f"\n[3/5] Applying {len(patches_to_apply)} patches...")
    for patch in patches_to_apply:
        paac[patch['offset']:patch['offset'] + 16] = GUARD_BYTES
        print(f"  {patch['name']}: {patch['description']}")

    # Step 4: Recompress and verify size
    print(f"\n[4/5] Recompressing with LZ4...")
    new_compressed = lz4.block.compress(bytes(paac), mode='default', acceleration=1, store_size=False)
    if len(new_compressed) != COMP_SIZE:
        print(f"  ERROR: Compressed to {len(new_compressed)} bytes, expected {COMP_SIZE}")
        print(f"  Delta: {len(new_compressed) - COMP_SIZE:+d} bytes")
        print(f"  Cannot do in-place replacement. Aborting.")
        return False
    print(f"  OK: {len(new_compressed)} bytes (exact match)")

    # Verify roundtrip
    verify = lz4.block.decompress(new_compressed, uncompressed_size=DECOMP_SIZE)
    if verify != bytes(paac):
        print(f"  ERROR: Roundtrip verification failed!")
        return False
    print(f"  Roundtrip verified")

    # Step 5: Backup and write
    print(f"\n[5/5] Writing to PAZ...")
    if not os.path.exists(PAZ_BACKUP):
        print(f"  Creating backup: {PAZ_BACKUP}")
        shutil.copy2(PAZ_PATH, PAZ_BACKUP)
    else:
        print(f"  Backup already exists: {PAZ_BACKUP}")

    with open(PAZ_PATH, 'r+b') as f:
        f.seek(PAZ_OFFSET)
        f.write(new_compressed)

    print(f"  Written {len(new_compressed)} bytes at offset {PAZ_OFFSET}")

    # Final verification
    with open(PAZ_PATH, 'rb') as f:
        f.seek(PAZ_OFFSET)
        readback = f.read(COMP_SIZE)

    if readback == new_compressed:
        print(f"\n  Readback verified OK")
    else:
        print(f"\n  ERROR: Readback mismatch!")
        return False

    print(f"\n{'=' * 70}")
    print(f"  PATCH APPLIED SUCCESSFULLY")
    print(f"  Modified: State 301 (attack) + State 328 (combo hub)")
    print(f"  Effect: LB (guard) now available during sword attack combos")
    print(f"  Backup: {PAZ_BACKUP}")
    print(f"  To restore: copy .bak over .paz")
    print(f"{'=' * 70}")
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
