#!/usr/bin/env python3
"""Deploy full 26-state guard cancel patch using PAZ-shift method."""

import struct, lz4.block, shutil, os, sys

PAZ_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.paz"
PAZ_BACKUP = PAZ_PATH + ".bak"
PAMT_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.pamt"
PAMT_BACKUP = PAMT_PATH + ".bak"
PAPGT_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\papgt"
PAPGT_BACKUP = PAPGT_PATH + ".bak"

PAZ_OFFSET = 225322576
COMP_SIZE = 224084
DECOMP_SIZE = 1243769

MAGIC = b"\x4D\x30\x25\x44"
SENTINEL = b"\x00\x00\x80\xBF"
GUARD = b"\x00\x00\x00\x00\x00\x00\x80\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
HASH_SEED = 0xC5EDE


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
    print("  Guard Cancel - Full 26-State PAZ-Shift Deploy")
    print("=" * 60)

    # Read and decompress
    print("\n[1/7] Reading sword_upper...")
    with open(PAZ_PATH, "rb") as f:
        f.seek(PAZ_OFFSET)
        compressed = f.read(COMP_SIZE)
    paac = bytearray(lz4.block.decompress(compressed, uncompressed_size=DECOMP_SIZE))
    assert len(paac) == DECOMP_SIZE
    print(f"  OK: {len(paac)} bytes")

    # Find and patch all unguarded states
    print("\n[2/7] Patching unguarded states...")
    markers = []
    pos = 0x44
    while pos < 0x8E96A:
        idx = paac.find(MAGIC, pos, 0x8E96A)
        if idx == -1:
            break
        markers.append(idx)
        pos = idx + 1

    large_states = []
    for i in range(len(markers)):
        end = markers[i + 1] if i + 1 < len(markers) else 0x8E96A
        sz = end - markers[i]
        if sz > 16:
            large_states.append((i, markers[i], sz))

    patched = 0
    for si, off, sz in large_states:
        rec = paac[off:off + sz]
        has_guard = False
        t112 = None
        t1073 = None
        tlast = None
        p = 0
        while True:
            idx = rec.find(SENTINEL, p)
            if idx == -1:
                break
            if idx >= 4 and idx + 8 <= len(rec):
                thresh = struct.unpack_from("<f", rec, idx - 4)[0]
                target = struct.unpack_from("<I", rec, idx + 4)[0]
                seq_val = struct.unpack_from("<I", rec, idx + 8)[0]
                if 0.0 <= thresh <= 10.0 and target < 50000 and seq_val < 5000:
                    abs_off = off + idx - 4
                    if target == 0:
                        has_guard = True
                    if target == 112 and t112 is None:
                        t112 = abs_off
                    if target == 1073:
                        t1073 = abs_off
                    tlast = abs_off
            p = idx + 1

        if not has_guard and tlast is not None:
            victim = t112 or t1073 or tlast
            paac[victim:victim + 16] = GUARD
            patched += 1
            print(f"  State {si}: patched")

    print(f"  Total: {patched} states")

    # Compress
    print("\n[3/7] Compressing...")
    new_comp = lz4.block.compress(bytes(paac), mode="default", acceleration=1, store_size=False)
    new_comp_size = len(new_comp)
    delta = new_comp_size - COMP_SIZE
    print(f"  Size: {new_comp_size} (delta: {delta:+d})")

    verify = lz4.block.decompress(new_comp, uncompressed_size=DECOMP_SIZE)
    assert verify == bytes(paac), "Roundtrip failed!"
    print("  Roundtrip OK")

    # Backups
    print("\n[4/7] Backups...")
    for src, bak, name in [(PAZ_PATH, PAZ_BACKUP, "PAZ"), (PAMT_PATH, PAMT_BACKUP, "PAMT"), (PAPGT_PATH, PAPGT_BACKUP, "PAPGT")]:
        if os.path.exists(src) and not os.path.exists(bak):
            shutil.copy2(src, bak)
            print(f"  {name} backed up")
        else:
            print(f"  {name} backup exists" if os.path.exists(bak) else f"  {name} not found")

    # PAZ shift
    print("\n[5/7] PAZ shift...")
    with open(PAZ_PATH, "rb") as f:
        paz_data = bytearray(f.read())
    old_paz_size = len(paz_data)

    insert_point = PAZ_OFFSET + COMP_SIZE
    new_paz = bytearray()
    new_paz.extend(paz_data[:PAZ_OFFSET])
    new_paz.extend(new_comp)
    new_paz.extend(paz_data[insert_point:])
    new_paz_size = len(new_paz)
    print(f"  PAZ: {old_paz_size:,} -> {new_paz_size:,} ({delta:+d})")

    tmp = PAZ_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(new_paz)
    os.replace(tmp, PAZ_PATH)
    print("  PAZ written")

    # Update PAMT
    print("\n[6/7] Updating PAMT...")
    with open(PAMT_PATH, "rb") as f:
        pamt_data = bytearray(f.read())

    old_pamt_hash = struct.unpack_from("<I", pamt_data, 0)[0]

    # Find sword_upper record and update comp_size
    target_bytes = struct.pack("<III", PAZ_OFFSET, COMP_SIZE, DECOMP_SIZE)
    rec_pos = pamt_data.find(target_bytes)
    if rec_pos < 0:
        print("  ERROR: sword_upper not found in PAMT!")
        return False
    struct.pack_into("<I", pamt_data, rec_pos + 4, new_comp_size)
    print(f"  sword_upper comp: {COMP_SIZE} -> {new_comp_size}")

    # Shift all subsequent entries (offset > PAZ_OFFSET)
    shifted = 0
    scan = 0
    while scan < len(pamt_data) - 12:
        off_val = struct.unpack_from("<I", pamt_data, scan)[0]
        if off_val > PAZ_OFFSET and off_val < old_paz_size:
            comp_val = struct.unpack_from("<I", pamt_data, scan + 4)[0]
            decomp_val = struct.unpack_from("<I", pamt_data, scan + 8)[0]
            if (0 < comp_val < 50_000_000 and
                0 < decomp_val < 50_000_000 and
                off_val + comp_val <= old_paz_size + 1024):
                struct.pack_into("<I", pamt_data, scan, off_val + delta)
                shifted += 1
                scan += 12
                continue
        scan += 1
    print(f"  Shifted {shifted} entries by {delta:+d}")

    # Update PAZ size in PAMT header
    paz_count = struct.unpack_from("<I", pamt_data, 4)[0]
    for pi in range(paz_count):
        sz_off = 8 + pi * 4
        sz_val = struct.unpack_from("<I", pamt_data, sz_off)[0]
        if sz_val == old_paz_size:
            struct.pack_into("<I", pamt_data, sz_off, new_paz_size)
            print(f"  PAZ[{pi}] size: {old_paz_size:,} -> {new_paz_size:,}")
            break
    else:
        print(f"  WARNING: PAZ size entry not found")

    # Recompute PAMT hash
    new_pamt_hash = hashlittle(bytes(pamt_data[12:]), HASH_SEED)
    struct.pack_into("<I", pamt_data, 0, new_pamt_hash)
    print(f"  PAMT hash: 0x{old_pamt_hash:08X} -> 0x{new_pamt_hash:08X}")

    tmp = PAMT_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(pamt_data)
    os.replace(tmp, PAMT_PATH)
    print("  PAMT written")

    # Update PAPGT
    print("\n[7/7] Updating PAPGT...")
    if os.path.exists(PAPGT_PATH):
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
            papgt_file_hash = hashlittle(bytes(papgt_data[12:]), HASH_SEED)
            struct.pack_into("<I", papgt_data, 4, papgt_file_hash)

            with open(PAPGT_PATH, "wb") as f:
                f.write(papgt_data)
            print(f"  Updated {count} hash ref(s), file hash recomputed")
        else:
            print("  WARNING: Old PAMT hash not found in PAPGT")
    else:
        print("  PAPGT not found")

    print(f"\n{'=' * 60}")
    print(f"  DEPLOYED: {patched} states, PAZ shifted {delta:+d} bytes")
    print(f"  To restore: py -3 tools/restore_guard_patch.py")
    print(f"{'=' * 60}")
    return True


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
