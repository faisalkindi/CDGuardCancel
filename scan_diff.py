"""
Differential scan: snapshots idle vs attacking, finds addresses that differ.
Run while game is open, standing idle.

1 beep  = taking IDLE snapshot
2 beeps = START ATTACKING for 3 seconds
3 beeps = STOP, taking ATTACK snapshot
1 low beep = DONE
"""
import pymem, struct, ctypes, time, winsound
from ctypes import wintypes

k32 = ctypes.windll.kernel32
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p), ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_bool

class MBI(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_uint64), ('AllocationBase', ctypes.c_uint64),
        ('AllocationProtect', wintypes.DWORD), ('_p1', wintypes.DWORD),
        ('RegionSize', ctypes.c_uint64), ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD), ('_p2', wintypes.DWORD),
    ]

k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t

def get_regions(handle):
    regions = []
    addr = 0x100000000
    while addr < 0x200000000:
        mbi = MBI()
        ret = k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0: break
        if mbi.State == 0x1000 and (mbi.Protect & 0x04 or mbi.Protect & 0x40):
            if 4096 <= mbi.RegionSize <= 10_000_000:
                regions.append((mbi.BaseAddress, mbi.RegionSize))
        addr = mbi.BaseAddress + mbi.RegionSize
    return regions

def snapshot(handle, regions):
    """Read all regions, return dict of {addr: uint32_value} for values 0-720."""
    br = ctypes.c_size_t(0)
    result = {}
    for base, size in regions:
        buf = (ctypes.c_char * size)()
        ok = k32.ReadProcessMemory(handle, base, buf, size, ctypes.byref(br))
        if not ok: continue
        data = bytes(buf[:br.value])
        for off in range(0, len(data) - 3, 4):
            val = struct.unpack_from('<I', data, off)[0]
            if val <= 720:
                result[base + off] = val
    return result

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle
print(f"Attached PID {pm.process_id}")

regions = get_regions(handle)
total = sum(s for _, s in regions)
print(f"{len(regions)} regions, {total/1024/1024:.0f} MB")

# Step 1: idle snapshot
print("\nStand IDLE (don't press anything)...")
time.sleep(2)
winsound.Beep(800, 300)
print("Taking IDLE snapshot...")
snap_idle = snapshot(handle, regions)
print(f"  {len(snap_idle)} addresses in range 0-720")

# Step 2: attack
time.sleep(1)
winsound.Beep(1200, 200)
time.sleep(0.1)
winsound.Beep(1200, 200)
print("\n>>> START ATTACKING NOW! <<<")
time.sleep(3)

# Step 3: attack snapshot
winsound.Beep(1200, 200)
time.sleep(0.1)
winsound.Beep(1200, 200)
time.sleep(0.1)
winsound.Beep(1200, 200)
print("Taking ATTACK snapshot...")
snap_attack = snapshot(handle, regions)
print(f"  {len(snap_attack)} addresses in range 0-720")

# Step 4: find differences
# Addresses that exist in both snapshots but have DIFFERENT values
diffs = []
common = set(snap_idle.keys()) & set(snap_attack.keys())
for addr in common:
    v_idle = snap_idle[addr]
    v_attack = snap_attack[addr]
    if v_idle != v_attack:
        diffs.append((addr, v_idle, v_attack))

print(f"\n{len(common)} common addresses, {len(diffs)} changed")
print(f"\nTop 50 candidates (sorted by address):")
for addr, v_idle, v_attack in sorted(diffs)[:50]:
    print(f"  0x{addr:016X}: idle={v_idle:4d} -> attack={v_attack:4d}")

# Group by (idle_val, attack_val) pair
from collections import Counter
pair_counts = Counter((vi, va) for _, vi, va in diffs)
print(f"\nTop value transitions (idle -> attack):")
for (vi, va), count in pair_counts.most_common(30):
    print(f"  {vi:4d} -> {va:4d}: {count:6d} addresses")

out = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\diff_results.txt"
with open(out, "w") as f:
    for addr, vi, va in sorted(diffs):
        f.write(f"0x{addr:016X} idle={vi} attack={va}\n")

pm.close_process()
winsound.Beep(500, 500)
print(f"\nDONE! {len(diffs)} results saved to diff_results.txt")
input("Press Enter to close...")
