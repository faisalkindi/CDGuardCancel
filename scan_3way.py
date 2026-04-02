"""
3-way scan: idle -> attack -> guard (memory efficient)
Scans region by region, comparing on the fly.
"""
import pymem, struct, ctypes, time, winsound
from ctypes import wintypes

class MBI(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_uint64), ('AllocationBase', ctypes.c_uint64),
        ('AllocationProtect', wintypes.DWORD), ('_p1', wintypes.DWORD),
        ('RegionSize', ctypes.c_uint64), ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD), ('_p2', wintypes.DWORD),
    ]

k32 = ctypes.windll.kernel32
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_bool

def get_regions(handle):
    regions = []
    addr = 0x100000000
    while addr < 0x200000000:
        mbi = MBI()
        if k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0: break
        if mbi.State == 0x1000 and (mbi.Protect & 0x04 or mbi.Protect & 0x40):
            if 4096 <= mbi.RegionSize <= 10_000_000:
                regions.append((mbi.BaseAddress, mbi.RegionSize))
        addr = mbi.BaseAddress + mbi.RegionSize
    return regions

def read_region(handle, base, size):
    br = ctypes.c_size_t(0)
    buf = (ctypes.c_char * size)()
    if not k32.ReadProcessMemory(handle, base, buf, size, ctypes.byref(br)):
        return None
    return bytes(buf[:br.value])

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle
regions = get_regions(handle)
print(f"PID {pm.process_id}, {len(regions)} regions, {sum(s for _,s in regions)/1024/1024:.0f} MB")

# Save region list for all 3 passes
region_data = {}

# === IDLE ===
print("\nStand IDLE...")
time.sleep(2)
winsound.Beep(600, 400)
print("Reading IDLE...")
for base, size in regions:
    data = read_region(handle, base, size)
    if data:
        region_data.setdefault(base, {})[0] = data  # 0 = idle
print("  Done")

# === ATTACK ===
winsound.Beep(1200, 200); time.sleep(0.1); winsound.Beep(1200, 200)
print("\n>>> ATTACK NOW! <<<")
time.sleep(3)
print(">>> KEEP ATTACKING... scanning in 2s <<<")
time.sleep(2)
winsound.Beep(1200, 150); time.sleep(0.1); winsound.Beep(1200, 150); time.sleep(0.1); winsound.Beep(1200, 150)
print(">>> STOP ATTACKING <<<")
print("Reading ATTACK...")
for base, size in regions:
    data = read_region(handle, base, size)
    if data:
        region_data.setdefault(base, {})[1] = data  # 1 = attack
print("  Done")

# === GUARD ===
winsound.Beep(900, 200); time.sleep(0.1); winsound.Beep(900, 200)
print("\n>>> HOLD GUARD (LB) NOW! <<<")
time.sleep(3)
winsound.Beep(900, 400)
print(">>> RELEASE GUARD <<<")
print("Reading GUARD...")
for base, size in regions:
    data = read_region(handle, base, size)
    if data:
        region_data.setdefault(base, {})[2] = data  # 2 = guard
print("  Done")

# === COMPARE region by region ===
print("\nComparing...")
all_diff = []       # all 3 different
idle_eq_guard = []  # idle == guard, attack differs

for base, snapshots in region_data.items():
    if len(snapshots) < 3: continue
    d0, d1, d2 = snapshots[0], snapshots[1], snapshots[2]
    minlen = min(len(d0), len(d1), len(d2))
    for off in range(0, minlen - 3, 4):
        vi = struct.unpack_from('<I', d0, off)[0]
        va = struct.unpack_from('<I', d1, off)[0]
        vg = struct.unpack_from('<I', d2, off)[0]
        if vi > 720 or va > 720 or vg > 720: continue
        addr = base + off
        if vi != va and va != vg and vi != vg:
            all_diff.append((addr, vi, va, vg))
        elif vi == vg and vi != va:
            idle_eq_guard.append((addr, vi, va, vg))

# Free memory
del region_data

print(f"\n{len(all_diff)} addresses: all 3 different")
print(f"{len(idle_eq_guard)} addresses: idle==guard, attack differs")

# Show all-3-different with small values
small = [(a,i,t,g) for a,i,t,g in all_diff if i<=100 and t<=100 and g<=100]
print(f"\n=== ALL 3 DIFFERENT (values <= 100): {len(small)} ===")
for addr, vi, va, vg in sorted(small)[:80]:
    print(f"  0x{addr:016X}: idle={vi:3d}  attack={va:3d}  guard={vg:3d}")

# Show idle==guard patterns
from collections import Counter
ig = Counter((vi, va) for _, vi, va, _ in idle_eq_guard)
print(f"\n=== IDLE==GUARD, ATTACK DIFFERS (top 20) ===")
for (vi, va), c in ig.most_common(20):
    print(f"  {vi:4d} -> {va:4d}: {c:6d}")

# Show idle==guard with small values
ig_small = [(a,i,t,g) for a,i,t,g in idle_eq_guard if i<=50 and t<=50]
print(f"\n=== IDLE==GUARD small (values<=50): {len(ig_small)} ===")
for addr, vi, va, vg in sorted(ig_small)[:80]:
    print(f"  0x{addr:016X}: idle/guard={vi:3d}  attack={va:3d}")

out = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\3way_results.txt"
with open(out, "w") as f:
    f.write("=== ALL 3 DIFFERENT ===\n")
    for addr, vi, va, vg in sorted(all_diff):
        f.write(f"0x{addr:016X} idle={vi} attack={va} guard={vg}\n")
    f.write(f"\n=== IDLE==GUARD ===\n")
    for addr, vi, va, vg in sorted(idle_eq_guard):
        f.write(f"0x{addr:016X} idle/guard={vi} attack={va}\n")

winsound.Beep(500, 500)
pm.close_process()
print(f"\nDONE!")
input("Press Enter to close...")
