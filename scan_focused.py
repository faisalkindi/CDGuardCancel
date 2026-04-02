"""
Focused 4-round scan: idle1 -> attack -> idle2 -> guard
Only keeps addresses where:
  idle1 == idle2 (stable idle value)
  idle != attack (changes during attack)
  idle != guard OR idle == guard (both interesting)
Scans as uint16 too (state might be 2 bytes).
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

def beep_and_wait(freq, ms, msg, wait):
    winsound.Beep(freq, ms)
    print(msg)
    time.sleep(wait)

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle
regions = get_regions(handle)
print(f"PID {pm.process_id}, {len(regions)} regions, {sum(s for _,s in regions)/1024/1024:.0f} MB\n")

snaps = {}  # {phase: {base: bytes}}

# IDLE 1
beep_and_wait(600, 400, "Stand IDLE (don't touch anything)...", 2)
print("Snapping IDLE1...")
for base, size in regions:
    d = read_region(handle, base, size)
    if d: snaps.setdefault(0, {})[base] = d
print("  Done\n")

# ATTACK
beep_and_wait(1200, 200, ">>> START ATTACKING! <<<", 0)
time.sleep(3)
beep_and_wait(1200, 150, ">>> STOP ATTACKING <<<", 1)
print("Snapping ATTACK...")
for base, size in regions:
    d = read_region(handle, base, size)
    if d: snaps.setdefault(1, {})[base] = d
print("  Done\n")

# IDLE 2
beep_and_wait(600, 400, "Stand IDLE again...", 3)
print("Snapping IDLE2...")
for base, size in regions:
    d = read_region(handle, base, size)
    if d: snaps.setdefault(2, {})[base] = d
print("  Done\n")

# GUARD
beep_and_wait(900, 200, ">>> HOLD GUARD (LB) NOW! <<<", 3)
beep_and_wait(900, 400, ">>> RELEASE GUARD <<<", 1)
print("Snapping GUARD...")
for base, size in regions:
    d = read_region(handle, base, size)
    if d: snaps.setdefault(3, {})[base] = d
print("  Done\n")

# COMPARE — 4-byte values
print("Comparing (uint32)...")
results_u32 = []
for base in snaps[0]:
    if base not in snaps[1] or base not in snaps[2] or base not in snaps[3]:
        continue
    d0, d1, d2, d3 = snaps[0][base], snaps[1][base], snaps[2][base], snaps[3][base]
    minlen = min(len(d0), len(d1), len(d2), len(d3))
    for off in range(0, minlen - 3, 4):
        v_idle1 = struct.unpack_from('<I', d0, off)[0]
        v_attack = struct.unpack_from('<I', d1, off)[0]
        v_idle2 = struct.unpack_from('<I', d2, off)[0]
        v_guard = struct.unpack_from('<I', d3, off)[0]
        # idle1 == idle2 (stable), idle != attack
        if v_idle1 == v_idle2 and v_idle1 != v_attack:
            if v_idle1 <= 1000 and v_attack <= 1000 and v_guard <= 1000:
                results_u32.append((base + off, v_idle1, v_attack, v_guard))

print(f"  {len(results_u32)} candidates (uint32, values<=1000, idle stable)")

# COMPARE — 2-byte values
print("Comparing (uint16)...")
results_u16 = []
for base in snaps[0]:
    if base not in snaps[1] or base not in snaps[2] or base not in snaps[3]:
        continue
    d0, d1, d2, d3 = snaps[0][base], snaps[1][base], snaps[2][base], snaps[3][base]
    minlen = min(len(d0), len(d1), len(d2), len(d3))
    for off in range(0, minlen - 1, 2):
        v_idle1 = struct.unpack_from('<H', d0, off)[0]
        v_attack = struct.unpack_from('<H', d1, off)[0]
        v_idle2 = struct.unpack_from('<H', d2, off)[0]
        v_guard = struct.unpack_from('<H', d3, off)[0]
        if v_idle1 == v_idle2 and v_idle1 != v_attack:
            if v_idle1 <= 1000 and v_attack <= 1000 and v_guard <= 1000:
                results_u16.append((base + off, v_idle1, v_attack, v_guard))

print(f"  {len(results_u16)} candidates (uint16, values<=1000, idle stable)")

# Show best candidates: where idle==guard (state returns to same after guard)
print("\n=== UINT32: idle==guard, idle!=attack, idle stable ===")
u32_igmatch = [(a,i,t,g) for a,i,t,g in results_u32 if i == g]
print(f"{len(u32_igmatch)} matches")
for addr, vi, va, vg in sorted(u32_igmatch)[:40]:
    print(f"  0x{addr:016X}: idle={vi:4d}  attack={va:4d}  guard={vg:4d}")

print("\n=== UINT32: all 3 different, idle stable ===")
u32_3diff = [(a,i,t,g) for a,i,t,g in results_u32 if i != g and i != t and t != g]
print(f"{len(u32_3diff)} matches")
for addr, vi, va, vg in sorted(u32_3diff)[:40]:
    print(f"  0x{addr:016X}: idle={vi:4d}  attack={va:4d}  guard={vg:4d}")

print("\n=== UINT16: idle==guard, idle!=attack, idle stable ===")
u16_igmatch = [(a,i,t,g) for a,i,t,g in results_u16 if i == g]
print(f"{len(u16_igmatch)} matches")
for addr, vi, va, vg in sorted(u16_igmatch)[:40]:
    print(f"  0x{addr:016X}: idle={vi:4d}  attack={va:4d}  guard={vg:4d}")

print("\n=== UINT16: all 3 different, idle stable ===")
u16_3diff = [(a,i,t,g) for a,i,t,g in results_u16 if i != g and i != t and t != g]
print(f"{len(u16_3diff)} matches")
for addr, vi, va, vg in sorted(u16_3diff)[:40]:
    print(f"  0x{addr:016X}: idle={vi:4d}  attack={va:4d}  guard={vg:4d}")

winsound.Beep(500, 500)
pm.close_process()
print("\nDONE!")
input("Press Enter to close...")
