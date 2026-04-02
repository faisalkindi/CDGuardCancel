"""
Test: Patch ALL non-guard transitions to also go to guard (state 0).
This is a brute-force test to see if writing to transition targets
in memory actually affects game behavior.

Run while in gameplay. Ctrl+C to restore.
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
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = ctypes.c_bool

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle
br = ctypes.c_size_t(0)

# Find the region with sword_upper data
needle = b'common_upper_branchset'
print("Finding sword_upper region...")
addr = 0x100000000
target_region = None
while addr < 0x800000000000:
    mbi = MBI()
    if k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0: break
    if mbi.State == 0x1000 and mbi.RegionSize <= 100_000_000 and (mbi.Protect & 0x06):
        buf = (ctypes.c_char * mbi.RegionSize)()
        if k32.ReadProcessMemory(handle, mbi.BaseAddress, buf, mbi.RegionSize, ctypes.byref(br)):
            data = bytes(buf[:br.value])
            if needle in data:
                target_region = (mbi.BaseAddress, data)
                break
    addr = mbi.BaseAddress + mbi.RegionSize
    if addr == 0: break

if not target_region:
    print("Region not found")
    pm.close_process()
    exit()

region_base, region_data = target_region
print(f"Region at 0x{region_base:X} ({len(region_data)} bytes)")

# Find all transitions: [float 0-1] [-1.0] [uint32 target 0-720] [uint32 seq 0-100]
sentinel = b'\x00\x00\x80\xBF'
all_trans = []
for i in range(0, len(region_data) - 16, 4):
    if region_data[i+4:i+8] == sentinel:
        thresh = struct.unpack_from('<f', region_data, i)[0]
        target = struct.unpack_from('<I', region_data, i+8)[0]
        seq = struct.unpack_from('<I', region_data, i+12)[0]
        if 0.0 <= thresh <= 1.0 and target <= 720 and seq <= 100:
            all_trans.append((region_base + i, thresh, target, seq))

# Filter: only patch transitions that DON'T already go to guard (0)
# and go to attack-range states (> 50, likely attack sub-states)
to_patch = [(a, th, t, s) for a, th, t, s in all_trans if t > 50]
print(f"Total transitions: {len(all_trans)}")
print(f"Non-guard transitions (target > 50): {len(to_patch)}")

# Save originals
originals = {}
buf4 = (ctypes.c_char * 4)()
for trans_addr, thresh, target, seq in to_patch:
    target_addr = trans_addr + 8  # target uint32 is at offset +8 in the transition
    originals[target_addr] = target

# Patch: change all attack transitions to target guard (state 0)
print(f"\nPatching {len(to_patch)} transitions to target guard (state 0)...")
patch_val = struct.pack('<I', 0)
patched = 0
for target_addr in originals:
    if k32.WriteProcessMemory(handle, target_addr, patch_val, 4, ctypes.byref(br)):
        patched += 1

print(f"Patched {patched}/{len(originals)}")
winsound.Beep(1000, 300)
print("\n>>> TEST NOW: Attack then press guard. Does it cancel instantly? <<<")
print(">>> Also try: can you still do a normal attack combo? <<<")
print(">>> Press Ctrl+C to restore <<<\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass

# Restore
print("\nRestoring...")
for target_addr, orig_val in originals.items():
    restore = struct.pack('<I', orig_val)
    k32.WriteProcessMemory(handle, target_addr, restore, 4, ctypes.byref(br))

print("Restored. Done.")
pm.close_process()
