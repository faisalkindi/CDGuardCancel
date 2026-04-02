"""
Test: Disable all InputBlock instances by setting _inputBlockType to 0xFF.
If guard works during attacks after this, we found the solution.
Run while in gameplay. Press Ctrl+C to restore original values.
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
VTABLE = 0x144AFCC70
needle = struct.pack('<Q', VTABLE)
br = ctypes.c_size_t(0)

# Find all InputBlock instances
print("Finding InputBlock instances...")
found = []
addr = 0
while addr < 0x800000000000:
    mbi = MBI()
    if k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0: break
    if mbi.State == 0x1000 and mbi.RegionSize <= 100_000_000 and (mbi.Protect & 0x04):
        buf = (ctypes.c_char * mbi.RegionSize)()
        if k32.ReadProcessMemory(handle, mbi.BaseAddress, buf, mbi.RegionSize, ctypes.byref(br)):
            data = bytes(buf[:br.value])
            pos = 0
            while True:
                pos = data.find(needle, pos)
                if pos == -1: break
                found.append(mbi.BaseAddress + pos)
                pos += 8
    addr = mbi.BaseAddress + mbi.RegionSize
    if addr == 0: break

print(f"Found {len(found)} InputBlock instances")

# Read and save original _inputBlockType values (+0x18)
originals = {}
buf4 = (ctypes.c_char * 4)()
for obj in found:
    target = obj + 0x18
    if k32.ReadProcessMemory(handle, target, buf4, 4, ctypes.byref(br)):
        val = struct.unpack_from('<I', bytes(buf4), 0)[0]
        originals[obj] = val
        print(f"  0x{obj:X}: _inputBlockType = {val}")

# Patch all to 0xFF
print(f"\nPatching all {len(originals)} instances to type 0xFF...")
patch = struct.pack('<I', 0xFF)
patched = 0
for obj in originals:
    target = obj + 0x18
    if k32.WriteProcessMemory(handle, target, patch, 4, ctypes.byref(br)):
        patched += 1

print(f"Patched {patched}/{len(originals)}")
winsound.Beep(1000, 300)
print("\n>>> GO TEST: Attack then press guard (LB). Does it cancel? <<<")
print(">>> Press Ctrl+C when done to restore originals <<<\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass

# Restore originals
print("\nRestoring original values...")
for obj, val in originals.items():
    target = obj + 0x18
    restore = struct.pack('<I', val)
    k32.WriteProcessMemory(handle, target, restore, 4, ctypes.byref(br))

print("Restored. Done.")
pm.close_process()
