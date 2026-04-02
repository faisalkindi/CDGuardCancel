"""
Step 5: Force-write idle values to top combat-correlated fields during attack.
Shotgun approach: if ANY of these control combat lock, flipping them back
to idle values should unblock guard.

Beeps: idle → you attack → script writes idle values → you try guard
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

# Known vtables
VT = {
    "CharCtrl": 0x14477C6B8,
    "PkgGroup": 0x144B37470,
}

def read_bytes(addr, size):
    buf = (ctypes.c_char * size)()
    if k32.ReadProcessMemory(handle, addr, buf, size, ctypes.byref(br)):
        return bytes(buf[:br.value])
    return None

def write_u32(addr, val):
    buf = struct.pack('<I', val)
    return k32.WriteProcessMemory(handle, addr, buf, 4, ctypes.byref(br))

def scan_heap(needle):
    hits = []
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
                    hits.append(mbi.BaseAddress + pos)
                    pos += 8
        addr = mbi.BaseAddress + mbi.RegionSize
        if addr == 0: break
    return hits

print("Finding instances...")
charctrl = scan_heap(struct.pack('<Q', VT["CharCtrl"]))
pkggroup = scan_heap(struct.pack('<Q', VT["PkgGroup"]))
print(f"  CharCtrl: {len(charctrl)}, PkgGroup: {len(pkggroup)}")

# From the scan: CharCtrl[1] and PkgGroup[7] and PkgGroup[8] had combat fields
# But instance indices may shift. Let's target ALL instances and write to the
# known combat-correlated offsets.

# Fields to force-write (offset, idle_value)
CHARCTRL_FIELDS = [(0x1F4, 1)]  # idle=1
PKGGROUP_FIELDS = [
    (0x1AC, 0), (0x268, 0), (0x26C, 0), (0x2EC, 0), (0x32C, 0),
    (0x368, 0), (0x36C, 0), (0x3A8, 0), (0x3AC, 0), (0x3E8, 0), (0x3EC, 0),
]

print(f"\nTargets: {len(charctrl)} CharCtrl x {len(CHARCTRL_FIELDS)} fields + {len(pkggroup)} PkgGroup x {len(PKGGROUP_FIELDS)} fields")

print("\nSwitch to game. 3 seconds...")
time.sleep(3)

print("\n>>> START ATTACKING! <<<")
for _ in range(3): winsound.Beep(1200, 150); time.sleep(0.15)
time.sleep(3)

print(">>> KEEP ATTACKING — writing idle values NOW <<<")
winsound.Beep(800, 300)

# Write idle values continuously for 5 seconds while user attacks + tries guard
start = time.time()
writes = 0
while time.time() - start < 8:
    for obj in charctrl:
        for off, val in CHARCTRL_FIELDS:
            write_u32(obj + off, val)
            writes += 1
    for obj in pkggroup:
        for off, val in PKGGROUP_FIELDS:
            write_u32(obj + off, val)
            writes += 1
    time.sleep(0.008)  # ~120Hz write rate

print(f">>> STOP — wrote {writes} values <<<")
winsound.Beep(500, 500)
print("\nDid guard work during the write window?")

pm.close_process()
input("Press Enter to close...")
