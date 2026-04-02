"""
Find ActionChart objects in memory by vtable pointer.
No user interaction needed — just reads memory.
"""
import pymem, struct, ctypes
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

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle
print(f"PID {pm.process_id}")

# Known vtable VAs from RTTI analysis
vtables = {
    "ActionChartPackage_BaseData": 0x144A5E650,
    "ClientInputActorComponent": 0x144782010,
    "CommonInputActorComponent": 0x14493D7F8,
    "ClientFrameEventActorComponent": 0x1449AFC28 + 0x140000000 - 0x140000000,  # need actual VA
    "CommonCharacterControlActorComponent": 0x1449C04A0 + 0x140000000 - 0x140000000,
}

# For each vtable, scan memory for 8-byte pointers matching the vtable VA
br = ctypes.c_size_t(0)

for name, vtable_va in vtables.items():
    print(f"\n=== Scanning for {name} (vtable 0x{vtable_va:X}) ===")
    needle = struct.pack('<Q', vtable_va)
    found = []

    addr = 0x100000000
    while addr < 0x200000000:
        mbi = MBI()
        if k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0: break
        if mbi.State == 0x1000 and (mbi.Protect & 0x04 or mbi.Protect & 0x40):
            if mbi.RegionSize <= 50_000_000:
                buf = (ctypes.c_char * mbi.RegionSize)()
                if k32.ReadProcessMemory(handle, mbi.BaseAddress, buf, mbi.RegionSize, ctypes.byref(br)):
                    data = bytes(buf[:br.value])
                    pos = 0
                    while True:
                        pos = data.find(needle, pos)
                        if pos == -1: break
                        obj_addr = mbi.BaseAddress + pos
                        found.append(obj_addr)
                        pos += 8
        addr = mbi.BaseAddress + mbi.RegionSize

    print(f"  Found {len(found)} instances")

    # Dump first 256 bytes of each instance
    for obj_addr in found[:10]:
        buf256 = (ctypes.c_char * 256)()
        if k32.ReadProcessMemory(handle, obj_addr, buf256, 256, ctypes.byref(br)):
            data = bytes(buf256[:br.value])
            print(f"\n  Object at 0x{obj_addr:X}:")
            for off in range(0, min(256, len(data)), 8):
                qval = struct.unpack_from('<Q', data, off)[0]
                ival = struct.unpack_from('<I', data, off)[0]
                fval = struct.unpack_from('<f', data, off)[0]
                is_ptr = 0x100000000 <= qval <= 0x7FFFFFFFFFFF
                extra = "PTR" if is_ptr else ""
                if 0 < ival <= 1000 and not is_ptr:
                    extra = f"<< u32={ival}"
                if 0.0 < fval < 100.0 and not is_ptr:
                    extra = f"<< f32={fval:.3f}"
                print(f"    +0x{off:03X}: {data[off:off+8].hex()}  q=0x{qval:016X}  {extra}")

pm.close_process()
print("\nDone")
input("Press Enter to close...")
