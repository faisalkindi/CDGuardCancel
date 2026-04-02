"""
Find StageChart_Function_InputBlock instances on the heap.
Dumps their fields so we can identify _inputBlockType offset.
Run while game is loaded and in gameplay.
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

# InputBlock vtable from live RTTI scan
INPUTBLOCK_VTABLE = 0x144AFCC70
needle = struct.pack('<Q', INPUTBLOCK_VTABLE)

# Also try other related vtables
VTABLES = {
    "InputBlock": 0x144AFCC70,
    "ActionChartPkg": 0x144A6C610,
}

br = ctypes.c_size_t(0)

for name, vtable in VTABLES.items():
    needle = struct.pack('<Q', vtable)
    found = []

    # Scan full address space (heap can be anywhere)
    addr = 0
    while addr < 0x800000000000:
        mbi = MBI()
        if k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if (mbi.State == 0x1000 and
            mbi.RegionSize <= 100_000_000 and
            (mbi.Protect & 0x04)):  # PAGE_READWRITE = heap
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
        if addr == 0: break  # overflow protection

    print(f"\n=== {name} (vtable 0x{vtable:X}): {len(found)} instances ===")

    for obj in found[:20]:
        buf256 = (ctypes.c_char * 256)()
        if k32.ReadProcessMemory(handle, obj, buf256, 256, ctypes.byref(br)):
            data = bytes(buf256[:br.value])
            print(f"\n  Object at 0x{obj:X}:")
            for off in range(0, 128, 4):
                u32 = struct.unpack_from('<I', data, off)[0]
                f32 = struct.unpack_from('<f', data, off)[0]
                note = ""
                if off == 0: note = "VTABLE PTR"
                elif 0 < u32 <= 100: note = f"u32={u32} <<<"
                elif -1.0 <= f32 <= 100.0 and f32 != 0: note = f"f32={f32:.3f}"
                elif u32 == 0: note = "zero"
                print(f"    +0x{off:02X}: {data[off:off+4].hex()}  u32={u32:<12d} {note}")

pm.close_process()
print("\nDone")
