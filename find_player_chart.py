"""
Step 4+5: Identify player's ActionChartPackage and find current state fields.
1. Find all 92 ActionChartPackage objects
2. Filter by +0x48 value (near sword_upper scale: 600-720)
3. Follow pointers, dump deeper structure
4. Sample fields at 30Hz while user plays, correlate with attacks/guard
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

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle
br = ctypes.c_size_t(0)

VTABLE = 0x144A6C610
needle = struct.pack('<Q', VTABLE)

def read_u32(addr):
    buf = (ctypes.c_char * 4)()
    if k32.ReadProcessMemory(handle, addr, buf, 4, ctypes.byref(br)):
        return struct.unpack_from('<I', bytes(buf), 0)[0]
    return None

def read_u64(addr):
    buf = (ctypes.c_char * 8)()
    if k32.ReadProcessMemory(handle, addr, buf, 8, ctypes.byref(br)):
        return struct.unpack_from('<Q', bytes(buf), 0)[0]
    return None

def read_bytes(addr, size):
    buf = (ctypes.c_char * size)()
    if k32.ReadProcessMemory(handle, addr, buf, size, ctypes.byref(br)):
        return bytes(buf[:br.value])
    return None

# Step 1: Find all ActionChartPackage instances
print("Finding ActionChartPackage instances...")
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

print(f"Found {len(found)} instances")

# Step 2: Read key fields, filter candidates
print("\nFiltering by +0x48 value (looking for sword chart ~600-720)...")
candidates = []
for obj in found:
    data = read_bytes(obj, 512)
    if not data or len(data) < 256: continue
    val_10 = struct.unpack_from('<I', data, 0x10)[0]
    val_30 = struct.unpack_from('<I', data, 0x30)[0]
    val_48 = struct.unpack_from('<I', data, 0x48)[0]
    ptr_18 = struct.unpack_from('<Q', data, 0x18)[0]
    ptr_38 = struct.unpack_from('<Q', data, 0x38)[0]
    ptr_50 = struct.unpack_from('<Q', data, 0x50)[0]

    print(f"  0x{obj:X}: +10={val_10:4d} +30={val_30:4d} +48={val_48:4d} ptrs=[0x{ptr_18:X}, 0x{ptr_38:X}, 0x{ptr_50:X}]")

    if 500 <= val_48 <= 800:
        candidates.append((obj, data, val_48))

print(f"\n{len(candidates)} candidates with +0x48 in range 500-800")

# Step 3: For each candidate, follow pointers and dump deeper
for obj, data, node_count in candidates:
    print(f"\n{'='*60}")
    print(f"CANDIDATE at 0x{obj:X} (node_count={node_count})")
    print(f"{'='*60}")

    # Dump the full 512 bytes with annotations
    for off in range(0, 256, 8):
        qval = struct.unpack_from('<Q', data, off)[0]
        u32a = struct.unpack_from('<I', data, off)[0]
        u32b = struct.unpack_from('<I', data, off+4)[0]
        is_ptr = 0x100000000 <= qval <= 0x7FFFFFFFFFFF
        note = ""
        if is_ptr:
            note = "PTR"
            # Try to read what the pointer points to
            target_data = read_bytes(qval, 32)
            if target_data:
                first_u32 = struct.unpack_from('<I', target_data, 0)[0]
                first_u64 = struct.unpack_from('<Q', target_data, 0)[0]
                if 0x140000000 <= first_u64 <= 0x150000000:
                    note = f"PTR -> vtable? 0x{first_u64:X}"
                elif first_u32 <= 1000:
                    note = f"PTR -> [{first_u32}, ...]"
                else:
                    note = f"PTR -> 0x{first_u32:08X}..."
        elif u32a <= 1000 and u32a > 0:
            note = f"u32={u32a}"
        print(f"  +0x{off:03X}: {data[off:off+8].hex()}  {note}")

    # Follow the first few pointers deeper
    for ptr_off in [0x18, 0x20, 0x28, 0x38, 0x40, 0x50]:
        ptr = struct.unpack_from('<Q', data, ptr_off)[0]
        if 0x100000000 <= ptr <= 0x7FFFFFFFFFFF:
            target = read_bytes(ptr, 128)
            if target:
                print(f"\n  Following +0x{ptr_off:02X} -> 0x{ptr:X}:")
                for i in range(0, min(128, len(target)), 8):
                    qv = struct.unpack_from('<Q', target, i)[0]
                    u32 = struct.unpack_from('<I', target, i)[0]
                    f32 = struct.unpack_from('<f', target, i)[0]
                    note = ""
                    if 0x100000000 <= qv <= 0x7FFFFFFFFFFF: note = "PTR"
                    elif 0 < u32 <= 1000: note = f"u32={u32}"
                    elif -2.0 <= f32 <= 100.0 and f32 != 0: note = f"f={f32:.3f}"
                    print(f"    +{i:03X}: {target[i:i+8].hex()}  {note}")

pm.close_process()
print("\nDone")
