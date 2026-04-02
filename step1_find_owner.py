"""
Steps 1-3: Find sword_upper package, find all objects referencing it,
dump their fields as candidates for the runtime owner.
"""
import pymem, struct, ctypes, time
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
ACPKG_VT = 0x144A6C610

def read_bytes(addr, size):
    buf = (ctypes.c_char * size)()
    if k32.ReadProcessMemory(handle, addr, buf, size, ctypes.byref(br)):
        return bytes(buf[:br.value])
    return None

def scan_heap(needle, limit=0x800000000000):
    hits = []
    addr = 0
    while addr < limit:
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

# ── Step 1: Find sword_upper package ──
print("Step 1: Finding ActionChartPackage instances...")
vt_needle = struct.pack('<Q', ACPKG_VT)
all_pkgs = scan_heap(vt_needle)
print(f"  {len(all_pkgs)} packages found")

sword_pkg = None
for obj in all_pkgs:
    data = read_bytes(obj, 256)
    if not data: continue
    ptr_18 = struct.unpack_from('<Q', data, 0x18)[0]
    if 0x100000000 <= ptr_18 <= 0x7FFFFFFFFFFF:
        target = read_bytes(ptr_18, 128)
        if target and b'sword_upper' in target and b'1_pc/1_phm' in target:
            sword_pkg = obj
            break

if not sword_pkg:
    print("  ERROR: sword_upper not found")
    pm.close_process()
    exit()

print(f"  sword_upper at 0x{sword_pkg:X}")

# ── Step 2: Find all pointers TO sword_pkg ──
print(f"\nStep 2: Scanning heap for pointers to 0x{sword_pkg:X}...")
ptr_needle = struct.pack('<Q', sword_pkg)
refs = scan_heap(ptr_needle)
print(f"  {len(refs)} references found")

# ── Step 3: Dump each referencing object ──
print(f"\nStep 3: Dumping referencing objects...")
# For each ref, back up to find the start of the containing object
# (look for a vtable-like pointer in the 8 bytes before the ref, or at aligned offsets)
candidates = []
for ref_addr in refs:
    # Try to find the object start by scanning backwards for a vtable pointer
    # (first 8 bytes of object should be 0x14xxxxxxx)
    for back in range(0, 512, 8):
        obj_start = ref_addr - back
        d = read_bytes(obj_start, 8)
        if not d: continue
        qval = struct.unpack_from('<Q', d, 0)[0]
        if 0x144000000 <= qval <= 0x145FFFFFF:  # vtable range
            # Found potential object start
            ref_offset = ref_addr - obj_start
            obj_data = read_bytes(obj_start, 512)
            if obj_data:
                candidates.append((obj_start, ref_offset, obj_data, qval))
            break

# Deduplicate by object start address
seen = set()
unique = []
for obj_start, ref_off, obj_data, vt in candidates:
    if obj_start not in seen:
        seen.add(obj_start)
        unique.append((obj_start, ref_off, obj_data, vt))

print(f"  {len(unique)} unique referencing objects")

# Save to file for analysis
out = open(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\owner_candidates.txt", "w")

for obj_start, ref_off, obj_data, vt in unique:
    header = f"\nObject at 0x{obj_start:X} (vtable=0x{vt:X}, ref to sword_pkg at +0x{ref_off:X})"
    print(header)
    out.write(header + "\n")

    # Dump fields — highlight small integers (potential state IDs)
    for off in range(0, min(256, len(obj_data)), 4):
        u32 = struct.unpack_from('<I', obj_data, off)[0]
        f32 = struct.unpack_from('<f', obj_data, off)[0]
        note = ""
        if off < 8: note = "VTABLE"
        elif 0 < u32 <= 720: note = f"*** STATE_CANDIDATE u32={u32}"
        elif -2.0 <= f32 <= 2.0 and f32 != 0: note = f"f32={f32:.4f}"
        elif u32 == 0: note = "zero"

        line = f"  +0x{off:03X}: {obj_data[off:off+4].hex()} u32={u32:<12d} {note}"
        if "STATE_CANDIDATE" in note:
            print(line)
        out.write(line + "\n")

out.close()
pm.close_process()
print(f"\nDone. Full dump in owner_candidates.txt")
