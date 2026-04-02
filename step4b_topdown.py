"""
Step 4b: Top-down — find player's ActionChartPackageGroup/Set,
which should contain or point to the runtime state evaluator.
Monitor fields across combat phases.
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

# Known vtables from live RTTI scan
VTABLES = {
    "CharCtrl": 0x14477C6B8,
    "Skill": 0x144789B60,
    "Attack": 0x144748100,
    "PkgGroup": 0x144B37470,
    "PkgSet": 0x144B37480,
    "Input": 0x14478E108,
}

def read_bytes(addr, size):
    buf = (ctypes.c_char * size)()
    if k32.ReadProcessMemory(handle, addr, buf, size, ctypes.byref(br)):
        return bytes(buf[:br.value])
    return None

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

# Find all instances of low-count classes
print("Finding instances...")
all_objects = {}  # {name: [addr, ...]}
for name, vt in VTABLES.items():
    instances = scan_heap(struct.pack('<Q', vt))
    all_objects[name] = instances
    print(f"  {name}: {len(instances)} instances")

# Collect ALL fields to monitor: every u32 offset in every instance (first 1024 bytes)
print("\nBuilding field list...")
fields = []  # (obj_addr, offset, class_name, instance_idx)
for name, instances in all_objects.items():
    for idx, obj in enumerate(instances):
        data = read_bytes(obj, 1024)
        if not data: continue
        for off in range(8, min(1024, len(data)) - 3, 4):
            u32 = struct.unpack_from('<I', data, off)[0]
            if 0 <= u32 <= 720:
                fields.append((obj, off, name, idx))

print(f"  {len(fields)} fields to monitor")

def read_field(addr, off):
    d = read_bytes(addr + off, 4)
    if d: return struct.unpack_from('<I', d, 0)[0]
    return -1

def sample(duration):
    prev = None
    start = time.time()
    snapshots = []
    while time.time() - start < duration:
        vals = tuple(read_field(a, o) for a, o, _, _ in fields)
        if vals != prev:
            snapshots.append((time.time() - start, vals))
            prev = vals
        time.sleep(0.03)
    return snapshots

# Guided sampling
print("\nSwitch to game. 3 seconds...")
time.sleep(3)

def announce(msg, freq, wait=2):
    print(f"\n  >>> {msg} <<<")
    for _ in range(3): winsound.Beep(freq, 150); time.sleep(0.15)
    time.sleep(wait)

announce("STAND IDLE", 600)
s_idle = sample(4)

announce("ATTACK (light combo)", 1200)
s_atk = sample(5)

announce("STAND IDLE", 600)
s_idle2 = sample(4)

announce("HOLD GUARD (LB)", 900)
s_guard = sample(4)

winsound.Beep(500, 500)
print("\n>>> DONE <<<")

# Analyze
def unique_vals(snaps, idx):
    return sorted(set(s[1][idx] for s in snaps if s[1][idx] >= 0))

print("\n=== COMBAT-CORRELATED FIELDS ===")
log = open(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\topdown_fields.txt", "w")

interesting = []
for i, (addr, off, cls, idx) in enumerate(fields):
    iv = unique_vals(s_idle, i)
    av = unique_vals(s_atk, i)
    iv2 = unique_vals(s_idle2, i)
    gv = unique_vals(s_guard, i)

    if iv == av: continue  # no change = boring
    if max(max(av, default=0), max(iv, default=0)) > 720: continue

    score = 0
    if iv == iv2: score += 10
    if iv == gv: score += 5
    if len(av) > 1: score += 3
    if max(av, default=0) > 10: score += 5
    if len(iv) == 1 and len(gv) == 1: score += 3  # stable idle/guard

    line = f"  {cls}[{idx}]+0x{off:03X}: idle={iv} atk={av} idle2={iv2} guard={gv} score={score}"
    interesting.append((score, line))
    log.write(line + "\n")

interesting.sort(key=lambda x: -x[0])
for score, line in interesting[:40]:
    print(line)

log.close()
pm.close_process()
print(f"\n{len(interesting)} combat-correlated fields found. Details in topdown_fields.txt")
