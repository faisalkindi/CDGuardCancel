"""
Step 4: Monitor all small-integer fields in the 5 owner objects
during idle/attack/guard to find current_state field.
Guided with beeps.
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
ACPKG_VT = 0x144A6C610

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

# ── Step 1: Find sword_upper ──
print("Finding sword_upper...")
all_pkgs = scan_heap(struct.pack('<Q', ACPKG_VT))
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
    print("ERROR: sword_upper not found"); pm.close_process(); exit()
print(f"  sword_upper at 0x{sword_pkg:X}")

# ── Step 2: Find references ──
print("Finding references...")
refs = scan_heap(struct.pack('<Q', sword_pkg))
print(f"  {len(refs)} references")

# Find object starts (look backwards for vtable pointer)
owners = []
seen = set()
for ref_addr in refs:
    for back in range(0, 512, 8):
        obj_start = ref_addr - back
        d = read_bytes(obj_start, 8)
        if not d: continue
        qval = struct.unpack_from('<Q', d, 0)[0]
        if 0x144000000 <= qval <= 0x145FFFFFF:
            if obj_start not in seen:
                seen.add(obj_start)
                owners.append((obj_start, ref_addr - obj_start))
            break

print(f"  {len(owners)} owner objects")
for addr, ref_off in owners:
    print(f"    0x{addr:X} (pkg ref at +0x{ref_off:X})")

# ── Step 4: Monitor all u32 fields (0-720 range) across actions ──
# Read 512 bytes from each owner, find all offsets with u32 in 0-720
print("\nTaking baseline snapshot (stand idle)...")
baseline = {}
for addr, _ in owners:
    data = read_bytes(addr, 512)
    if data:
        baseline[addr] = data

# Collect all field offsets with small values
field_addrs = []  # (owner_addr, offset, label)
for addr, data in baseline.items():
    for off in range(8, min(512, len(data)) - 3, 4):
        u32 = struct.unpack_from('<I', data, off)[0]
        if 0 <= u32 <= 720:
            field_addrs.append((addr, off))

print(f"  {len(field_addrs)} monitorable fields across {len(owners)} objects")

def read_fields():
    vals = []
    for addr, off in field_addrs:
        d = read_bytes(addr + off, 4)
        if d:
            vals.append(struct.unpack_from('<I', d, 0)[0])
        else:
            vals.append(-1)
    return vals

def sample(duration, label):
    """Sample fields, return list of (time, values) only when changed."""
    prev = None
    start = time.time()
    snapshots = []
    while time.time() - start < duration:
        vals = read_fields()
        if vals != prev:
            snapshots.append((time.time() - start, vals))
            prev = vals
        time.sleep(0.03)
    return snapshots

# ── Guided sampling ──
print("\nSwitch to game. Instructions in 3 seconds...")
time.sleep(3)

def announce(msg, freq, wait=2):
    print(f"\n{'='*40}")
    print(f"  {msg}")
    print(f"{'='*40}")
    for _ in range(3):
        winsound.Beep(freq, 150); time.sleep(0.15)
    time.sleep(wait)

announce("STAND IDLE", 600)
idle_snaps = sample(4, "IDLE")

announce("ATTACK NOW (light attacks)", 1200)
attack_snaps = sample(5, "ATTACK")

announce("STAND IDLE", 600)
idle2_snaps = sample(4, "IDLE2")

announce("HOLD GUARD (LB)", 900)
guard_snaps = sample(4, "GUARD")

winsound.Beep(500, 500)
print("\n>>> DONE <<<")

# ── Analysis: find fields that differ between phases ──
def avg_val(snaps, idx):
    vals = [s[1][idx] for s in snaps if s[1][idx] >= 0]
    if not vals: return -1
    return sum(vals) / len(vals)

def unique_vals(snaps, idx):
    return sorted(set(s[1][idx] for s in snaps if s[1][idx] >= 0))

print("\n=== FIELDS THAT CHANGE BETWEEN PHASES ===")
log = open(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\state_fields.txt", "w")

interesting = []
for i, (addr, off) in enumerate(field_addrs):
    idle_vals = unique_vals(idle_snaps, i)
    atk_vals = unique_vals(attack_snaps, i)
    idle2_vals = unique_vals(idle2_snaps, i)
    guard_vals = unique_vals(guard_snaps, i)

    # Interesting if: attack values differ from idle, and values are in state range
    if idle_vals != atk_vals and max(max(atk_vals, default=0), max(idle_vals, default=0)) <= 720:
        score = 0
        if idle_vals == idle2_vals: score += 10  # stable idle
        if idle_vals == guard_vals: score += 5   # guard same as idle
        if len(atk_vals) > 1: score += 3         # multiple attack states
        if max(atk_vals, default=0) > 10: score += 5  # attack value not just 0/1

        line = f"  0x{addr:X}+0x{off:03X}: idle={idle_vals} atk={atk_vals} idle2={idle2_vals} guard={guard_vals} score={score}"
        interesting.append((score, line, addr, off, idle_vals, atk_vals, guard_vals))
        log.write(line + "\n")

interesting.sort(key=lambda x: -x[0])
for score, line, *_ in interesting[:30]:
    print(line)

log.close()
pm.close_process()
print(f"\n{len(interesting)} interesting fields. Details in state_fields.txt")
