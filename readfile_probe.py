"""
Proof gate 1-2: Hook ReadFile via pymem to detect sword_upper.paac reads.
Since pymem can't hook APIs directly, we instead:
1. Find all loaded .paac file paths in the game's PAZ read cache
2. Check if sword_upper.paac content is readable (plaintext vs encrypted)
3. If found, locate the transition data for patching

This runs while you start a fight.
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

def read_bytes(addr, size):
    buf = (ctypes.c_char * size)()
    if k32.ReadProcessMemory(handle, addr, buf, size, ctypes.byref(br)):
        return bytes(buf[:br.value])
    return None

# The .paac header from our file analysis:
# - uint16 node_count at +0x00 (sword_upper = 721 = 0x02D1)
# - float speed at +0x08 (sword_upper = 1.3333)
# - The label string table starts with "upperaction/1_pc/1_phm/common_upper_branchset"
#   followed by "key_guard"

# Strategy: search for the .paac header signature in all readable memory.
# The header bytes: D1 02 (node count 721 as uint16 LE)
# followed within 8 bytes by the speed float 1.3333 = 0x3FAAAAAB

print("Searching for sword_upper.paac raw data in memory...")
print("(This searches for the .paac header: node_count=721, speed=1.333)")
print("START FIGHTING NOW — keep fighting for 30 seconds\n")

for _ in range(3):
    winsound.Beep(1200, 150)
    time.sleep(0.15)

# Poll for up to 60 seconds
HEADER_SIG = struct.pack('<H', 721)  # 0xD1 0x02
SPEED_BYTES = struct.pack('<f', 1.3333333730697632)  # exact float from .paac

found_paac = None
start = time.time()

while time.time() - start < 60:
    addr = 0
    while addr < 0x800000000000:
        mbi = MBI()
        if k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0: break
        if mbi.State == 0x1000 and mbi.RegionSize <= 100_000_000 and (mbi.Protect & 0x06):
            buf = (ctypes.c_char * mbi.RegionSize)()
            if k32.ReadProcessMemory(handle, mbi.BaseAddress, buf, mbi.RegionSize, ctypes.byref(br)):
                data = bytes(buf[:br.value])
                # Search for node_count 721 at 2-byte boundaries
                pos = 0
                while True:
                    pos = data.find(HEADER_SIG, pos)
                    if pos == -1: break
                    # Verify speed float at +0x08
                    if pos + 12 <= len(data):
                        speed_at = data[pos+8:pos+12]
                        if speed_at == SPEED_BYTES:
                            va = mbi.BaseAddress + pos
                            found_paac = va
                            print(f"FOUND .paac header at 0x{va:X}")
                            break
                    pos += 2
                if found_paac: break
        addr = mbi.BaseAddress + mbi.RegionSize
        if addr == 0: break

    if found_paac: break
    elapsed = time.time() - start
    if int(elapsed) % 5 == 0:
        print(f"  Scanning... ({elapsed:.0f}s)")
    time.sleep(0.5)

if not found_paac:
    print("\n.paac header NOT found after 60 seconds")
    # Try alternative: search for the branchset string which is near the header
    print("Trying alternative: searching for branchset string...")
    needle = b'common_upper_branchset\x00'
    addr = 0
    while addr < 0x800000000000:
        mbi = MBI()
        if k32.VirtualQueryEx(handle, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0: break
        if mbi.State == 0x1000 and mbi.RegionSize <= 100_000_000 and (mbi.Protect & 0x06):
            buf = (ctypes.c_char * mbi.RegionSize)()
            if k32.ReadProcessMemory(handle, mbi.BaseAddress, buf, mbi.RegionSize, ctypes.byref(br)):
                data = bytes(buf[:br.value])
                pos = data.find(needle)
                if pos >= 0:
                    va = mbi.BaseAddress + pos
                    # Check if key_guard is within 200 bytes
                    nearby = data[pos:pos+200]
                    if b'key_guard' in nearby:
                        # This is the string table. The .paac header is ~0x8E9F3 bytes before
                        # (from our file analysis). But in memory it might be different.
                        # Let's just mark this and look backwards for the header
                        print(f"  String table at 0x{va:X}")
                        # Read backwards in chunks to find the 721 node count
                        for back in [0x8F000, 0x90000, 0x100000, 0x130000]:
                            header_addr = va - back
                            hdr = read_bytes(header_addr, 16)
                            if hdr:
                                nc = struct.unpack_from('<H', hdr, 0)[0]
                                spd = struct.unpack_from('<f', hdr, 8)[0]
                                if nc == 721 and abs(spd - 1.3333) < 0.001:
                                    found_paac = header_addr
                                    print(f"  FOUND .paac at 0x{header_addr:X} (back={back})")
                                    break
                    if found_paac: break
        addr = mbi.BaseAddress + mbi.RegionSize
        if addr == 0: break

if found_paac:
    winsound.Beep(800, 500)
    print(f"\n=== GATE 1 PASSED: .paac data found at 0x{found_paac:X} ===")

    # Gate 2: Verify it's readable plaintext
    header = read_bytes(found_paac, 64)
    nc = struct.unpack_from('<H', header, 0)[0]
    spd = struct.unpack_from('<f', header, 8)[0]
    print(f"  node_count = {nc}")
    print(f"  speed = {spd:.4f}")

    # Read the string table area (at ~+0x8E9F3 from header based on file analysis)
    for offset in [0x8E9F0, 0x8EA00, 0x8EA20]:
        strtab = read_bytes(found_paac + offset, 128)
        if strtab and b'key_guard' in strtab:
            print(f"  String table confirmed at +0x{offset:X}")
            print(f"  === GATE 2 PASSED: plaintext, not encrypted ===")

            # Now find transitions: at ~+0x44 from header, states begin
            # Read first few state records and look for transition patterns
            state_area = read_bytes(found_paac + 0x44, 4096)
            if state_area:
                # Count -1.0 sentinels (transition markers)
                sentinel_count = state_area.count(b'\x00\x00\x80\xBF')
                # Count 50.0 markers (state boundaries)
                marker_count = state_area.count(b'\x00\x00\x48\x42')
                print(f"\n  State area (+0x44): sentinels={sentinel_count} markers={marker_count}")

                # Find first transition: [float thresh] [-1.0] [u32 target] [u32 seq]
                for i in range(0, len(state_area) - 16, 4):
                    if state_area[i+4:i+8] == b'\x00\x00\x80\xBF':
                        thresh = struct.unpack_from('<f', state_area, i)[0]
                        target = struct.unpack_from('<I', state_area, i+8)[0]
                        seq = struct.unpack_from('<I', state_area, i+12)[0]
                        if 0.0 <= thresh <= 1.0 and target <= 720 and seq <= 100:
                            trans_addr = found_paac + 0x44 + i
                            print(f"\n  First valid transition at 0x{trans_addr:X} (+0x{0x44+i:X}):")
                            print(f"    thresh={thresh:.4f} target={target} seq={seq}")
                            print(f"    Target address (for patching): 0x{trans_addr + 8:X}")
                            break
            break
    else:
        print("  String table not at expected offset — format may differ")
else:
    print("\n.paac data NOT found. Chart may not be loaded yet.")

pm.close_process()
print("\nDone")
