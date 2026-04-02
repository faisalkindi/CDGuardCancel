"""
Run this script while the game is open and you're standing idle.
1 beep  = START ATTACKING (spam combos for 3 seconds)
2 beeps = STOP — scanning in progress
1 low beep = DONE — check results
"""
import pymem, struct, ctypes, time, winsound
from ctypes import wintypes

print("Switch to the game window NOW. You have 3 seconds...")
time.sleep(3)

# BEEP = start attacking
winsound.Beep(1000, 500)
print(">>> BEEP! START ATTACKING NOW <<<")
time.sleep(3)

# DOUBLE BEEP = stop
winsound.Beep(1500, 200)
time.sleep(0.1)
winsound.Beep(1500, 200)
print(">>> STOP! Scanning... <<<")

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle

k32 = ctypes.windll.kernel32
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_bool

idle_file = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\idle_zeros.bin"
with open(idle_file, "rb") as f:
    raw = f.read()
idle_zeros = [struct.unpack_from("<Q", raw, i)[0] for i in range(0, len(raw), 8)]
print(f"Checking {len(idle_zeros)} addresses...")

changed = []
br = ctypes.c_size_t(0)
buf4 = (ctypes.c_char * 4)()
for addr in idle_zeros:
    ok = k32.ReadProcessMemory(handle, addr, buf4, 4, ctypes.byref(br))
    if not ok:
        continue
    val = struct.unpack_from("<I", bytes(buf4), 0)[0]
    if val != 0 and val <= 720:
        changed.append((addr, val))

print(f"Found {len(changed)} addresses changed to state range (1-720)")

from collections import Counter
val_counts = Counter(v for _, v in changed)
print(f"\nTop values:")
for val, count in val_counts.most_common(20):
    print(f"  value {val:4d}: {count:6d} addresses")

out = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\attack_candidates.txt"
with open(out, "w") as f:
    for addr, val in sorted(changed, key=lambda x: x[1]):
        f.write(f"0x{addr:016X} = {val}\n")

pm.close_process()
winsound.Beep(500, 500)
print("\nDONE! Results saved to attack_candidates.txt")
input("Press Enter to close...")
