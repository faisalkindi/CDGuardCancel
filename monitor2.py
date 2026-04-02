"""
Guided monitor: tells you exactly what to do with beeps.
Monitors 8 candidate addresses through specific actions.
"""
import pymem, struct, ctypes, time, winsound

k32 = ctypes.windll.kernel32
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_bool

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle

candidates = [
    0x000000010C5FA67C, 0x000000010C503654, 0x000000010C5F7CFC, 0x000000010183CD78,
    0x000000010183BB94, 0x000000010183CA64, 0x000000010183C0C8, 0x000000010C582AF8,
]
labels = ["combo28", "att406", "att622", "guard18", "id868", "id740", "small4", "att10"]

br = ctypes.c_size_t(0)
buf4 = (ctypes.c_char * 4)()

def read_all():
    vals = []
    for addr in candidates:
        ok = k32.ReadProcessMemory(handle, addr, buf4, 4, ctypes.byref(br))
        vals.append(struct.unpack_from('<I', bytes(buf4), 0)[0] if ok else -1)
    return vals

def monitor(duration, label):
    """Monitor for duration seconds, printing changes."""
    prev = [None] * len(candidates)
    start = time.time()
    while time.time() - start < duration:
        vals = read_all()
        changed = any(prev[i] is not None and vals[i] != prev[i] for i in range(len(vals)))
        if changed:
            t = time.time() - start
            line = f"  {label:>10s} +{t:4.1f}s  " + "  ".join(f"{v:>8d}" for v in vals)
            print(line)
            log.write(line + "\n")
        prev = vals[:]
        time.sleep(0.03)

log = open(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\monitor2_log.txt", "w")
hdr = f"{'':>17s}  " + "  ".join(f"{l:>8s}" for l in labels)
print(hdr)
log.write(hdr + "\n")

print("\nSwitch to game NOW.")
print("LOW beep  = stand still")
print("HIGH beep = do the action")
print("Starting in 5 seconds...")
time.sleep(5)

def announce(msg, freq, wait_before=2):
    """Beep 3 times, print message, wait before monitoring."""
    print(f"\n{'='*50}")
    print(f"  {msg}")
    print(f"{'='*50}")
    for _ in range(3):
        winsound.Beep(freq, 150)
        time.sleep(0.15)
    time.sleep(wait_before)

# Step 1
announce("STAND STILL — do nothing", 600)
monitor(4, "IDLE")

# Step 2
announce("DO ONE SINGLE ATTACK — then stop", 1200)
monitor(5, "1 ATTACK")

# Step 3
announce("STAND STILL — do nothing", 600)
monitor(4, "IDLE")

# Step 4
announce("SPAM ATTACK COMBO — keep pressing", 1200)
monitor(5, "COMBO")

# Step 5
announce("STAND STILL — do nothing", 600)
monitor(4, "IDLE")

# Step 6
announce("HOLD GUARD (LB) — keep holding", 900)
monitor(4, "GUARD")

# Step 7
announce("RELEASE GUARD — stand still", 600)
monitor(4, "IDLE")

winsound.Beep(500, 500)
print("\n>>> DONE <<<")

log.close()
pm.close_process()
print("Results saved to monitor2_log.txt")
input("Press Enter to close...")
