"""
Real-time monitor of candidate addresses.
Play the game normally — attack, guard, idle, combo.
The values update every 100ms. Watch for patterns.
Press Ctrl+C to stop.
"""
import pymem, struct, ctypes, time, os

k32 = ctypes.windll.kernel32
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_bool

pm = pymem.Pymem("CrimsonDesert.exe")
handle = pm.process_handle
print(f"Attached PID {pm.process_id}\n")

# Top candidates from 3-way scan
candidates = [
    (0x000000010183BD2C, "idle/guard=0 att=7"),
    (0x000000010183C964, "idle/guard=0 att=24"),
    (0x000000010183D73C, "idle/guard=0 att=47"),
    (0x000000010183BB98, "idle/guard=0 att=43"),
    (0x000000010183F5E0, "idle/guard=1 att=16"),
    (0x000000010183F780, "idle/guard=1 att=32"),
    (0x000000010183F58C, "idle/guard=1 att=34"),
    (0x000000010183C924, "idle/guard=0 att=4"),
]

# Header
print("Switch to game and play! Values update here.")
print("Look for an address that changes when you attack and returns when you guard.\n")
header = "  ".join(f"{'addr':>8s}" for _, desc in candidates)
print(f"{'Time':>6s}  " + "  ".join(f"{desc[:16]:>16s}" for _, desc in candidates))
print("-" * (8 + len(candidates) * 18))

# Log to file too
log = open(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\monitor_log.txt", "w")

br = ctypes.c_size_t(0)
buf4 = (ctypes.c_char * 4)()
prev = [None] * len(candidates)
start = time.time()

try:
    while True:
        elapsed = time.time() - start
        vals = []
        changed = False
        for i, (addr, _) in enumerate(candidates):
            ok = k32.ReadProcessMemory(handle, addr, buf4, 4, ctypes.byref(br))
            if ok:
                val = struct.unpack_from('<I', bytes(buf4), 0)[0]
                vals.append(val)
                if prev[i] is not None and val != prev[i]:
                    changed = True
                prev[i] = val
            else:
                vals.append(-1)

        if changed:
            line = f"{elapsed:6.1f}  " + "  ".join(f"{v:16d}" for v in vals)
            print(line)
            log.write(line + "\n")
            log.flush()

        time.sleep(0.05)
except KeyboardInterrupt:
    pass

log.close()
pm.close_process()
print("\nStopped.")
