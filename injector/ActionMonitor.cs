using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.IO;

/// <summary>
/// Monitors the combat action system in real-time.
/// Watches the action_id fields and combat gate calls to see
/// what happens when you use Evasive Slash vs Guard during attacks.
///
/// Fields monitored (from RE):
///   [player+0x9C0] = current action_id (u16)
///   [player+0x9C2] = last executed action_id (u16)
///   [player+0x9CA] = action_active flag (u8)
///   [player+0x9C8] = override flag (u8)
///   [player+0x958] = another state byte
/// </summary>
internal static class Program
{
    private const uint ProcessAccess = 0x0438; // QUERY|VM_READ|VM_WRITE|VM_OP
    private const int ExitKey = 0x77; // F8

    private static int Main()
    {
        Console.WriteLine("Crimson Desert Action Monitor");
        Console.WriteLine("Watches combat action fields in real-time.");
        Console.WriteLine("Press F8 to stop.");
        Console.WriteLine();
        Console.WriteLine("Instructions:");
        Console.WriteLine("  1. Stand idle — note the baseline values");
        Console.WriteLine("  2. Press guard (LB) while idle — note what changes");
        Console.WriteLine("  3. Start attacking — note the values");
        Console.WriteLine("  4. Press guard (LB) during attack — note what changes (or doesn't)");
        Console.WriteLine("  5. Use Evasive Slash during attack — note what changes");
        Console.WriteLine();

        Process process = WaitForProcess();
        if (process == null) return 1;

        IntPtr handle = OpenProcess(ProcessAccess, false, (uint)process.Id);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process. Run as admin.");
            return 1;
        }

        long moduleBase = process.MainModule.BaseAddress.ToInt64();

        // Find the player object pointer.
        // From RE: the combat gate at 0x140AD4F00 receives rcx = player object.
        // Caller at 0x140AD7693 loads it from: [rip+global] -> [+0x90] -> [+0x1168]
        // But we can also find it by watching [rbx+0x9C0] from the callers.
        //
        // Simpler approach: scan for the action_id field pattern.
        // The player object has 0xFFFF at offset 0x9C0 when no action is active.
        // We need to find the player object address first.
        //
        // Alternative: just monitor the combat gate function itself.
        // Place a counter at the function entry to see if it's called.

        // Actually simplest: monitor a KNOWN address.
        // The combat gate function starts at moduleBase + 0xAD4F00.
        // We can write a tiny counter there that increments a shared value.
        //
        // Even simpler: just poll the function's first byte to see if
        // Themida reverts our patch, and also monitor if it gets called
        // by temporarily writing "inc [counter]; jmp original"

        // SIMPLEST: just monitor memory values that change during combat.
        // Use the fresh dump's known offsets for the input system.

        // From the guard suppression analysis:
        // The InputBlockFromCode flag is at a global address we found:
        //   module + 0x5C49318 (in DATA section)
        // Let's monitor that plus the combat gate function entry.

        long flagAddr = moduleBase + 0x5C49318; // InputBlockFromCode flag
        long gateAddr = moduleBase + 0xAD4F00;  // combat gate function start

        // Also monitor the caller's global flag at [rip+0x5171C98]
        // From caller at 0x140AD7679: cmp byte [rip+0x5171C98], 0
        // rip after this instruction = 0x140AD7680
        // target = 0x140AD7680 + 0x5171C98 = 0x145C49318
        // Wait, that's the SAME address as the InputBlockFromCode flag!
        long callerFlagAddr = moduleBase + 0x5C49318;

        // Let me also find the pending action array.
        // From caller 2: movzx edx, word [r15]
        // r15 comes from earlier in that function — it's a local pointer.
        // Can't easily find it without hooking.

        // Better approach: write a tiny code cave at the combat gate entry
        // that logs the action_id (edx) to a known memory location before proceeding.

        // Allocate shared memory for logging
        IntPtr logMem = VirtualAllocEx(handle, IntPtr.Zero, new UIntPtr(4096),
            0x3000, 0x40); // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE

        if (logMem == IntPtr.Zero)
        {
            Console.WriteLine("Failed to allocate log memory");
            CloseHandle(handle);
            return 1;
        }

        long logBase = logMem.ToInt64();
        Console.WriteLine("Log memory at: 0x{0:X}", logBase);

        // Layout of log memory:
        // +0x000: call counter (u32)
        // +0x004: last action_id (u16)
        // +0x006: padding
        // +0x008: InputBlockFromCode flag value (u8)
        // +0x010: original function bytes (8 bytes, for restore)

        // Save original function bytes
        byte[] origBytes = ReadBytes(handle, gateAddr, 16);
        if (origBytes == null)
        {
            Console.WriteLine("Failed to read function bytes");
            CloseHandle(handle);
            return 1;
        }
        WriteBytes(handle, logBase + 0x10, origBytes);

        // Initialize counters to 0
        WriteBytes(handle, logBase, new byte[16]);

        // Build code cave:
        //   lock inc dword [logBase]        ; increment call counter
        //   mov [logBase+4], dx             ; save action_id
        //   <original bytes>                ; execute original prologue
        //   jmp gateAddr+N                  ; jump back

        // Original first 8 bytes: 48 89 5C 24 08 48 89 74
        // That's: mov [rsp+8], rbx; mov [rsp+...
        // We need to overwrite exactly 5 bytes (for a JMP rel32) or more.
        // 5 bytes = the first instruction "mov [rsp+8], rbx" which is 5 bytes.
        // Wait: 48 89 5C 24 08 = 5 bytes. Perfect.

        int overwriteLen = 5; // mov [rsp+8], rbx = 5 bytes

        // Build cave at logBase + 0x100
        long caveAddr = logBase + 0x100;

        byte[] cave = new byte[64];
        int ci = 0;

        // lock inc dword [logBase]: F0 FF 05 disp32
        cave[ci++] = 0xF0; // LOCK prefix
        cave[ci++] = 0xFF; // INC
        cave[ci++] = 0x05; // [rip+disp32]
        int disp1 = (int)(logBase - (caveAddr + ci + 4));
        cave[ci++] = (byte)(disp1);
        cave[ci++] = (byte)(disp1 >> 8);
        cave[ci++] = (byte)(disp1 >> 16);
        cave[ci++] = (byte)(disp1 >> 24);

        // mov [logBase+4], dx: 66 89 15 disp32
        cave[ci++] = 0x66; // operand size prefix
        cave[ci++] = 0x89; // MOV
        cave[ci++] = 0x15; // [rip+disp32]
        int disp2 = (int)((logBase + 4) - (caveAddr + ci + 4));
        cave[ci++] = (byte)(disp2);
        cave[ci++] = (byte)(disp2 >> 8);
        cave[ci++] = (byte)(disp2 >> 16);
        cave[ci++] = (byte)(disp2 >> 24);

        // Original instruction: 48 89 5C 24 08
        cave[ci++] = 0x48;
        cave[ci++] = 0x89;
        cave[ci++] = 0x5C;
        cave[ci++] = 0x24;
        cave[ci++] = 0x08;

        // JMP back to gateAddr + overwriteLen
        cave[ci++] = 0xE9;
        int backDisp = (int)((gateAddr + overwriteLen) - (caveAddr + ci + 4));
        cave[ci++] = (byte)(backDisp);
        cave[ci++] = (byte)(backDisp >> 8);
        cave[ci++] = (byte)(backDisp >> 16);
        cave[ci++] = (byte)(backDisp >> 24);

        // Write cave
        WriteBytes(handle, caveAddr, cave);

        // Patch function entry: JMP to cave
        byte[] jmpPatch = new byte[overwriteLen];
        jmpPatch[0] = 0xE9;
        int jmpDisp = (int)(caveAddr - (gateAddr + 5));
        jmpPatch[1] = (byte)(jmpDisp);
        jmpPatch[2] = (byte)(jmpDisp >> 8);
        jmpPatch[3] = (byte)(jmpDisp >> 16);
        jmpPatch[4] = (byte)(jmpDisp >> 24);

        WriteBytes(handle, gateAddr, jmpPatch);
        FlushInstructionCache(handle, new IntPtr(gateAddr), new IntPtr(overwriteLen));

        Console.WriteLine("Monitoring active. Watch the numbers:");
        Console.WriteLine("  Calls = how many times the combat gate is called");
        Console.WriteLine("  ActionID = the last action_id passed to the gate");
        Console.WriteLine("  Flag = InputBlockFromCode flag value");
        Console.WriteLine();
        Console.WriteLine("Do these actions and note the numbers:");
        Console.WriteLine("  1. Guard while IDLE (should see calls increase, note the action_id)");
        Console.WriteLine("  2. Attack then guard (does calls increase? if not, gate is never called)");
        Console.WriteLine("  3. Attack then Evasive Slash (does calls increase?)");
        Console.WriteLine();

        uint lastCalls = 0;
        ushort lastAction = 0;

        while (true)
        {
            if ((GetAsyncKeyState(ExitKey) & 1) != 0) break;
            if (process.HasExited) break;

            byte[] logData = ReadBytes(handle, logBase, 16);
            if (logData != null)
            {
                uint calls = BitConverter.ToUInt32(logData, 0);
                ushort actionId = BitConverter.ToUInt16(logData, 4);

                byte[] flagData = ReadBytes(handle, flagAddr, 1);
                byte flag = flagData != null ? flagData[0] : (byte)0xFF;

                if (calls != lastCalls || actionId != lastAction)
                {
                    Console.WriteLine("  Calls={0}  ActionID={1} (0x{1:X4})  Flag={2}",
                        calls, actionId, flag);
                    lastCalls = calls;
                    lastAction = actionId;
                }
            }

            // Re-apply patch if Themida reverts it
            byte[] check = ReadBytes(handle, gateAddr, 1);
            if (check != null && check[0] != 0xE9)
            {
                WriteBytes(handle, gateAddr, jmpPatch);
                FlushInstructionCache(handle, new IntPtr(gateAddr), new IntPtr(overwriteLen));
                Console.WriteLine("  (re-applied — Themida reverted)");
            }

            Thread.Sleep(50);
        }

        // Restore
        WriteBytes(handle, gateAddr, origBytes);
        FlushInstructionCache(handle, new IntPtr(gateAddr), new IntPtr(overwriteLen));
        VirtualFreeEx(handle, logMem, UIntPtr.Zero, 0x8000); // MEM_RELEASE
        CloseHandle(handle);
        Console.WriteLine("Restored and cleaned up.");
        return 0;
    }

    private static Process WaitForProcess()
    {
        Console.Write("Waiting for CrimsonDesert.exe...");
        while (true)
        {
            Process[] procs = Process.GetProcessesByName("CrimsonDesert");
            for (int i = 0; i < procs.Length; i++)
            {
                try
                {
                    string name = System.IO.Path.GetFileNameWithoutExtension(procs[i].MainModule.FileName);
                    if (name == "CrimsonDesert")
                    {
                        Console.WriteLine(" found (PID {0})", procs[i].Id);
                        return procs[i];
                    }
                }
                catch { }
            }
            Thread.Sleep(500);
        }
    }

    private static byte[] ReadBytes(IntPtr handle, long address, int count)
    {
        byte[] buf = new byte[count];
        IntPtr read;
        if (ReadProcessMemory(handle, new IntPtr(address), buf, new IntPtr(count), out read))
            return buf;
        return null;
    }

    private static bool WriteBytes(IntPtr handle, long address, byte[] data)
    {
        IntPtr written;
        return WriteProcessMemory(handle, new IntPtr(address), data, new IntPtr(data.Length), out written);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr written);
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr addr, UIntPtr size, uint type, uint protect);
    [DllImport("kernel32.dll")]
    private static extern bool VirtualFreeEx(IntPtr h, IntPtr addr, UIntPtr size, uint type);
    [DllImport("kernel32.dll")]
    private static extern bool FlushInstructionCache(IntPtr h, IntPtr addr, IntPtr size);
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);
}
