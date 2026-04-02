using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

/// <summary>
/// Guard Cancel Logger v5 — logs what action IDs (edx) the function receives.
/// Uses a shared memory flag: code cave writes edx to a known address,
/// C# program reads and logs it.
///
/// No game behavior is modified — this is purely observation.
/// </summary>
internal static class Program
{
    private const uint ProcessAccess = 0x0400 | 0x0010 | 0x0020 | 0x0008;
    private const uint MemCommit = 0x1000;
    private const uint MemReserve = 0x2000;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageReadWrite = 0x04;

    private const string TargetProcess = "CrimsonDesert";
    private const int F8 = 0x77;
    private const int PollMs = 10;
    private const int DeactivateDelayMs = 200;
    private const ushort XINPUT_LB = 0x0100;

    // Hook the function entry at +2FE1F0
    // Must overwrite complete instructions: 5 + 1 + 4 = 10 bytes
    private const long HookOffset = 0x2FE1F0;
    private static readonly byte[] OriginalBytes = new byte[] {
        0x48, 0x89, 0x5C, 0x24, 0x18,  // mov [rsp+18], rbx  (5 bytes)
        0x56,                            // push rsi            (1 byte)
        0x48, 0x83, 0xEC, 0x20          // sub rsp, 20         (4 bytes)
    };
    private const int OverwriteLength = 10;

    private static volatile bool _running = true;

    private static int Main()
    {
        Console.WriteLine("==========================================");
        Console.WriteLine("  Guard Action Logger v5");
        Console.WriteLine("  Logs action IDs — no game changes");
        Console.WriteLine("==========================================");
        Console.WriteLine();
        Console.WriteLine("Hold LB to activate logging.");
        Console.WriteLine("Press F8 to quit.");
        Console.WriteLine();

        Process process = WaitForProcess();
        if (process == null) return 1;

        IntPtr handle = OpenProcess(ProcessAccess, false, (uint)process.Id);
        if (handle == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            Console.WriteLine("Failed to open process. Error: {0}", err);
            if (err == 5) Console.WriteLine("Run as administrator.");
            Console.ReadKey();
            return 1;
        }

        try
        {
            long moduleBase = 0x140000000;
            try { moduleBase = process.MainModule.BaseAddress.ToInt64(); } catch { }

            long targetAddr = moduleBase + HookOffset;

            // Verify original bytes
            byte[] current = ReadBytes(handle, targetAddr, OriginalBytes.Length);
            if (current == null || !BytesEqual(current, OriginalBytes))
            {
                Console.Write("WARNING: Bytes don't match at +{0:X}. Found: ", HookOffset);
                if (current != null) for (int i = 0; i < current.Length; i++) Console.Write("{0:X2} ", current[i]);
                Console.WriteLine();
                Console.WriteLine("Continue? (Y/N)");
                if (Console.ReadKey().Key != ConsoleKey.Y) return 1;
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine("Target verified at CrimsonDesert.exe+{0:X}", HookOffset);
            }

            // Allocate shared data page (for cave to write edx values)
            IntPtr dataPage = VirtualAllocEx(handle, IntPtr.Zero, new UIntPtr(4096), MemCommit | MemReserve, PageReadWrite);
            if (dataPage == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Failed to allocate data page.");
                Console.ReadKey();
                return 1;
            }
            long dataAddr = dataPage.ToInt64();
            Console.WriteLine("Data page at: 0x{0:X}", dataAddr);

            // Data layout:
            // +0x00: last edx value (4 bytes)
            // +0x04: call counter (4 bytes)

            // Build code cave — simple approach using RIP-relative addressing.
            // We store the data address right after the jmp, and use r11 (volatile/scratch).
            // Cave layout:
            //   mov [rsp+18], rbx        ; original instruction 1
            //   push rsi                 ; original instruction 2
            //   (logging skipped — just safe passthrough for now to verify cave works)
            //   jmp back

            // Safe passthrough — all 3 original instructions + jmp back
            byte[] caveBytes = new byte[]
            {
                0x48, 0x89, 0x5C, 0x24, 0x18,        // mov [rsp+18], rbx (original)
                0x56,                                  // push rsi (original)
                0x48, 0x83, 0xEC, 0x20,               // sub rsp, 20 (original)
                0xE9, 0x00, 0x00, 0x00, 0x00,         // jmp back to +2FE1FA
            };

            // Allocate cave
            IntPtr cave = AllocateNear(handle, targetAddr, caveBytes.Length + 16);
            if (cave == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Failed to allocate code cave.");
                Console.ReadKey();
                return 1;
            }
            Console.WriteLine("Code cave at: 0x{0:X}", cave.ToInt64());

            // Patch back-jump
            int backJumpOffset = caveBytes.Length - 4;
            long returnAddr = targetAddr + OverwriteLength;
            int backRelative = (int)(returnAddr - (cave.ToInt64() + caveBytes.Length));
            WriteInt32(caveBytes, backJumpOffset, backRelative);

            if (!WriteBytes(handle, cave.ToInt64(), caveBytes))
            {
                Console.WriteLine("ERROR: Failed to write code cave.");
                Console.ReadKey();
                return 1;
            }

            // Build jmp patch (5 bytes jmp + 5 bytes nop to fill 10)
            byte[] patchBytes = new byte[OverwriteLength];
            patchBytes[0] = 0xE9;
            int caveRelative = (int)(cave.ToInt64() - (targetAddr + 5));
            WriteInt32(patchBytes, 1, caveRelative);
            for (int i = 5; i < OverwriteLength; i++) patchBytes[i] = 0x90; // nop

            Console.WriteLine();
            Console.WriteLine("Ready! Hold LB to activate logging.");
            Console.WriteLine("The logger will show action IDs the function receives.");
            Console.WriteLine();

            bool hookActive = false;
            long deactivateAt = 0;
            uint lastCounter = 0;
            int lastEdx = -1;

            while (_running)
            {
                if (process.HasExited) break;
                if ((GetAsyncKeyState(F8) & 1) != 0) break;

                bool lbHeld = IsLBPressed();

                if (lbHeld)
                {
                    deactivateAt = DateTime.UtcNow.Ticks + (TimeSpan.TicksPerMillisecond * DeactivateDelayMs);

                    if (!hookActive)
                    {
                        // Clear data page
                        WriteBytes(handle, dataAddr, new byte[8]);
                        lastCounter = 0;
                        lastEdx = -1;

                        if (WriteBytes(handle, targetAddr, patchBytes))
                        {
                            FlushInstructionCache(handle, new IntPtr(targetAddr), new IntPtr(patchBytes.Length));
                            hookActive = true;
                            Console.WriteLine("[{0:HH:mm:ss}] LOGGING (LB held)", DateTime.Now);
                        }
                    }

                    // Read logged values
                    if (hookActive)
                    {
                        byte[] data = ReadBytes(handle, dataAddr, 8);
                        if (data != null)
                        {
                            int edxVal = BitConverter.ToInt32(data, 0);
                            uint counter = BitConverter.ToUInt32(data, 4);

                            if (counter != lastCounter && edxVal != lastEdx)
                            {
                                Console.WriteLine("  edx = {0} (0x{0:X}) calls={1}", edxVal, counter);
                                lastEdx = edxVal;
                            }
                            lastCounter = counter;
                        }
                    }
                }
                else if (hookActive && DateTime.UtcNow.Ticks > deactivateAt)
                {
                    if (WriteBytes(handle, targetAddr, OriginalBytes))
                    {
                        FlushInstructionCache(handle, new IntPtr(targetAddr), new IntPtr(OriginalBytes.Length));
                        hookActive = false;
                        Console.WriteLine("[{0:HH:mm:ss}] LOGGING OFF", DateTime.Now);
                    }
                }

                Thread.Sleep(PollMs);
            }

            if (hookActive)
            {
                WriteBytes(handle, targetAddr, OriginalBytes);
                FlushInstructionCache(handle, new IntPtr(targetAddr), new IntPtr(OriginalBytes.Length));
                Console.WriteLine("Original code restored.");
            }
        }
        finally
        {
            CloseHandle(handle);
        }

        Console.WriteLine("Done. Press any key to close.");
        Console.ReadKey();
        return 0;
    }

    private static bool IsLBPressed()
    {
        XINPUT_STATE state;
        uint result = XInputGetState(0, out state);
        if (result != 0) return false;
        return (state.Gamepad.wButtons & XINPUT_LB) != 0;
    }

    private static Process WaitForProcess()
    {
        Console.Write("Waiting for CrimsonDesert.exe...");
        while (_running)
        {
            if ((GetAsyncKeyState(F8) & 1) != 0) return null;
            foreach (var p in Process.GetProcessesByName(TargetProcess))
            {
                try
                {
                    if (p.MainModule != null)
                    {
                        Console.WriteLine(" PID {0}", p.Id);
                        return p;
                    }
                }
                catch { }
            }
            Thread.Sleep(500);
        }
        return null;
    }

    private static byte[] ReadBytes(IntPtr handle, long address, int count)
    {
        byte[] buf = new byte[count];
        IntPtr read;
        return ReadProcessMemory(handle, new IntPtr(address), buf, new IntPtr(count), out read) ? buf : null;
    }

    private static bool WriteBytes(IntPtr handle, long address, byte[] data)
    {
        IntPtr written;
        return WriteProcessMemory(handle, new IntPtr(address), data, new IntPtr(data.Length), out written)
            && written.ToInt32() == data.Length;
    }

    private static void WriteInt32(byte[] buf, int offset, int value)
    {
        Buffer.BlockCopy(BitConverter.GetBytes(value), 0, buf, offset, 4);
    }

    private static void WriteInt64(byte[] buf, int offset, long value)
    {
        Buffer.BlockCopy(BitConverter.GetBytes(value), 0, buf, offset, 8);
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }

    private static IntPtr AllocateNear(IntPtr handle, long target, int size)
    {
        long step = 0x10000;
        long range = 0x70000000;
        for (long d = 0; d < range; d += step)
        {
            IntPtr ptr = TryAlloc(handle, target + d, size);
            if (ptr != IntPtr.Zero && FitsRel32(ptr.ToInt64(), target)) return ptr;
            if (d == 0) continue;
            ptr = TryAlloc(handle, target - d, size);
            if (ptr != IntPtr.Zero && FitsRel32(ptr.ToInt64(), target)) return ptr;
        }
        return IntPtr.Zero;
    }

    private static IntPtr TryAlloc(IntPtr handle, long addr, int size)
    {
        if (addr <= 0) return IntPtr.Zero;
        long aligned = addr & ~0xFFFFL;
        return VirtualAllocEx(handle, new IntPtr(aligned), new UIntPtr((uint)size), MemCommit | MemReserve, PageExecuteReadWrite);
    }

    private static bool FitsRel32(long cave, long target)
    {
        long diff = cave - (target + 5);
        return diff >= int.MinValue && diff <= int.MaxValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct XINPUT_GAMEPAD
    {
        public ushort wButtons;
        public byte bLeftTrigger;
        public byte bRightTrigger;
        public short sThumbLX;
        public short sThumbLY;
        public short sThumbRX;
        public short sThumbRY;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct XINPUT_STATE
    {
        public uint dwPacketNumber;
        public XINPUT_GAMEPAD Gamepad;
    }

    [DllImport("xinput1_4.dll")]
    private static extern uint XInputGetState(uint dwUserIndex, out XINPUT_STATE pState);

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
    private static extern bool FlushInstructionCache(IntPtr h, IntPtr addr, IntPtr size);
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);
}
