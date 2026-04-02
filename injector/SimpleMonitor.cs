using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

/// <summary>
/// Simple polling monitor — no code patching, just reads memory values.
/// Scans for the player object by finding the action_id field pattern,
/// then polls it to see what changes during guard vs evasive slash.
/// </summary>
internal static class Program
{
    private const uint ProcessAccess = 0x0410; // QUERY_INFO | VM_READ
    private const int ExitKey = 0x77; // F8

    private static int Main()
    {
        Console.WriteLine("Simple Action Monitor (read-only, no patches)");
        Console.WriteLine("Press F8 to stop.");
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
        Console.WriteLine("Module base: 0x{0:X}", moduleBase);

        // Read the global pointer chain to find the player/input component.
        // From the combat gate caller at 0x140AD7693:
        //   mov rax, [rip+0x51C6ED8]  (at 0x140AD4F19, loads a global ptr)
        //   mov rdx, [rax+0x90]
        //   mov rsi, [rdx+0x1168]     (rsi = input component)
        //
        // The global is at 0x140AD4F19 + 7 + 0x51C6ED8 = 0x145C9BDF8
        // Let me read this pointer chain.

        long globalPtr = moduleBase + 0x5C9BDF8;
        Console.WriteLine("Global ptr at: 0x{0:X}", globalPtr);

        // Follow pointer chain: global -> [+0x90] -> [+0x1168] = input component
        long ptr1 = ReadPtr(handle, globalPtr);
        if (ptr1 == 0) { Console.WriteLine("Global ptr is null"); CloseHandle(handle); return 1; }
        Console.WriteLine("  [global] = 0x{0:X}", ptr1);

        long ptr2 = ReadPtr(handle, ptr1 + 0x90);
        if (ptr2 == 0) { Console.WriteLine("ptr+0x90 is null"); CloseHandle(handle); return 1; }
        Console.WriteLine("  [+0x90]  = 0x{0:X}", ptr2);

        long inputComp = ReadPtr(handle, ptr2 + 0x1168);
        if (inputComp == 0) { Console.WriteLine("ptr+0x1168 is null"); CloseHandle(handle); return 1; }
        Console.WriteLine("  [+0x1168] = 0x{0:X} (input component)", inputComp);

        // Now the combat gate is called with rcx = player object (which has the input component).
        // The action fields are at player+0x9C0, 0x9C2, 0x9CA, 0x9C8.
        // But the player object is what gets passed as rcx to the gate.
        // From caller 1: rcx = rbx = player object.
        // From caller 2: rcx = rsi = [rdx+0x1168] = input component.
        // They might be the same object or different.
        //
        // Let me try reading from the input component at those offsets.

        // Also read from a wider range to find what changes
        Console.WriteLine();
        Console.WriteLine("Monitoring input component at 0x{0:X}", inputComp);
        Console.WriteLine("Reading offsets 0x9B0-0x9D0 (action fields)");
        Console.WriteLine();
        Console.WriteLine("Do these in order:");
        Console.WriteLine("  1. Stand idle");
        Console.WriteLine("  2. Press guard (LB)");
        Console.WriteLine("  3. Attack (RB)");
        Console.WriteLine("  4. During attack press guard (LB)");
        Console.WriteLine("  5. During attack use Evasive Slash");
        Console.WriteLine();

        byte[] lastSnapshot = null;

        while (true)
        {
            if ((GetAsyncKeyState(ExitKey) & 1) != 0) break;
            if (process.HasExited) break;

            // Read a block of memory from the input component
            byte[] data = ReadBytes(handle, inputComp + 0x9B0, 0x30);
            if (data == null) { Thread.Sleep(100); continue; }

            // Check if anything changed
            if (lastSnapshot == null || !BytesEqual(data, lastSnapshot))
            {
                // Show what changed
                Console.Write("  ");
                for (int i = 0; i < data.Length; i++)
                {
                    if (lastSnapshot != null && data[i] != lastSnapshot[i])
                        Console.Write("[{0:X2}]", data[i]);
                    else
                        Console.Write(" {0:X2} ", data[i]);

                    if (i == 0xF || i == 0x1F)
                        Console.Write("| ");
                }

                // Decode known fields
                ushort actionId1 = BitConverter.ToUInt16(data, 0x10); // +0x9C0
                ushort actionId2 = BitConverter.ToUInt16(data, 0x12); // +0x9C2
                byte overrideFlag = data[0x18];                        // +0x9C8
                byte activeFlag = data[0x1A];                          // +0x9CA

                Console.WriteLine();
                Console.WriteLine("    action1=0x{0:X4} action2=0x{1:X4} override={2} active={3}",
                    actionId1, actionId2, overrideFlag, activeFlag);

                lastSnapshot = (byte[])data.Clone();
            }

            Thread.Sleep(30);
        }

        CloseHandle(handle);
        Console.WriteLine("Done.");
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

    private static long ReadPtr(IntPtr handle, long address)
    {
        byte[] buf = new byte[8];
        IntPtr read;
        if (ReadProcessMemory(handle, new IntPtr(address), buf, new IntPtr(8), out read))
            return BitConverter.ToInt64(buf, 0);
        return 0;
    }

    private static byte[] ReadBytes(IntPtr handle, long address, int count)
    {
        byte[] buf = new byte[count];
        IntPtr read;
        if (ReadProcessMemory(handle, new IntPtr(address), buf, new IntPtr(count), out read))
            return buf;
        return null;
    }

    private static bool BytesEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);
}
