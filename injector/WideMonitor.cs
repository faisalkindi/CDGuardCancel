using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

/// <summary>
/// Wide monitor — scans a large range of the input component object
/// looking for values that change when you guard, attack, or use skills.
/// No code patching, pure read-only.
/// </summary>
internal static class Program
{
    private const uint ProcessAccess = 0x0410;
    private const int ExitKey = 0x77; // F8
    private const int SnapshotKey = 0x75; // F6 = take snapshot
    private const int DiffKey = 0x76; // F7 = show diff from snapshot

    private static int Main()
    {
        Console.WriteLine("Wide Memory Monitor (read-only)");
        Console.WriteLine("F6 = snapshot current state");
        Console.WriteLine("F7 = show what changed since snapshot");
        Console.WriteLine("F8 = quit");
        Console.WriteLine();
        Console.WriteLine("Steps:");
        Console.WriteLine("  1. Stand IDLE, press F6 (snapshot idle state)");
        Console.WriteLine("  2. Press GUARD (LB) while idle, press F7 (see what changed)");
        Console.WriteLine("  3. Press F6 again (snapshot guard state)");
        Console.WriteLine("  4. Start ATTACKING, press F7 (see what changed)");
        Console.WriteLine("  5. Press F6 (snapshot attack state)");
        Console.WriteLine("  6. Press GUARD during attack, press F7 (see what changed — or didn't)");
        Console.WriteLine("  7. Press F6 (snapshot)");
        Console.WriteLine("  8. Use EVASIVE SLASH during attack, press F7 (compare with step 6)");
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

        // Follow pointer chain to input component
        long g = ReadPtr(handle, moduleBase + 0x5C9BDF8);
        if (g == 0) { Console.WriteLine("Global ptr null"); return 1; }
        long p2 = ReadPtr(handle, g + 0x90);
        if (p2 == 0) { Console.WriteLine("ptr2 null"); return 1; }
        long obj = ReadPtr(handle, p2 + 0x1168);
        if (obj == 0) { Console.WriteLine("obj null"); return 1; }

        Console.WriteLine("Object at 0x{0:X}", obj);
        Console.WriteLine("Scanning offsets 0x000 to 0xFFF (4KB)");
        Console.WriteLine();

        const int ScanSize = 0x1000;
        byte[] snapshot = null;

        while (true)
        {
            if ((GetAsyncKeyState(ExitKey) & 1) != 0) break;
            if (process.HasExited) break;

            if ((GetAsyncKeyState(SnapshotKey) & 1) != 0)
            {
                snapshot = ReadBytes(handle, obj, ScanSize);
                if (snapshot != null)
                    Console.WriteLine("[F6] Snapshot taken ({0} bytes)", snapshot.Length);
            }

            if ((GetAsyncKeyState(DiffKey) & 1) != 0 && snapshot != null)
            {
                byte[] current = ReadBytes(handle, obj, ScanSize);
                if (current != null)
                {
                    Console.WriteLine("[F7] Changes since snapshot:");
                    int changes = 0;
                    for (int i = 0; i < ScanSize; i++)
                    {
                        if (current[i] != snapshot[i])
                        {
                            // Show as u16 if the next byte also changed
                            if (i + 1 < ScanSize && current[i + 1] != snapshot[i + 1])
                            {
                                ushort oldVal = BitConverter.ToUInt16(snapshot, i);
                                ushort newVal = BitConverter.ToUInt16(current, i);
                                Console.WriteLine("  +0x{0:X3}: 0x{1:X4} -> 0x{2:X4}  (u16: {1} -> {2})",
                                    i, oldVal, newVal);
                                i++; // skip next byte
                            }
                            else
                            {
                                Console.WriteLine("  +0x{0:X3}: 0x{1:X2} -> 0x{2:X2}",
                                    i, snapshot[i], current[i]);
                            }
                            changes++;
                            if (changes > 40)
                            {
                                Console.WriteLine("  ... (too many changes, showing first 40)");
                                break;
                            }
                        }
                    }
                    if (changes == 0)
                        Console.WriteLine("  NO CHANGES");
                }
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

    private static long ReadPtr(IntPtr handle, long addr)
    {
        byte[] buf = new byte[8];
        IntPtr r;
        if (ReadProcessMemory(handle, new IntPtr(addr), buf, new IntPtr(8), out r))
            return BitConverter.ToInt64(buf, 0);
        return 0;
    }

    private static byte[] ReadBytes(IntPtr handle, long addr, int count)
    {
        byte[] buf = new byte[count];
        IntPtr r;
        if (ReadProcessMemory(handle, new IntPtr(addr), buf, new IntPtr(count), out r))
            return buf;
        return null;
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
