using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

internal static class GuardCancelV2
{
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessQueryInformation = 0x0400;

    private const string TargetProcess = "CrimsonDesert";
    private const int ExitKey = 0x77; // F8

    // AOB from CE findings: the evaluation call + test al,al + je
    // +27123E3: 48 8B CB          mov rcx, rbx
    // +27123E6: E8 A5 FC FF FF    call +2712090
    // +27123EB: 84 C0             test al, al
    // +27123ED: 74 12             je +2712401  <-- PATCH TARGET (2 bytes)
    //
    // Pattern: mov rcx,rbx / call ?? ?? ?? ?? / test al,al / je 12
    private static readonly byte[] Pattern = {
        0x48, 0x8B, 0xCB,                          // mov rcx, rbx
        0xE8, 0x00, 0x00, 0x00, 0x00,              // call (wildcard)
        0x84, 0xC0,                                 // test al, al
        0x74, 0x12                                  // je +0x12
    };
    private static readonly bool[] Mask = {
        true, true, true,
        true, false, false, false, false,
        true, true,
        true, true
    };

    // Patch the je (74 12) at offset 10-11 in the pattern
    private const int PatchOffset = 10;
    private static readonly byte[] OriginalBytes = { 0x74, 0x12 };
    private static readonly byte[] PatchedBytes = { 0x90, 0x90 };

    private static int Main()
    {
        Console.WriteLine("Crimson Desert — Guard Cancel v2");
        Console.WriteLine("Patches evaluation gate to allow guard during attacks.");
        Console.WriteLine("Press F8 to restore and exit.");
        Console.WriteLine();

        Process process = WaitForProcess();
        if (process == null) return 1;

        IntPtr handle = OpenProcess(
            ProcessQueryInformation | ProcessVmRead | ProcessVmWrite | ProcessVmOperation,
            false, (uint)process.Id);

        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process. Run as administrator.");
            return 1;
        }

        long moduleBase = process.MainModule.BaseAddress.ToInt64();
        long moduleSize = process.MainModule.ModuleMemorySize;
        Console.WriteLine("Base: 0x{0:X}, Size: {1} MB", moduleBase, moduleSize / 1024 / 1024);

        // AOB scan
        long patchAddress = ScanForPattern(handle, moduleBase, moduleSize);
        if (patchAddress == 0)
        {
            Console.WriteLine("Pattern not found. Game may have updated.");
            CloseHandle(handle);
            Console.ReadKey();
            return 1;
        }

        Console.WriteLine("Found at 0x{0:X} (RVA +0x{1:X})", patchAddress, patchAddress - moduleBase);

        // Verify original bytes
        byte[] check = ReadBytes(handle, patchAddress, 2);
        if (check == null || check[0] != OriginalBytes[0] || check[1] != OriginalBytes[1])
        {
            Console.WriteLine("Unexpected bytes: {0:X2} {1:X2} (expected {2:X2} {3:X2})",
                check != null ? check[0] : 0, check != null ? check[1] : 0,
                OriginalBytes[0], OriginalBytes[1]);
            CloseHandle(handle);
            Console.ReadKey();
            return 1;
        }

        // Apply patch
        WriteBytes(handle, patchAddress, PatchedBytes);
        Console.WriteLine("PATCHED: 74 12 -> 90 90 (je -> nop nop)");
        Console.WriteLine();
        Console.WriteLine("Test: attack with sword, press LB mid-attack.");
        Console.WriteLine("Press F8 to restore and exit.");

        // Keep alive, re-apply if Themida reverts
        while (true)
        {
            if ((GetAsyncKeyState(ExitKey) & 1) != 0) break;
            if (process.HasExited) break;

            byte[] current = ReadBytes(handle, patchAddress, 2);
            if (current != null && current[0] == OriginalBytes[0] && current[1] == OriginalBytes[1])
            {
                WriteBytes(handle, patchAddress, PatchedBytes);
                Console.WriteLine("[{0}] Re-applied (Themida reverted)", DateTime.Now.ToString("HH:mm:ss"));
            }

            Thread.Sleep(100);
        }

        // Restore
        WriteBytes(handle, patchAddress, OriginalBytes);
        Console.WriteLine("Restored. Closing.");
        CloseHandle(handle);
        return 0;
    }

    private static Process WaitForProcess()
    {
        Console.Write("Waiting for CrimsonDesert.exe...");
        for (int i = 0; i < 120; i++)
        {
            Process[] procs = Process.GetProcessesByName(TargetProcess);
            for (int p = 0; p < procs.Length; p++)
            {
                try
                {
                    string exeName = System.IO.Path.GetFileNameWithoutExtension(procs[p].MainModule.FileName);
                    if (exeName == TargetProcess)
                    {
                        Console.WriteLine(" found (PID {0})", procs[p].Id);
                        return procs[p];
                    }
                }
                catch { }
            }
            Thread.Sleep(500);
        }
        Console.WriteLine(" timeout.");
        return null;
    }

    private static long ScanForPattern(IntPtr handle, long baseAddr, long size)
    {
        const int ChunkSize = 4 * 1024 * 1024;
        byte[] buffer = new byte[ChunkSize + Pattern.Length];

        for (long offset = 0; offset < size; offset += ChunkSize)
        {
            int toRead = (int)Math.Min(ChunkSize + Pattern.Length, size - offset);
            IntPtr bytesRead;
            if (!ReadProcessMemory(handle, new IntPtr(baseAddr + offset),
                    buffer, new IntPtr(toRead), out bytesRead))
                continue;

            int readCount = bytesRead.ToInt32();
            for (int i = 0; i <= readCount - Pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < Pattern.Length; j++)
                {
                    if (Mask[j] && buffer[i + j] != Pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return baseAddr + offset + i + PatchOffset;
            }
        }
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

    private static bool WriteBytes(IntPtr handle, long address, byte[] data)
    {
        IntPtr written;
        return WriteProcessMemory(handle, new IntPtr(address), data, new IntPtr(data.Length), out written);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBase,
        byte[] lpBuffer, IntPtr nSize, out IntPtr lpRead);

    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBase,
        byte[] lpBuffer, IntPtr nSize, out IntPtr lpWritten);

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);
}
