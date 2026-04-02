using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

internal static class Program
{
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessQueryInformation = 0x0400;

    private const string TargetProcess = "CrimsonDesert";
    private const int ExitKey = 0x77; // F8

    // AOB: E8 ?? ?? ?? ?? 84 C0 75 1F 0F B7 D3 48 8B CE
    // The 0x75 at offset 7 is the patch target (JNE -> JMP)
    private static readonly byte[] Pattern = {
        0xE8, 0x00, 0x00, 0x00, 0x00, // call (wildcard displacement)
        0x84, 0xC0,                     // test al, al
        0x75, 0x1F,                     // jne +0x1F
        0x0F, 0xB7, 0xD3,              // movzx edx, bx
        0x48, 0x8B, 0xCE               // mov rcx, rsi
    };
    private static readonly bool[] Mask = {
        true, false, false, false, false,
        true, true,
        true, true,
        true, true, true,
        true, true, true
    };
    private const int PatchOffset = 7; // offset of the 0x75 within the pattern
    private const byte OriginalByte = 0x75; // JNE
    private const byte PatchedByte = 0xEB;  // JMP

    private static int Main()
    {
        Console.WriteLine("Crimson Desert — Guard Cancel During Attacks");
        Console.WriteLine("Patches 1 byte to allow guard (LB) during attack animations.");
        Console.WriteLine("Press F8 to stop and restore.");
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
        Console.WriteLine("Module base: 0x{0:X}", moduleBase);
        Console.WriteLine("Module size: {0} MB", moduleSize / 1024 / 1024);

        // AOB scan
        long patchAddress = ScanForPattern(handle, moduleBase, moduleSize);
        if (patchAddress == 0)
        {
            Console.WriteLine("Pattern not found. Game may have updated.");
            CloseHandle(handle);
            return 1;
        }

        Console.WriteLine("Found patch target at 0x{0:X}", patchAddress);

        // Verify original byte
        byte[] check = ReadByte(handle, patchAddress);
        if (check == null || check[0] != OriginalByte)
        {
            Console.WriteLine("Unexpected byte at target: 0x{0:X2} (expected 0x{1:X2})",
                check != null ? check[0] : 0, OriginalByte);
            CloseHandle(handle);
            return 1;
        }

        // Apply patch
        WriteByte(handle, patchAddress, PatchedByte);
        Console.WriteLine("PATCHED: 0x{0:X2} -> 0x{1:X2}", OriginalByte, PatchedByte);
        Console.WriteLine("Guard should now work during attacks. Press F8 to stop.");

        // Keep alive, re-apply if reverted
        while (true)
        {
            if ((GetAsyncKeyState(ExitKey) & 1) != 0) break;
            if (process.HasExited) break;

            byte[] current = ReadByte(handle, patchAddress);
            if (current != null && current[0] == OriginalByte)
            {
                WriteByte(handle, patchAddress, PatchedByte);
                Console.WriteLine("Re-applied (Themida reverted)");
            }

            Thread.Sleep(100);
        }

        // Restore
        WriteByte(handle, patchAddress, OriginalByte);
        Console.WriteLine("Restored original byte. Closing.");
        CloseHandle(handle);
        return 0;
    }

    private static Process WaitForProcess()
    {
        Console.Write("Waiting for CrimsonDesert.exe...");
        while (true)
        {
            Process[] procs = Process.GetProcessesByName(TargetProcess);
            for (int i = 0; i < procs.Length; i++)
            {
                // Exact match — exclude CrimsonDesertModManager etc.
                try
                {
                    string exeName = System.IO.Path.GetFileNameWithoutExtension(procs[i].MainModule.FileName);
                    if (exeName == TargetProcess)
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

    private static long ScanForPattern(IntPtr handle, long baseAddr, long size)
    {
        const int ChunkSize = 4 * 1024 * 1024; // 4MB chunks
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

    private static byte[] ReadByte(IntPtr handle, long address)
    {
        byte[] buf = new byte[1];
        IntPtr read;
        if (ReadProcessMemory(handle, new IntPtr(address), buf, new IntPtr(1), out read))
            return buf;
        return null;
    }

    private static bool WriteByte(IntPtr handle, long address, byte value)
    {
        byte[] buf = { value };
        IntPtr written;
        return WriteProcessMemory(handle, new IntPtr(address), buf, new IntPtr(1), out written);
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
