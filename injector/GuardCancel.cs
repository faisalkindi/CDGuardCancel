using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

internal static class GuardCancel
{
    private const uint ProcessAll = 0x001FFFFF;
    private const string TargetProcess = "CrimsonDesert";
    private const int ExitKey = 0x77; // F8
    private const byte GUARD_SLOT = 0;
    private const int XINPUT_GAMEPAD_LEFT_SHOULDER = 0x0100;

    [StructLayout(LayoutKind.Sequential)]
    private struct XINPUT_GAMEPAD { public ushort wButtons; public byte bLeftTrigger; public byte bRightTrigger; public short sThumbLX; public short sThumbLY; public short sThumbRX; public short sThumbRY; }
    [StructLayout(LayoutKind.Sequential)]
    private struct XINPUT_STATE { public uint dwPacketNumber; public XINPUT_GAMEPAD Gamepad; }
    [DllImport("xinput1_4.dll")]
    private static extern uint XInputGetState(uint idx, ref XINPUT_STATE state);

    // AOB: movaps xmm1,xmm6 / mov [rsp+20],rcx / mov rcx,rbx / call eval / test al,al / je +12
    private static readonly byte[] AOB = {
        0x0F, 0x28, 0xCE,
        0x48, 0x89, 0x4C, 0x24, 0x20,
        0x48, 0x8B, 0xCB,
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x84, 0xC0,
        0x74, 0x12
    };
    private static readonly bool[] Mask = {
        true, true, true,
        true, true, true, true, true,
        true, true, true,
        true, false, false, false, false,
        true, true,
        true, true
    };
    private const int CallOffset = 11;
    private const int CallLen = 5;

    private static int Main()
    {
        Console.WriteLine("Crimson Desert — Guard Cancel (LB-gated cave)");
        Console.WriteLine("Only forces guard eval when LB is held + slot 0.");
        Console.WriteLine("Press F8 to restore and exit.");
        Console.WriteLine();

        Process process = WaitForProcess();
        if (process == null) return 1;

        IntPtr handle = OpenProcess(ProcessAll, false, (uint)process.Id);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to open process. Run as administrator.");
            Console.ReadKey();
            return 1;
        }

        long moduleBase = process.MainModule.BaseAddress.ToInt64();
        long moduleSize = process.MainModule.ModuleMemorySize;
        Console.WriteLine("Base: 0x{0:X}, Size: {1} MB", moduleBase, moduleSize / 1024 / 1024);

        Console.Write("Scanning...");
        long patAddr = ScanForPattern(handle, moduleBase, moduleSize, AOB, Mask);
        if (patAddr == 0)
        {
            Console.WriteLine(" not found.");
            Console.ReadKey();
            CloseHandle(handle);
            return 1;
        }
        Console.WriteLine(" FOUND at RVA +0x{0:X}", patAddr - moduleBase);

        long callAddr = patAddr + CallOffset;
        long afterCall = callAddr + CallLen;

        byte[] callBytes = ReadBytes(handle, callAddr, 5);
        if (callBytes == null || callBytes[0] != 0xE8)
        {
            Console.WriteLine("Call byte mismatch.");
            Console.ReadKey();
            CloseHandle(handle);
            return 1;
        }
        int callDisp = BitConverter.ToInt32(callBytes, 1);
        long evalTarget = afterCall + callDisp;
        Console.WriteLine("  evaluator at RVA +0x{0:X}", evalTarget - moduleBase);

        // Allocate cave (256 bytes: byte 0 = LB flag, code starts at byte 16)
        IntPtr cavePtr = IntPtr.Zero;
        long step = 0x10000;
        for (long d = step; d < 0x7FFF0000L; d += step)
        {
            cavePtr = VirtualAllocEx(handle, new IntPtr(callAddr + d), 256, 0x3000, 0x40);
            if (cavePtr != IntPtr.Zero) break;
            if (callAddr > d) {
                cavePtr = VirtualAllocEx(handle, new IntPtr(callAddr - d), 256, 0x3000, 0x40);
                if (cavePtr != IntPtr.Zero) break;
            }
        }
        if (cavePtr == IntPtr.Zero)
        {
            Console.WriteLine("Cave alloc failed.");
            Console.ReadKey();
            CloseHandle(handle);
            return 1;
        }
        long caveBase = cavePtr.ToInt64();
        long flagAddr = caveBase;       // byte 0 = LB flag
        long codeAddr = caveBase + 16;  // code starts at offset 16
        Console.WriteLine("  cave at 0x{0:X}, flag at 0x{1:X}", caveBase, flagAddr);

        // Initialize flag to 0
        WriteBytes(handle, flagAddr, new byte[] { 0 }, 1);

        // Build cave code at caveBase+16:
        //
        //   cmp r8d, GUARD_SLOT       ; is this the guard slot?
        //   jne doCall                ; no → call evaluator normally
        //   push rax                  ; save
        //   mov rax, flagAddr         ; load flag address
        //   cmp byte [rax], 1         ; is LB held?
        //   pop rax                   ; restore
        //   jne doCall                ; LB not held → call evaluator normally
        //   mov al, 1                 ; LB held + guard slot → force success
        //   jmp afterCall
        // doCall:
        //   call evalTarget
        //   jmp afterCall

        byte[] cave = new byte[80];
        int o = 0;

        // cmp r8d, GUARD_SLOT
        cave[o++] = 0x41; cave[o++] = 0x83; cave[o++] = 0xF8; cave[o++] = GUARD_SLOT;

        // jne doCall (short)
        cave[o++] = 0x75;
        int jne1Pos = o; cave[o++] = 0x00;

        // push rax
        cave[o++] = 0x50;

        // mov rax, flagAddr (48 B8 imm64)
        cave[o++] = 0x48; cave[o++] = 0xB8;
        long fa = flagAddr;
        for (int b = 0; b < 8; b++) { cave[o++] = (byte)(fa & 0xFF); fa >>= 8; }

        // cmp byte [rax], 1
        cave[o++] = 0x80; cave[o++] = 0x38; cave[o++] = 0x01;

        // pop rax
        cave[o++] = 0x58;

        // jne doCall (short)
        cave[o++] = 0x75;
        int jne2Pos = o; cave[o++] = 0x00;

        // Force success: mov al, 1
        cave[o++] = 0xB0; cave[o++] = 0x01;

        // jmp afterCall
        cave[o++] = 0xE9;
        int rel1 = (int)(afterCall - (codeAddr + o + 4));
        cave[o++] = (byte)rel1; cave[o++] = (byte)(rel1 >> 8);
        cave[o++] = (byte)(rel1 >> 16); cave[o++] = (byte)(rel1 >> 24);

        // doCall:
        int doCallOff = o;
        cave[jne1Pos] = (byte)(doCallOff - (jne1Pos + 1));
        cave[jne2Pos] = (byte)(doCallOff - (jne2Pos + 1));

        // call evalTarget
        cave[o++] = 0xE8;
        int callRel = (int)(evalTarget - (codeAddr + o + 4));
        cave[o++] = (byte)callRel; cave[o++] = (byte)(callRel >> 8);
        cave[o++] = (byte)(callRel >> 16); cave[o++] = (byte)(callRel >> 24);

        // jmp afterCall
        cave[o++] = 0xE9;
        int rel2 = (int)(afterCall - (codeAddr + o + 4));
        cave[o++] = (byte)rel2; cave[o++] = (byte)(rel2 >> 8);
        cave[o++] = (byte)(rel2 >> 16); cave[o++] = (byte)(rel2 >> 24);

        // Write cave code
        WriteBytes(handle, codeAddr, cave, o);
        Console.WriteLine("  cave code: {0} bytes", o);

        // Save original and install redirect
        byte[] origCall = ReadBytes(handle, callAddr, CallLen);
        byte[] redirect = new byte[5];
        redirect[0] = 0xE9;
        int redRel = (int)(codeAddr - (callAddr + 5));
        redirect[1] = (byte)redRel; redirect[2] = (byte)(redRel >> 8);
        redirect[3] = (byte)(redRel >> 16); redirect[4] = (byte)(redRel >> 24);

        WriteBytes(handle, callAddr, redirect, 5);
        Console.WriteLine("  hook installed at RVA +0x{0:X}", callAddr - moduleBase);
        Console.WriteLine();
        Console.WriteLine("ACTIVE — Hold LB during attacks to guard.");
        Console.WriteLine("Press F8 to restore and exit.");

        // Main loop: poll XInput, update flag byte in game memory
        XINPUT_STATE xstate = new XINPUT_STATE();
        byte lastFlag = 0;

        while (true)
        {
            if ((GetAsyncKeyState(ExitKey) & 1) != 0) break;
            if (process.HasExited) break;

            bool lb = false;
            if (XInputGetState(0, ref xstate) == 0)
                lb = (xstate.Gamepad.wButtons & XINPUT_GAMEPAD_LEFT_SHOULDER) != 0;

            byte flag = lb ? (byte)1 : (byte)0;
            if (flag != lastFlag)
            {
                WriteBytes(handle, flagAddr, new byte[] { flag }, 1);
                lastFlag = flag;
                Console.WriteLine("[{0}] LB {1}", DateTime.Now.ToString("HH:mm:ss.fff"),
                    lb ? "HELD → guard forced" : "released → normal");
            }

            // Re-apply hook if Themida reverts
            byte[] cur = ReadBytes(handle, callAddr, 1);
            if (cur != null && cur[0] != 0xE9)
            {
                WriteBytes(handle, callAddr, redirect, 5);
                Console.WriteLine("[{0}] Re-applied hook", DateTime.Now.ToString("HH:mm:ss"));
            }

            Thread.Sleep(8); // ~120Hz polling
        }

        // Restore
        WriteBytes(handle, flagAddr, new byte[] { 0 }, 1);
        WriteBytes(handle, callAddr, origCall, CallLen);
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
            for (int p = 0; p < procs.Length; p++) {
                try { if (procs[p].MainModule != null) { Console.WriteLine(" found (PID {0})", procs[p].Id); return procs[p]; } }
                catch { }
            }
            Thread.Sleep(500);
        }
        Console.WriteLine(" timeout."); return null;
    }

    private static long ScanForPattern(IntPtr h, long baseAddr, long size, byte[] pat, bool[] mask)
    {
        const int Chunk = 4 * 1024 * 1024;
        byte[] buf = new byte[Chunk + pat.Length];
        for (long off = 0; off < size; off += Chunk) {
            int toRead = (int)Math.Min(Chunk + pat.Length, size - off);
            IntPtr rd;
            if (!ReadProcessMemory(h, new IntPtr(baseAddr + off), buf, new IntPtr(toRead), out rd)) continue;
            int n = rd.ToInt32();
            for (int i = 0; i <= n - pat.Length; i++) {
                bool ok = true;
                for (int j = 0; j < pat.Length; j++)
                    if (mask[j] && buf[i + j] != pat[j]) { ok = false; break; }
                if (ok) return baseAddr + off + i;
            }
        }
        return 0;
    }

    private static byte[] ReadBytes(IntPtr h, long addr, int count)
    { byte[] b = new byte[count]; IntPtr r; return ReadProcessMemory(h, new IntPtr(addr), b, new IntPtr(count), out r) ? b : null; }

    private static bool WriteBytes(IntPtr h, long addr, byte[] data, int len)
    { byte[] b = new byte[len]; Array.Copy(data, b, len); IntPtr w; return WriteProcessMemory(h, new IntPtr(addr), b, new IntPtr(len), out w); }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint a, bool i, uint pid);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr h, IntPtr b, byte[] buf, IntPtr sz, out IntPtr rd);
    [DllImport("kernel32.dll")]
    private static extern bool WriteProcessMemory(IntPtr h, IntPtr b, byte[] buf, IntPtr sz, out IntPtr wr);
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, int sz, uint t, uint p);
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int k);
}
