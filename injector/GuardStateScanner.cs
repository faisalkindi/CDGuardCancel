using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

/// <summary>
/// Guard State Scanner v2 — requires candidates to pass the 3-state pattern
/// multiple times to eliminate false positives from noise.
/// </summary>
internal static class Program
{
    private const uint ProcessAccess = 0x0418;
    private const int F6 = 0x75, F8 = 0x77;

    private static int Main()
    {
        Console.WriteLine("===========================================");
        Console.WriteLine("  Guard STATE Scanner v2");
        Console.WriteLine("  Requires 3 rounds to confirm candidates");
        Console.WriteLine("===========================================");
        Console.WriteLine();
        Console.WriteLine("3 game states, repeated 3 times:");
        Console.WriteLine("  A) Standing idle, NOT pressing LB");
        Console.WriteLine("  B) Standing idle, HOLDING LB (guard active)");
        Console.WriteLine("  C) Mid-attack combo, HOLDING LB (guard blocked)");
        Console.WriteLine();
        Console.WriteLine("Press F8 to quit at any time.");
        Console.WriteLine();

        Process process = WaitForProcess();
        if (process == null) return 1;

        IntPtr handle = OpenProcess(ProcessAccess, false, (uint)process.Id);
        if (handle == IntPtr.Zero) { Console.WriteLine("Failed to open process. Run as admin."); return 1; }

        long moduleBase = 0x140000000, moduleSize = 0;
        try { moduleBase = process.MainModule.BaseAddress.ToInt64(); moduleSize = process.MainModule.ModuleMemorySize; } catch { }

        List<MemRegion> regions = EnumerateRegions(handle);
        long totalMB = 0; foreach (var r in regions) totalMB += r.Size;
        Console.WriteLine("Process: PID {0}, {1} regions ({2} MB)\n", process.Id, regions.Count, totalMB / 1024 / 1024);

        // ══════════════════════════════════════════
        // ROUND 1: Full memory diff to get candidates
        // ══════════════════════════════════════════
        Console.WriteLine("╔══════════════════════════════════════╗");
        Console.WriteLine("║  ROUND 1 of 3 — Initial full scan   ║");
        Console.WriteLine("╚══════════════════════════════════════╝");

        Console.WriteLine("\n>> STATE A: Stand idle. Do NOT press LB. Press F6.");
        WaitForKey(F6); if (ShouldExit(process)) { CloseHandle(handle); return 0; }
        Console.Write("Snapshotting A...");
        var snapA = TakeSnapshot(handle, regions);
        Console.WriteLine(" done");

        Console.WriteLine("\n>> STATE B: Stand idle. HOLD LB (guarding). Press F6.");
        WaitForKey(F6); if (ShouldExit(process)) { CloseHandle(handle); return 0; }
        Console.Write("Snapshotting B...");
        var snapB = TakeSnapshot(handle, regions);
        Console.WriteLine(" done");

        Console.WriteLine("\n>> STATE C: Attack enemy + HOLD LB (guard blocked). Press F6.");
        WaitForKey(F6); if (ShouldExit(process)) { CloseHandle(handle); return 0; }
        Console.Write("Snapshotting C...");
        var snapC = TakeSnapshot(handle, regions);
        Console.WriteLine(" done");

        Console.Write("\nDiffing...");
        var candidates = new List<HitInfo>();

        for (int ri = 0; ri < regions.Count; ri++)
        {
            if (ri >= snapA.Count || ri >= snapB.Count || ri >= snapC.Count) break;
            byte[] a = snapA[ri], b = snapB[ri], c = snapC[ri];
            if (a == null || b == null || c == null) continue;
            int len = Math.Min(a.Length, Math.Min(b.Length, c.Length));
            long baseAddr = regions[ri].Base;

            for (int i = 0; i <= len - 4; i += 4)
            {
                // Only keep A==C candidates (guard is the sole differentiator)
                // Check u8
                if (a[i] == c[i] && a[i] != b[i])
                {
                    candidates.Add(new HitInfo { Addr = baseAddr + i, ValA = a[i], ValB = b[i], Width = 1 });
                    if (candidates.Count > 500000) break;
                }
                // Check u32 (if u8 didn't match)
                else if (i + 3 < len)
                {
                    uint va = ReadU32(a, i), vb = ReadU32(b, i), vc = ReadU32(c, i);
                    if (va == vc && va != vb)
                    {
                        candidates.Add(new HitInfo { Addr = baseAddr + i, ValA = va, ValB = vb, Width = 4 });
                        if (candidates.Count > 500000) break;
                    }
                }
            }
            if (candidates.Count > 500000) break;
        }

        snapA = snapB = snapC = null;
        GC.Collect();

        Console.WriteLine(" {0} candidates after round 1", candidates.Count);

        if (candidates.Count == 0)
        {
            Console.WriteLine("No candidates found.");
            CloseHandle(handle);
            Console.WriteLine("Press any key to close.");
            Console.ReadKey();
            return 1;
        }

        // ══════════════════════════════════════════
        // ROUNDS 2-3: Verify each candidate individually
        // ══════════════════════════════════════════
        for (int round = 2; round <= 3; round++)
        {
            Console.WriteLine("\n╔══════════════════════════════════════╗");
            Console.WriteLine("║  ROUND {0} of 3 — {1} candidates left ║", round, candidates.Count);
            Console.WriteLine("╚══════════════════════════════════════╝");

            // Check state A
            Console.WriteLine("\n>> STATE A: Stand idle. Do NOT press LB. Press F6.");
            WaitForKey(F6); if (ShouldExit(process)) break;

            Console.Write("Checking A...");
            var keep = new List<HitInfo>();
            foreach (var h in candidates)
            {
                byte[] v = ReadBytes(handle, h.Addr, 4);
                if (v == null) continue;
                uint val = (h.Width == 1) ? v[0] : ReadU32(v, 0);
                if (val == h.ValA) keep.Add(h);
            }
            Console.WriteLine(" {0} -> {1}", candidates.Count, keep.Count);
            candidates = keep;
            if (candidates.Count == 0) break;

            // Check state B
            Console.WriteLine("\n>> STATE B: Stand idle. HOLD LB (guarding). Press F6.");
            WaitForKey(F6); if (ShouldExit(process)) break;

            Console.Write("Checking B...");
            keep = new List<HitInfo>();
            foreach (var h in candidates)
            {
                byte[] v = ReadBytes(handle, h.Addr, 4);
                if (v == null) continue;
                uint val = (h.Width == 1) ? v[0] : ReadU32(v, 0);
                if (val == h.ValB) keep.Add(h);
            }
            Console.WriteLine(" {0} -> {1}", candidates.Count, keep.Count);
            candidates = keep;
            if (candidates.Count == 0) break;

            // Check state C
            Console.WriteLine("\n>> STATE C: Attack enemy + HOLD LB (guard blocked). Press F6.");
            WaitForKey(F6); if (ShouldExit(process)) break;

            Console.Write("Checking C...");
            keep = new List<HitInfo>();
            foreach (var h in candidates)
            {
                byte[] v = ReadBytes(handle, h.Addr, 4);
                if (v == null) continue;
                uint val = (h.Width == 1) ? v[0] : ReadU32(v, 0);
                if (val == h.ValA) keep.Add(h); // C should equal A
            }
            Console.WriteLine(" {0} -> {1}", candidates.Count, keep.Count);
            candidates = keep;
        }

        // ══════════════════════════════════════════
        // RESULTS
        // ══════════════════════════════════════════
        Console.WriteLine("\n================================================");
        Console.WriteLine("FINAL: {0} addresses (survived 3 rounds)", candidates.Count);
        Console.WriteLine("================================================");
        Console.WriteLine("  A = idle value (no guard)");
        Console.WriteLine("  B = guard value (LB works)");
        Console.WriteLine("  A==C confirmed (blocked == idle)");
        Console.WriteLine();

        candidates.Sort(delegate(HitInfo x, HitInfo y) { return x.Addr.CompareTo(y.Addr); });

        string logPath = System.IO.Path.Combine(
            System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location),
            "guard_state_results.txt");
        var log = new System.IO.StreamWriter(logPath);
        log.WriteLine("Guard State Scanner v2 Results — {0}", DateTime.Now);
        log.WriteLine("FINAL: {0} addresses (survived 3 rounds)", candidates.Count);
        log.WriteLine();

        foreach (var h in candidates)
        {
            string loc = (h.Addr >= moduleBase && h.Addr < moduleBase + moduleSize)
                ? string.Format("MODULE+0x{0:X}", h.Addr - moduleBase) : "HEAP";
            string w = h.Width == 1 ? "u8" : "u32";

            string line = string.Format("  0x{0:X}  ({1}) {2}  A={3} B={4}", h.Addr, loc, w, h.ValA, h.ValB);
            Console.WriteLine(line);
            log.WriteLine(line);
        }

        log.Flush();
        log.Close();
        Console.WriteLine("\nResults saved to: {0}", logPath);

        // Live monitor
        if (candidates.Count > 0 && candidates.Count <= 200)
        {
            Console.WriteLine("\nLive monitoring... press/release LB to verify. F8 to stop.");
            var current = new Dictionary<long, uint>();
            foreach (var h in candidates) current[h.Addr] = 0xDEADBEEF;

            while (true)
            {
                if ((GetAsyncKeyState(F8) & 1) != 0) break;
                if (process.HasExited) break;

                foreach (var h in candidates)
                {
                    byte[] v = ReadBytes(handle, h.Addr, 4);
                    if (v == null) continue;
                    uint val = (h.Width == 1) ? v[0] : ReadU32(v, 0);
                    if (val != current[h.Addr])
                    {
                        string label = "";
                        if (val == h.ValA) label = " (IDLE/BLOCKED)";
                        else if (val == h.ValB) label = " (GUARD)";
                        Console.WriteLine("  0x{0:X}: {1} -> {2}{3}", h.Addr, current[h.Addr], val, label);
                        current[h.Addr] = val;
                    }
                }
                Thread.Sleep(50);
            }
        }

        CloseHandle(handle);
        Console.WriteLine("\nDone. Press any key to close.");
        Console.ReadKey();
        return 0;
    }

    struct HitInfo
    {
        public long Addr;
        public uint ValA; // idle value = blocked value (A==C)
        public uint ValB; // guard value
        public int Width;
    }

    struct MemRegion { public long Base; public int Size; }

    private static uint ReadU32(byte[] buf, int offset)
    {
        return (uint)(buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24));
    }

    private static List<byte[]> TakeSnapshot(IntPtr handle, List<MemRegion> regions)
    {
        var snap = new List<byte[]>(regions.Count);
        for (int i = 0; i < regions.Count; i++)
        {
            snap.Add(ReadBytes(handle, regions[i].Base, regions[i].Size));
            if ((i + 1) % 500 == 0) Console.Write(".");
        }
        return snap;
    }

    private static List<MemRegion> EnumerateRegions(IntPtr handle)
    {
        var regions = new List<MemRegion>();
        long addr = 0;
        while (addr < 0x7FFFFFFFFFFF)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(handle, new IntPtr(addr), out mbi, new IntPtr(48)) == IntPtr.Zero)
            { addr += 0x10000; continue; }
            long rBase = mbi.BaseAddress.ToInt64();
            long rSize = mbi.RegionSize.ToInt64();
            if (mbi.State == 0x1000 && (mbi.Protect & 0xEE) != 0 && (mbi.Protect & 0x100) == 0)
            {
                int sz = (int)Math.Min(rSize, 16 * 1024 * 1024);
                regions.Add(new MemRegion { Base = rBase, Size = sz });
            }
            addr = rBase + rSize;
            if (addr <= rBase) break;
        }
        return regions;
    }

    private static void WaitForKey(int vk)
    {
        while (true)
        {
            if ((GetAsyncKeyState(vk) & 1) != 0) return;
            if ((GetAsyncKeyState(F8) & 1) != 0) return;
            Thread.Sleep(30);
        }
    }

    private static bool ShouldExit(Process p)
    {
        return p.HasExited || (GetAsyncKeyState(F8) & 1) != 0;
    }

    private static Process WaitForProcess()
    {
        Console.Write("Waiting for CrimsonDesert.exe...");
        while (true)
        {
            if ((GetAsyncKeyState(F8) & 1) != 0) return null;
            foreach (var p in Process.GetProcessesByName("CrimsonDesert"))
            {
                try { if (p.MainModule != null) { Console.WriteLine(" PID {0}", p.Id); return p; } } catch { }
            }
            Thread.Sleep(500);
        }
    }

    private static byte[] ReadBytes(IntPtr handle, long address, int count)
    {
        byte[] buf = new byte[count];
        IntPtr read;
        return ReadProcessMemory(handle, new IntPtr(address), buf, new IntPtr(count), out read) ? buf : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, IntPtr len);
    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);
}
