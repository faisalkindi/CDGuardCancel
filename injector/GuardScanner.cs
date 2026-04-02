using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

/// <summary>
/// Guard Button Scanner v3 — bulk snapshot approach.
/// Takes 3 snapshots (LB up, LB down, LB up), diffs per-region in bulk.
/// No giant dictionaries — filters at the byte-array level.
/// </summary>
internal static class Program
{
    private const uint ProcessAccess = 0x0418;
    private const int F6 = 0x75, F8 = 0x77;

    private static int Main()
    {
        Console.WriteLine("Guard Button Scanner v3");
        Console.WriteLine("Press F8 to quit at any time.\n");

        Process process = WaitForProcess();
        if (process == null) return 1;

        IntPtr handle = OpenProcess(ProcessAccess, false, (uint)process.Id);
        if (handle == IntPtr.Zero) { Console.WriteLine("Failed to open process. Run as admin."); return 1; }

        long moduleBase = 0x140000000, moduleSize = 0;
        try { moduleBase = process.MainModule.BaseAddress.ToInt64(); moduleSize = process.MainModule.ModuleMemorySize; } catch { }
        Console.WriteLine("Module: 0x{0:X}\n", moduleBase);

        // Enumerate regions once
        var regions = EnumerateRegions(handle);
        long totalMB = 0; foreach (var r in regions) totalMB += r.Size;
        Console.WriteLine("{0} regions, {1} MB\n", regions.Count, totalMB / 1024 / 1024);

        // ── 3 snapshots ──
        Console.WriteLine("=== STEP 1/3: Do NOT press LB. Press F6. ===");
        WaitForKey(F6); if (ShouldExit(process)) { CloseHandle(handle); return 0; }
        Console.Write("Snapshotting (LB not pressed)...");
        var snap1 = TakeSnapshot(handle, regions);
        Console.WriteLine(" done ({0} regions)", snap1.Count);

        Console.WriteLine("\n=== STEP 2/3: HOLD LB down (guard). Press F6. ===");
        WaitForKey(F6); if (ShouldExit(process)) { CloseHandle(handle); return 0; }
        Console.Write("Snapshotting (LB held down)...");
        var snap2 = TakeSnapshot(handle, regions);
        Console.WriteLine(" done");

        Console.WriteLine("\n=== STEP 3/3: Let go of LB. Press F6. ===");
        WaitForKey(F6); if (ShouldExit(process)) { CloseHandle(handle); return 0; }
        Console.Write("Snapshotting (LB released)...");
        var snap3 = TakeSnapshot(handle, regions);
        Console.WriteLine(" done");

        // ── Bulk diff: find addresses where snap1=0, snap2!=0, snap3=0 ──
        Console.Write("\nAnalyzing 3-way diff...");
        var candidates = new List<HitInfo>();

        for (int ri = 0; ri < regions.Count; ri++)
        {
            if (ri >= snap1.Count || ri >= snap2.Count || ri >= snap3.Count) break;
            byte[] a = snap1[ri], b = snap2[ri], c = snap3[ri];
            if (a == null || b == null || c == null) continue;
            int len = Math.Min(a.Length, Math.Min(b.Length, c.Length));
            long baseAddr = regions[ri].Base;

            for (int i = 0; i <= len - 4; i += 4)
            {
                // Check as u8 at aligned offset
                if (a[i] == 0 && b[i] != 0 && c[i] == 0)
                {
                    candidates.Add(new HitInfo { Addr = baseAddr + i, ValHeld = b[i] });
                    if (candidates.Count > 500000) break; // safety cap
                }
            }
            if (candidates.Count > 500000) break;
        }

        Console.WriteLine(" {0} candidates", candidates.Count);

        // Free snapshots
        snap1 = snap2 = snap3 = null;
        GC.Collect();

        if (candidates.Count == 0)
        {
            Console.WriteLine("No candidates. Was LB actually pressed/released at the right times?");
            CloseHandle(handle); return 1;
        }

        // ── Refinement rounds (read 1 byte per candidate, but list is manageable now) ──
        int round = 0;
        bool expectHeld = true;

        while (candidates.Count > 50)
        {
            round++;
            if (expectHeld)
                Console.WriteLine("\n=== REFINE {0}: HOLD LB, press F6 === ({1} left)", round, candidates.Count);
            else
                Console.WriteLine("\n=== REFINE {0}: RELEASE LB, press F6 === ({1} left)", round, candidates.Count);

            WaitForKey(F6);
            if (ShouldExit(process)) break;

            Console.Write("Filtering...");
            var keep = new List<HitInfo>();
            foreach (var h in candidates)
            {
                byte[] v = ReadBytes(handle, h.Addr, 1);
                if (v == null) continue;

                if (expectHeld && v[0] != 0)
                    keep.Add(new HitInfo { Addr = h.Addr, ValHeld = v[0] });
                else if (!expectHeld && v[0] == 0)
                    keep.Add(new HitInfo { Addr = h.Addr, ValHeld = h.ValHeld });
            }
            candidates = keep;
            Console.WriteLine(" {0} remaining", candidates.Count);
            expectHeld = !expectHeld;

            if (candidates.Count == 0)
            {
                Console.WriteLine("All candidates eliminated. Try again from scratch.");
                CloseHandle(handle); return 1;
            }
        }

        // ── Results ──
        Console.WriteLine("\n========================================");
        Console.WriteLine("FINAL: {0} addresses", candidates.Count);
        Console.WriteLine("========================================");

        candidates.Sort((a, b) => a.Addr.CompareTo(b.Addr));
        var finals = new Dictionary<long, byte>();

        foreach (var h in candidates)
        {
            string loc = (h.Addr >= moduleBase && h.Addr < moduleBase + moduleSize)
                ? string.Format("MODULE+0x{0:X}", h.Addr - moduleBase) : "HEAP";

            byte[] ctx = ReadBytes(handle, h.Addr - 8, 20);
            string hex = "";
            if (ctx != null)
            {
                for (int i = 0; i < ctx.Length; i++)
                {
                    if (i == 8) hex += "[";
                    hex += string.Format("{0:X2}", ctx[i]);
                    if (i == 8) hex += "]";
                    if (i < ctx.Length - 1) hex += " ";
                }
            }
            Console.WriteLine("  0x{0:X}  ({1})  held={2}  {3}", h.Addr, loc, h.ValHeld, hex);
            finals[h.Addr] = 0;
        }

        // ── Live monitor ──
        Console.WriteLine("\nLive monitoring... press/release LB to verify. F8 to exit.");
        while (true)
        {
            if ((GetAsyncKeyState(F8) & 1) != 0) break;
            if (process.HasExited) break;

            foreach (var h in candidates)
            {
                byte[] v = ReadBytes(handle, h.Addr, 1);
                if (v != null && v[0] != finals[h.Addr])
                {
                    Console.WriteLine("  0x{0:X}: {1} -> {2}", h.Addr, finals[h.Addr], v[0]);
                    finals[h.Addr] = v[0];
                }
            }
            Thread.Sleep(50);
        }

        CloseHandle(handle);
        Console.WriteLine("Done.");
        return 0;
    }

    struct HitInfo { public long Addr; public byte ValHeld; }
    struct MemRegion { public long Base; public int Size; }

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
