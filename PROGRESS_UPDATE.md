# Crimson Desert Animation Cancel — Progress Update

## What Changed Since Last Handoff

### Major Breakthroughs

**1. We can find ANY game object on the heap via RTTI vtable scanning**

Python (pymem) can attach to the live game, scan all writable memory for 8-byte vtable pointers, and find every instance of any RTTI class. This works reliably:

```python
# Example: found 41 InputBlock instances and 92 ActionChartPackage instances
pm = pymem.Pymem("CrimsonDesert.exe")
# Scan heap for objects whose first 8 bytes == known vtable VA
INPUTBLOCK_VTABLE = 0x144AFCC70
ACTIONCHART_VTABLE = 0x144A6C610
```

**2. We can read/write game heap memory freely**

`WriteProcessMemory` works on all heap objects. Themida does NOT protect data writes — only code. We successfully wrote to 1479 memory locations and 12 InputBlock objects without any crash or detection.

**3. Live RTTI discovery works**

The memory dump's addresses don't match the live process (game was updated). But we can find correct addresses at runtime by scanning for RTTI decorated name strings like `.?AVStageChart_Function_InputBlock@pa@@`, then walking type_info → COL → vtable. Python script does this in ~30 seconds.

**4. The raw .paac file IS loaded into memory**

Found sword_upper.paac's string table at multiple heap addresses (contains "key_guard", "key_norattack", "key_guard_start", etc.). Found 6,037 transition-pattern matches [float thresh, float -1.0, uint32 target, uint32 seq] in the same region. 3,782 of those target state 0 (guard).

### What We Tested and What Failed

**Test 1: InputBlock `_inputBlockType` heap patch → FAILED**
- Found 41 `StageChart_Function_InputBlock` instances on heap
- Object layout: vtable(+0x00), unknown(+0x04-0x14), `-1.0f`(+0x14), `_inputBlockType`(+0x18), `_unsetOnSequencerControl`(+0x20)
- `_inputBlockType` values seen: 0, 1, 3, 4, 5, 8
- Patched ALL 12 instances (in one test run) to 0xFF → guard still doesn't cancel attacks
- **Conclusion:** InputBlock is NOT what prevents guard during attacks. It likely blocks input during menus/cutscenes/NPC interactions (the condition strings in objects confirm: "ExistTag(set_npc_menu) & Sell==Sell", etc.)

**Test 2: Raw .paac transition target patch → FAILED**
- Found the loaded .paac binary data in heap memory (region 0x3C0AE000000, 34MB)
- Identified 6,037 transition patterns matching [thresh 0-1.0, sentinel -1.0, target 0-720, seq 0-100]
- Patched 1,479 non-guard transitions (target > 50) to target guard (state 0)
- Guard still doesn't cancel attacks
- **Conclusion:** The game does NOT read transitions from the raw loaded .paac bytes. It deserializes them into runtime objects (the 92 ActionChartPackage instances). We patched the wrong copy.

**Test 3: MinHook on Themida-protected function → FAILED (confirmed)**
- RTTI scan correctly finds InputBlock's vfunc[3] at 0x141C8F760
- MinHook creates hook (MH_OK) and enables it (MH_OK)
- But the hook NEVER fires (blocked=0, bypassed=0 in all tests)
- x64dbg breakpoint at the same-ish address fires instantly (every frame)
- **Conclusion:** Themida CRC protection silently reverts MinHook's code patches. Code hooking is not viable for game functions.

### What We Know About the 92 ActionChartPackage Objects

These are the deserialized action chart state machines. Sample object layout:

```
+0x00: vtable pointer (0x144A6C610)
+0x04: u32 = 1 (always)
+0x08: zeros
+0x10: u32 = 1 or 2 or 17 (possibly layer type or chart type)
+0x14: u32 = 65537 (0x10001) or similar flags
+0x18: pointer (to some data)
+0x1C: u32 = 960 (0x3C0) — recurring value, possibly a type tag
+0x20: pointer
+0x24: u32 = 960
+0x28: pointer (sometimes zero)
+0x2C: u32 = 960 (when pointer is non-zero)
+0x30: u32 = small number (1, 2, 3, 9, 13, 21, 25, 29, 31) — paired with +0x34
+0x34: u32 = same as +0x30 (always matches)
+0x38: pointer
+0x3C: u32 = 960
+0x40: pointer
+0x44: u32 = 960
+0x48: u32 = varies (4, 6, 8, 9, 12, 17, 25, 43, 45, 51, 52, 96, 172, 182, 639) — paired with +0x4C
+0x4C: u32 = same as +0x48
+0x50: pointer
+0x54: u32 = 960
+0x58-0x7C: more pointer/count pairs or zeros
```

The paired values at +0x30 and +0x48 likely represent node/transition counts. **The object with +0x48 = 639 could be sword_upper** (the .paac has 617 marker states, 721 header count — 639 is in that range).

The pointers at +0x18, +0x20, +0x28, +0x38, +0x40, +0x50 likely point to arrays of parsed nodes, transitions, and conditions. **Following these pointers to find the actual transition arrays is the critical next step.**

### Tools and Scripts Created

All at `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\`:

| Script | Purpose |
|--------|---------|
| `find_inputblock.py` | Finds InputBlock instances by vtable, dumps fields |
| `find_objects.py` | Generic vtable-based object finder |
| `patch_inputblock.py` | Patches _inputBlockType on all instances |
| `patch_transitions.py` | Patches raw .paac transitions in memory |
| `scan_3way.py` | 3-state memory diff scanner (idle/attack/guard) |
| `scan_focused.py` | 4-round scanner with stable-idle filter |
| `monitor.py` / `monitor2.py` | Real-time address value monitor |
| `paac_parser.py` | .paac binary format parser |

### Viable Next Steps (Ranked)

**A. Follow ActionChartPackage pointers to parsed transitions (HIGHEST PRIORITY)**
The 92 ActionChartPackage objects contain pointers to the actual transition data the game reads. Steps:
1. Find the sword_upper object (likely the one with +0x48 = 639)
2. Follow its pointers (+0x18, +0x38, +0x50, etc.) to find arrays
3. Dump those arrays, look for transition-like structures
4. Patch the transition targets in the PARSED data (not raw .paac)

**B. Per-instance vtable shadowing**
Instead of MinHook (code patch), clone the InputBlock vtable to heap memory, replace vfunc[3] with our function pointer, then overwrite each InputBlock object's vtable pointer to point to our clone. This is a DATA write (vtable pointer is at +0x00 of each object, on the heap), not a CODE write. Themida shouldn't detect it.

**C. Hook ReadFile/NtReadFile to intercept .paac before parsing**
The game reads .paac files via system APIs. Hook ReadFile (system DLL, not Themida-protected), detect when sword_upper.paac is being read, patch the bytes before the game's parser sees them. This modifies the source data so the parser creates the objects we want.

**D. Page-guard VEH interception**
Set PAGE_GUARD on the memory page containing InputBlock's vfunc[3]. When the game calls it, a STATUS_GUARD_PAGE_VIOLATION exception fires. Our VEH handler intercepts it, checks if guard should bypass, and either skips or allows. No code bytes modified.

### Environment
- Python 3.13 (`py -3`), pymem installed
- Game running at PID varies per launch, base always 0x140000000
- CDControllerRemap ASI loaded, XInput hook working (detects guard=1, attacking=1)
- All heap writes confirmed working via WriteProcessMemory

### Key File Locations
- CDControllerRemap source: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDControllerRemap\src\dllmain.cpp`
- .paac analysis: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\paac_analysis.txt`
- Full original handoff: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\HANDOFF_PROMPT.md`
