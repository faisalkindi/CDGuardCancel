# Crimson Desert Animation Cancel Mod — Complete Handover Report

**Date:** March 24, 2026
**Goal:** When player presses LB (guard) during any attack animation, character instantly transitions to guard stance.
**Game:** Crimson Desert (PC/Steam Early Access)
**Engine:** BlackSpace Engine (Pearl Abyss proprietary)
**Protection:** Themida packer on executable

---

## Executive Summary

After an extensive reverse engineering and prototyping session, we proved that PAZ file patching works (game accepts modified data), identified the exact file and structure controlling combat transitions (sword_upper.paac), and narrowed the problem to one undecoded component: the **condition graph** — a 622KB proprietary bytecode section that controls when attack sub-states can transition to guard. All other approaches were systematically tested and ruled out.

---

## Game Architecture (Confirmed)

### Combat State Machine
- Defined in `.paac` (PA Action Chart) binary files inside PAZ archives
- Player sword combat: `actionchart/bin__/upperaction/1_pc/1_phm/sword_upper.paac` (1,243,769 bytes decompressed)
- Located in PAZ directory `0010/0.paz` at offset `225322576`, compressed size `224084` (LZ4, type 0x0002, no encryption)
- Header: 721 nodes, speed 1.3333
- String table: 45 labels including `key_guard`, `key_guard_start`, `key_norattack`, `key_hardattack`, `key_cancel`
- Animation paths: 428 `.paa` files (attack, guard, dodge, combo animations all present)

### .paac Internal Structure
```
Offset 0x00000000 - 0x00000043: Header (68 bytes) — node_count=721, speed=1.333, flags=0x800
Offset 0x00000044 - 0x0008E96A: State records (583,974 bytes) — 617 states with inline transitions
Offset 0x0008E9F3 - 0x0008ECB5: Label string table (45 entries)
Offset 0x0008ECB5 - 0x00095DE6: Animation paths (428 entries)
Offset 0x00095DE6 - 0x00097996: Extra string tables (effects, motionblending, bones, cameras)
Offset 0x00097996 - 0x0012FA79: CONDITION GRAPH (622,819 bytes) ← THE CRITICAL UNDECODED SECTION
```

### Two Types of Transitions
1. **Inline transitions** (in state records, offset 0x44-0x8E96A):
   - Format: `[float32 threshold] [float32 -1.0 sentinel] [uint32 target_state] [uint32 sequence]` (16 bytes each)
   - 150 states have inline transitions — **ALL already include guard (state 0) as a target**
   - 467 states have ZERO inline transitions

2. **Condition graph transitions** (offset 0x97996-0x12FA79):
   - 651 records of exactly 260 bytes each (identified by `4D 30 25 44` marker at +2)
   - Each record has a "bytecode" section at +0xE0 that varies per record
   - The byte at +0xE7 in each record appears to be an input key index
   - **This is what controls attack sub-state transitions — undecoded**

### Why Guard Doesn't Work During Attacks
The 467 attack sub-states (mid-combo animation phases) have their transitions ENTIRELY in the condition graph. The condition graph bytecode determines which inputs trigger which transitions and under what conditions. Guard is not listed as an allowed input for these states in the condition graph. Modifying inline transitions has zero effect on these states.

---

## What Was Tested (Comprehensive)

### Approach 1: XInput Button Manipulation
| Variant | Result |
|---------|--------|
| Suppress RB/RT when LB pressed | No effect — state machine ignores |
| Inject dodge (B) then guard (LB) | No effect |
| QPC time burst to fast-forward animation | Rejected as too hacky |

**Why:** The state machine doesn't have guard transitions from attack sub-states. No amount of button manipulation changes this.

### Approach 2: MinHook on Game Functions
| Target | Result |
|--------|--------|
| StageChart_Function_InputBlock vfunc[3] | Hook installs (MH_OK) but never fires |
| Multiple RVAs tried (0x1C880F0, 0x1C8F760) | Same result each time |

**Why:** Themida CRC protection silently reverts code patches in .sdata section.

### Approach 3: InputBlock Heap Object Patching
- Found 41 InputBlock instances on heap via vtable scan (vtable 0x144AFCC70)
- Object layout: vtable(+0x00), _inputBlockType(+0x18), _unsetOnSequencerControl(+0x20)
- _inputBlockType values: 0, 1, 3, 4, 5, 8
- Patched ALL instances to 0xFF
- **Result: No effect.** InputBlock controls menu/cutscene input blocking, not combat guard blocking.

### Approach 4: Raw .paac Heap Patching
- Found raw .paac bytes loaded in heap (34MB region)
- Identified 6,037 transition patterns in the region
- Patched 1,479 non-guard transitions to target guard (state 0)
- **Result: No effect.** Game reads from deserialized runtime objects, not raw file bytes.

### Approach 5: Component Field Force-Write
- Found all player-facing RTTI components: CharacterControl (56), Skill (81), Attack (119), PackageGroup (10), PackageSet (11), Input (58)
- Monitored 51,983 u32 fields across idle/attack/guard phases
- Top scorer: CharCtrl[1]+0x1F4 (idle=1, attack=[0,1,256], guard=1)
- Force-wrote idle values to all combat-correlated fields at 120Hz (91,584 writes)
- **Result: No effect.** These are status flags, not combat locks.

### Approach 6: Runtime ActionChart Object Search
- Found 92-133 ActionChartPackage_BaseData instances (vtable 0x144A6C610)
- Identified sword_upper by name: type=3, 45 strings, 428 animation paths
- **Critical finding: sword_upper is LAZILY LOADED** — only exists during active combat, unloaded after
- Found 5 objects referencing the package (2 vtable types: 0x1447467F8, 0x144C0D320)
- Monitored all their fields during combat — no state ID changes found
- **Conclusion:** Runtime state is deeper in the chain (behind 2+ pointer dereferences) or in a non-RTTI class

### Approach 7: PAZ File Patching (PARTIALLY SUCCESSFUL)
- **Proven: Game accepts modified PAZ files** — no integrity check, no crash
- Modified inline transitions in sword_upper.paac, compressed to exact 224084 bytes via LZ4
- First attempt (with compensator hacks): **crashed** — compensator changes corrupted data
- Second attempt (11 clean patches, no compensators): **no crash, but no behavior change**
- **Why no change:** Patched inline transitions in states that use the condition graph exclusively

### Approach 8: Memory Scanning (Cheat Engine + pymem)
- Scanned 600MB+ of game memory across idle/attack/guard states
- 3-way scan, 4-way scan, focused monitoring of top candidates
- No address cleanly tracks the action chart state (all candidates were noisy flags/counters)
- **Why:** The state is likely stored behind multiple pointer dereferences in an unknown object

### Approach 9: Ghidra RTTI Analysis
- Imported 381MB exe into Ghidra
- Extracted 5,366 RTTI class names
- **No ActionChartEvaluator, ActionChartPlayer, or similar runtime state class exists in RTTI**
- The runtime evaluator is either a template class, inline struct, or non-polymorphic

---

## What IS Proven to Work

1. **PAZ file patching** — game loads modified PAZ without integrity checks
2. **LZ4 recompression** — can produce exact-size compressed output for clean single-byte changes
3. **pymem heap read/write** — can find and modify any game object on the heap
4. **RTTI vtable scanning** — can find any RTTI class instance in the live process
5. **CDControllerRemap XInput hook** — detects guard=1 and attacking=1 reliably
6. **System DLL hooking** — kernel32, xinput, d3d12 hooks all work (Themida-safe)

---

## The Remaining Path

### Primary: Decode the Condition Graph
The 622KB condition graph at offset 0x97996 in sword_upper.paac contains the bytecode that controls attack sub-state transitions. Partial analysis exists:

- 651 records of 260 bytes each
- Record marker: `4D 30 25 44` at +2 within each record
- Fixed structure: vtable-like pointer at +0x18, state reference at +0x1C, -1.0 sentinels at fixed offsets
- **Bytecode at +0xE0 (24 bytes)** varies per record — this is the transition condition expression
- Byte +0xE7 histogram: 0x09(226), 0x04(199), 0x03(143), 0x01(38), 0x00(42) — likely input key index
- The dominant pattern: `01 00 02 29 05 0B 0C [KEY] 00 [PARAM] 01 02 05 FF FF 00 00 FF 03 05 04 00 00 00`

If the bytecode can be decoded enough to:
1. Identify which records belong to attack sub-states
2. Find the "allowed input key" field
3. Change it to include key_guard (index 0 or 1)

Then PAZ file patching (proven working) would deliver the mod.

### Secondary: ReadFile Intercept
Hook kernel32 ReadFile in CDControllerRemap. When the game reads sword_upper's compressed data from the PAZ:
1. Let the original read complete
2. Decompress the buffer
3. Patch the condition graph in the decompressed data
4. Recompress (size doesn't matter since we control the buffer passed to the game's LZ4 decompressor)

Challenge: the game reads compressed data into a buffer, then calls statically-linked LZ4 decompress. We'd need to either hook the decompress (not possible — statically linked, Themida-protected) or replace the compressed buffer with uncompressed data and somehow bypass the LZ4 step.

### Tertiary: VEH Page-Guard
Set PAGE_GUARD on the ActionChartPackage memory pages. When the game's evaluator reads transition data, the exception handler fires. Walk the call stack to find the evaluator object and its current state field. Then force-write the guard state.

---

## Key Addresses (Session-Specific — Rediscover Each Run)

| Item | Method to Find |
|------|---------------|
| sword_upper ActionChartPackage | Scan heap for ACPKG vtable, follow +0x18 pointer for name containing "sword_upper" |
| ActionChartPackage_BaseData vtable | RTTI scan for `.?AVActionChartPackage_BaseData@pa@@` |
| InputBlock vtable | RTTI scan for `.?AVStageChart_Function_InputBlock@pa@@` |
| InputBlock instances | Scan heap for InputBlock vtable pointer |
| Game base | Always `0x140000000` |

**Note:** Vtable addresses change between game updates. ALWAYS rediscover via RTTI, never hardcode.

---

## File Inventory

### Source Code
```
C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\
├── CDControllerRemap\          — Working ASI mod (XInput hook, D3D12 texture injection)
│   └── src\dllmain.cpp         — Contains AnimCancel integration (InputBlock hook, state tracking)
├── CDAnimCancel\               — Standalone analysis + scripts
│   ├── src\dllmain.cpp         — Various ASI attempts (v0.1-v1.0)
│   ├── tools\
│   │   ├── paac_parser.py      — .paac binary format parser
│   │   └── paac_analysis.txt   — Full format analysis (1368 lines)
│   ├── extracted\              — Extracted .paac and .paatt files from PAZ
│   ├── extracted_xml\          — Decrypted game XML configs
│   ├── mod_test\               — Modified .paac files and compressed outputs
│   ├── find_inputblock.py      — Finds InputBlock heap instances
│   ├── find_objects.py         — Generic vtable-based object finder
│   ├── find_player_chart.py    — Finds ActionChartPackage by name
│   ├── step1_find_owner.py     — Finds objects referencing sword_upper
│   ├── step4_monitor_owners.py — Monitors owner object fields during combat
│   ├── step4b_topdown.py       — Top-down component field monitoring
│   ├── step5_force_write.py    — Force-writes idle values to combat fields
│   ├── scan_3way.py            — 3-state memory diff scanner
│   ├── scan_focused.py         — 4-round scanner with stable-idle filter
│   ├── readfile_probe.py       — Searches for .paac header in live memory
│   ├── monitor.py / monitor2.py — Real-time address value monitors
│   ├── patch_inputblock.py     — Patches _inputBlockType on heap instances
│   ├── patch_transitions.py    — Patches raw .paac transitions in heap
│   ├── HANDOFF_PROMPT.md       — Original handoff document
│   ├── PROGRESS_UPDATE_*.md    — Progressive status updates (1-5)
│   └── FINAL_STATUS.md         — Final status summary
├── PAZUnpacker\                — PAZ extraction tools
│   ├── paz_extract.py          — Full PAZ extractor (PAMT parser + LZ4 + ChaCha20)
│   └── RESEARCH.md             — PAZ/PAMT format documentation
├── crimson-desert-unpacker\    — lazorr's tools (ChaCha20 decrypt, LZ4 decompress, PAZ repack)
├── CDInputMapper\              — Heap object discovery via stack frame scanning
├── CDHideHeadgear\             — Signature scan + probe hooks (reference for Themida workarounds)
├── HurryTheFUp\                — QPC hook pattern (reference)
└── GhidraProject\              — Ghidra project with imported CrimsonDesert.exe
```

### Game Files
```
E:\SteamLibrary\steamapps\common\Crimson Desert\
├── 0010\
│   ├── 0.paz                   — Action chart PAZ archive (sword_upper at offset 225322576)
│   └── 0.paz.bak               — Backup of original (RESTORE IF CORRUPTED)
├── bin64\
│   ├── CrimsonDesert.exe       — 381MB, Themida-packed
│   ├── CrimsonDesert_dump.bin  — 542MB memory dump (WARNING: outdated RVAs)
│   ├── CrimsonDesert_dump.map  — Memory region map
│   ├── CDControllerRemap.asi   — Working controller remap mod
│   └── CDControllerRemap.ini   — Config (has [AnimCancel] section)
```

### Tools Installed
- Python 3.13 (`py -3`), pymem, lz4, capstone
- Visual Studio 2022 Build Tools + CMake
- MinHook (via CMake FetchContent)
- x64dbg: `C:\Users\faisa\Ai\Tools\x64dbg\release\`
- Ghidra 12.0.4: `C:\Users\faisa\Ai\Tools\ghidra_12.0.4_PUBLIC\`
- Cheat Engine: installed

### Build Commands
```bash
# CDControllerRemap
CMAKE="C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
$CMAKE --build "C:/Users/faisa/Ai/Mods Dev/CrimsonDesert-Mods/CDControllerRemap/build" --config Release
```

---

## Critical Knowledge for Next Developer

1. **Themida blocks ALL code patches** — MinHook installs but hooks silently fail. Only system DLL hooks work.
2. **PAZ files have NO integrity check** — game loads modified PAZ data. This is the proven delivery mechanism.
3. **LZ4 compressed size must match exactly** — in-place PAZ patching requires finding modifications that compress to the original byte count. Single clean changes work; bulk changes need size-neutral combinations.
4. **sword_upper.paac loads lazily** — only exists in memory during active combat with an enemy. Scans must happen while fighting.
5. **The condition graph is the key** — 622KB of bytecode at offset 0x97996 controls all attack sub-state transitions. Decoding this is the path to the mod.
6. **ActionChartPackage_BaseData is NOT the combat chart class** — the 109 instances found are supplementary charts (riding, fishing, climbing). The actual combat evaluator uses an unknown class hierarchy with no RTTI.
7. **GetModuleHandleA("CrimsonDesert.exe") returns NULL** from ASI context — always use GetModuleHandleA(NULL) or hardcode base 0x140000000.
8. **Memory dump RVAs don't match live process** — always rediscover addresses via RTTI at runtime.
9. **The user has a custom button remap** — X=RB (light attack), Y=RT (heavy attack), A=B (dodge), LB=guard unchanged.
10. **CDControllerRemap is the integration point** — it's the only ASI that successfully sees button presses via XInput hook.
