# Progress Update 5 — Final State

## Critical Discovery: Combat Charts are Lazily Loaded

The sword_upper combat chart is **NOT persistently in memory**. It's:
1. Loaded from PAZ when combat starts (aggro an enemy)
2. Parsed into runtime objects
3. Raw .paac data AND path string are discarded after parsing
4. The parsed objects do NOT use `ActionChartPackage_BaseData` vtable (0x144A6C610)
5. When out of combat, the chart data may be unloaded entirely

**Evidence:**
- With weapon sheathed: 105-109 ActionChartPackage_BaseData instances, none named "sword_upper"
- After drawing weapon: same count, still no sword_upper
- After fighting enemy: `key_guard_start` string appears at 0x414555B4888 but belongs to `ride_upper`
- The string "1_phm/sword_upper" exists only in the `characteractionpackagedescription.paacdesc` mapping file, not as a loaded chart
- Raw .paac header (node_count=721, speed=1.333) not found anywhere in heap

## What This Means

The actual combat action chart evaluator uses a **different class hierarchy** than `ActionChartPackage_BaseData`. The 109 packages we found are supplementary charts (riding, climbing, fishing, torch, etc.). The core combat charts are managed differently — possibly:
- Inline within the `ActionChartPackageGroup` objects
- Using template classes without RTTI
- Stored as non-polymorphic structs embedded in component objects

## RTTI Class Hierarchy (from exe analysis)

5,366 total RTTI classes in the exe. Action-related:
- `ActionChartPackage_BaseData` — only used for supplementary charts
- `ActionChartPackageGroup` (8-10 instances) — likely contains/manages combat state
- `ActionChartPackageSet` (8-11 instances)
- `ClientCharacterControlActorComponent` (33-56 instances)
- `ClientSkillActorComponent` (81 instances)
- `ClientAttackActorComponent` (119 instances)
- `FrameEventAccessor` (49 instances)
- **NO** ActionChartEvaluator, ActionChartPlayer, ActionChartInstance, or similar runtime state class exists in RTTI

## All Approaches Tried and Results

| Approach | Result |
|----------|--------|
| XInput button suppression | No effect — state machine ignores |
| XInput dodge injection | No effect |
| QPC time burst | Rejected |
| MinHook on InputBlock vfunc[3] | Installs but never fires (Themida CRC) |
| InputBlock _inputBlockType patch | No effect (12 instances patched to 0xFF) |
| Raw .paac transition patch in heap | No effect (game reads parsed objects, not raw data) |
| Force-write combat flags on CharCtrl/PkgGroup | No effect (91K writes, flags are status indicators not locks) |
| ActionChartPackage_BaseData instance scan | Found 109 packages, none is sword_upper combat chart |
| ReadFile probe (raw .paac in memory) | Not found — parsed and discarded |
| Ghidra RTTI class hierarchy | No evaluator class exists |

## Remaining Viable Approaches

### 1. ReadFile/NtReadFile ASI Hook (IN CDControllerRemap)
Hook ReadFile at the system DLL level. When the game reads from 0010/0.paz (action chart PAZ), monitor the decompressed output for sword_upper.paac header bytes. Patch transitions in the buffer before the parser consumes them. This catches the data at load-time, before it's parsed and discarded.

**Challenge:** The PAZ read goes through LZ4 decompression. Need to hook after decompress, not after ReadFile.

### 2. Deep ActionChartPackageGroup Exploration
The 8-10 PackageGroup instances likely contain the combat evaluator. Scan beyond 1024 bytes (try 4-8KB). Follow ALL pointers to depth 2-3. Must be done DURING active combat.

### 3. VEH Page-Guard on PAZ File Buffer
When the .paac is loaded and parsed, it passes through a memory buffer. Set PAGE_GUARD on likely buffer regions. When the parser accesses the data, our exception handler fires, giving us the buffer address and call stack.

### 4. LZ4 Decompress Hook
The game uses LZ4 for PAZ decompression. LZ4 functions are in a DLL (possibly statically linked). If we can find and hook the LZ4 decompress function (which is NOT in Themida-protected code if it's from an external lib), we can intercept the decompressed .paac data.

## Key Addresses (This Session)
- ActionChartPackage_BaseData vtable: `0x144A6C610`
- ActionChartPackageGroup vtable: `0x144B37470`
- ActionChartPackageSet vtable: `0x144B37480`
- InputBlock vtable: `0x144AFCC70`
- Game base: `0x140000000`

## Files
- All scripts in `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\`
- Full RTTI dump: `C:\Users\faisa\.claude\projects\C--Users-faisa\36a4d1fe-fe0d-462b-b3bd-f64dbbc3d804\tool-results\bd32c3on2.txt`
- Ghidra project: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\GhidraProject\`
