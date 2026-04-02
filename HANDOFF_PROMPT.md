# Crimson Desert Animation Cancel Mod — Full Context Handoff

## Goal
Create a mod for Crimson Desert (PC/Steam) that makes guard (LB on controller) instantly cancel any attack animation. When the player presses LB mid-attack, the character should immediately transition to guard/block stance — no waiting for the animation to finish.

## Game Details
- **Game:** Crimson Desert (Early Access, Steam)
- **Engine:** BlackSpace Engine (Pearl Abyss proprietary, NOT Unreal)
- **Protection:** Themida packer on the executable
- **Executable:** `E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert.exe`
- **Player character:** Kliff (sword & shield)
- **Input:** XInput (controller only, Steam Input must be disabled)
- **Existing mod infrastructure:** Ultimate ASI Loader (winmm.dll) + MinHook + CDControllerRemap ASI that successfully hooks XInputGetState and sees all button presses

## What We Know For Certain

### Combat State Machine (.paac files)
- Combat actions are defined in binary `.paac` (PA Action Chart) files
- `sword_upper.paac` (1.2MB) has 718 states with transitions between them
- State 0 = guard (key_guard), transitions exist from all base states to guard
- 467 attack sub-states have NO inline guard transitions — their transitions are in a 622KB "condition graph" section (proprietary bytecode, undecoded)
- The game already supports dodge cancel and parry cancel during attacks (confirmed by game reviews)
- Input keys in the state machine: key_guard, key_guard_start, key_norattack, key_hardattack, key_cancel, key_dash

### RTTI Classes Found (in live process)
- `StageChart_Function_InputBlock` — controls input blocking during animations
  - vtable at `0x144AFCC70`
  - Has `_inputBlockType` property
- `ActionChartPackage_BaseData` — the action chart data container
  - vtable at `0x144A6C610`
- `ClientInputActorComponent` — processes player input
- `ClientFrameEventTimerAttack` / `ClientFrameEventAttack` — attack frame events
- 5,947 total RTTI classes in the binary

### Code Vein 2 Parallel (same developer built a similar mod)
For Code Vein 2 (Unreal Engine), the same user created a "DefensiveCancel" mod that worked by:
- Renaming ability tags from `Ability.ActiveAction.Dodge` to `Ability.DefensAction.Dodge` in binary uasset files
- Attacks block `ActiveAction` tag; renamed defensive abilities bypass the block
- Pure data modification, no code hooking
- Source at: `C:\Users\faisa\Ai\Mods Dev\CodeVein2-Mods\DefensiveCancel_v4\`

### What Other Games Do (from research)
1. **Dark Souls / Elden Ring:** Modify TAE (TimeAct Events) in animation files to add cancel windows, or use Cheat Engine to find animation state ID and overwrite it
2. **Monster Hunter World:** Write action IDs to memory at runtime
3. **FF16:** Edit database tables controlling cancel window timing
4. **BDO (same engine family):** Animation canceling is built-in; uses action chart system with cancel transitions

## What Was Tried and FAILED

### 1. XInput Button Manipulation (multiple approaches)
- Suppressing attack buttons (RB/RT) when guard (LB) pressed → game state machine ignores it, animation continues
- Injecting dodge button (B) to cancel then guard → didn't work
- QPC time burst to fast-forward animation → rejected as hacky

**Why it fails:** The state machine simply doesn't have guard transitions from attack sub-states. No amount of button manipulation changes the state machine's transition table.

### 2. Hooking InputBlock Function via MinHook
- Found `StageChart_Function_InputBlock::vfunc[3]` via RTTI in live process
- MinHook creates hook successfully (MH_CreateHook returns MH_OK)
- MinHook enables hook successfully (MH_EnableHook returns MH_OK)
- **But the hook NEVER fires** (blocked=0, bypassed=0 in all tests)
- Tested with hardcoded RVA and with dynamic RTTI discovery — same result

**Why it fails:** Themida's CRC protection detects code modifications in the .sdata section and silently restores the original bytes. MinHook patches the function entry point, but Themida's background CRC thread undoes it. This is confirmed by the research finding that direct game function patching doesn't work for Themida-protected games.

### 3. Separate ASI Mod
- Created CDAnimCancel.asi as a standalone mod
- Hooked XInputGetState but `btn=0x0000` (never saw button presses)
- CDControllerRemap's hook works but the separate ASI's doesn't — hook ordering issue

**Why it fails:** When two ASIs hook the same function, the second one may not see correct data due to MinHook trampoline chaining.

### 4. Cheat Engine / Memory Scanning
- Scanned ~600MB of game memory across idle/attack/guard states
- Found 106K+ addresses that changed between states
- Monitored top 8 candidates in real-time — all were noise (counters, floats, flags), none tracked the action chart state cleanly
- Value 868/869 appeared frequently but is likely a global action mode flag, not the specific state index

**Why it's incomplete:** The state ID might not be stored as a simple integer. It could be a pointer, an enum, part of a larger structure, or updated at a frequency that our 30ms polling missed.

## Files and Tools Available

### Source Code
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDControllerRemap\` — working ASI mod with XInput hook (THE place to integrate any solution)
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\` — standalone attempt (failed, but has analysis tools)
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDInputMapper\` — found input object on heap via stack frame scanning
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\HurryTheFUp\` — QPC hook (working)
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDHideHeadgear\` — signature scan approach

### Analysis Results
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\paac_analysis.txt` — full .paac format analysis (1368 lines)
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\paac_parser.py` — .paac binary parser
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\` — extracted .paac and .paatt files
- `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted_xml\` — decrypted game XML configs

### Game Data
- PAZ archives at `E:\SteamLibrary\steamapps\common\Crimson Desert\`
- PAZ extractor: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\PAZUnpacker\paz_extract.py`
- ChaCha20 decryption: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\crimson-desert-unpacker\`
- PAZ repacker: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\crimson-desert-unpacker\python\paz_repack.py`
- Memory dump: `E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.bin` (542MB, WARNING: may be outdated — live process has different RVAs)

### Tools Installed
- Python 3.13 (use `py -3`), pymem installed
- Visual Studio 2022 Build Tools + CMake
- MinHook (fetched via CMake FetchContent)
- x64dbg at `C:\Users\faisa\Ai\Tools\x64dbg\`
- Ghidra 12.0.4 at `C:\Users\faisa\Ai\Tools\ghidra_12.0.4_PUBLIC\`
- Cheat Engine installed
- Capstone disassembler (Python)

## Key Constraints
- **Themida blocks code patching** — any writes to executable code in .sdata section are detected and reverted by CRC checks
- **Data writes ARE safe** — writing to heap/stack/data memory is not detected
- **XInput hooking works** — CDControllerRemap proves this; it's the integration point for any solution
- **System DLL hooking works** — kernel32, xinput, d3d12 hooks all work fine
- **The user has a custom button remap** — X=RB (light attack), Y=RT (heavy attack), LB=guard unchanged
- **Must feel instant** — no visible delay between LB press and guard activation

## Unexplored Approaches to Consider

1. **PAZ data patching** — Modify sword_upper.paac to add guard transitions to attack sub-states. 32 transitions were identified as replaceable (change target uint32 from original to 0). The .paac can be repacked into PAZ. Risk: the condition graph bytecode also needs updating.

2. **Decode the condition graph** — The 622KB condition graph has 260-byte repeating records with a bytecode section. If decoded, we could modify the conditions that gate guard transitions during attacks. Partial analysis exists in paac_analysis.txt.

3. **Themida CRC bypass** — Tools like Themidie2 bypass Themida's anti-debug. A VirtualAlloc-based CRC bypass feeds unmodified code to CRC checks while actual code is patched. This would allow MinHook to hook game functions.

4. **D3D12 command list hooking** — CDControllerRemap already hooks D3D12 CopyTextureRegion. Maybe we can intercept the animation update through D3D12 draw calls.

5. **Runtime object discovery** — CDInputMapper found the input object via stack frame scanning from XInputGetState. A similar technique could find the ActionChart instance and its current state field. Then write the guard state value when LB is pressed.

6. **Lua/Script injection** — BDO uses Lua internally (confirmed by RE). Crimson Desert may too. If a Lua scripting layer exists, it might provide a cleaner API for forcing state transitions.

7. **Hardware breakpoints** — Instead of MinHook code patching (which Themida detects), use VEH (Vectored Exception Handler) + hardware debug registers to intercept function calls without modifying code bytes. This is how CDControllerRemap's KeyGuide patcher works (see CDControllerRemap_kgpatch.log).

8. **Hook the vtable pointer itself** — Instead of patching function code, overwrite the vtable entry (which is in writable .data memory, not protected .sdata code). When the game calls vfunc[3] via the vtable, it would call our function instead.

## Memory Bank References
- `C:\Users\faisa\.claude\projects\C--Users-faisa\memory\project_cd_animation_cancel.md`
- `C:\Users\faisa\.claude\projects\C--Users-faisa\memory\MEMORY.md` (has entries for all CD mods)
- `C:\Users\faisa\Ai\.memory-bank\codevein2-modding\` (Code Vein 2 mod approach)
