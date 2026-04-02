# Guard Cancel During Attacks — Full Research Document

**Author:** kindiboy  
**Date:** March 20 - April 1, 2026  
**Game:** Crimson Desert (PC/Steam Early Access)  
**Engine:** BlackSpace Engine (Pearl Abyss proprietary)  
**Protection:** Themida + Denuvo on executable

---

## What I'm Trying to Do

Press LB (guard/block) during any sword attack animation and have Kliff immediately transition to guard stance, cancelling the attack. The game already lets skills cancel attacks — guard should be able to do the same thing.

---

## What I Know About the Combat System

I've spent about a week reverse engineering the combat internals. Here's everything I found.

### The Action Chart Format (.paac files)

Combat actions live in binary `.paac` files inside PAZ archives. The one that matters is `sword_upper.paac` — it's 1.2MB decompressed, sitting in `0010/0.paz` at offset 225322576, LZ4 compressed to 224084 bytes.

The file breaks down like this:

```
Offset 0x00000000 - 0x00000043: Header (68 bytes) — 721 nodes, speed 1.333
Offset 0x00000044 - 0x0008E96A: State records (~584KB) — 617 states with inline transitions  
Offset 0x0008E9F3 - 0x0008ECB5: String table — 45 labels (key_guard, key_norattack, etc.)
Offset 0x0008ECB5 - 0x00095DE6: Animation paths — 428 .paa files
Offset 0x00095DE6 - 0x00097996: Extra string tables
Offset 0x00097996 - 0x0012FA79: CONDITION GRAPH — 622KB of proprietary bytecode
```

### Two State Formats

I found two distinct state formats in the file, both sharing the `4D 30 25 44` magic marker:

**Format A — Attack states** (~400-600 bytes each): These have a 21-byte header, inline transitions (16 bytes each: `[f32 threshold][f32 sentinel=-1.0][u16 target][u16 pad][u32 seq]`), timeline cancel entries after an `FF FF FF FF FF FF` separator, and animation blend triplets. Attack states use timeline entries for skill cancels but have NO guard support.

**Format B — Guard/combat states** (~2000 bytes each): These have a 24-byte header with hash fields and a flags byte (0xF1), an input condition table around +0x150, the same transition format, and crucially — **guard sub-blocks**: 3 x 88 bytes with FF*8 separators, timing windows, and sentinels. These are the actual guard mechanism.

Out of 51 Format B states, 50 have guard sub-blocks. The one that doesn't is State 328 — the combo hub at 42,865 bytes.

### The 3-Layer Guard Block System

I identified three layers that control whether guard works:

**Layer 1 — Branchset** (`common_upper_branchset.paac`, 165KB): Every weapon .paac references this as string table entry 0. It routes `key_*` inputs to the action chart. `key_guard` is the ONLY input with a type-182 conditional gate — all skill keys route unconditionally. I built a 10-byte LZ4 literal patch that removes the guard gate. Game loads fine with it, but it's not sufficient alone.

**Layer 2 — Timeline entries**: These handle skill cancels during attacks. Guard does NOT use this system at all. I added `key_guard` to 25 attack state timelines via PAZ-shift — zero effect, because guard doesn't work through timelines.

**Layer 3 — Guard sub-blocks**: The 3x88-byte structures are the actual guard mechanism. They only exist in Format B states. Attack states are Format A — no structural support.

### Why Skills Cancel Attacks But Guard Doesn't

Skills work through: timeline entry -> transition lookup -> state change  
Guard works through: guard sub-blocks -> separate activation path

Two completely different systems. That's why adding `key_guard` to timelines does nothing.

### The Condition Graph

The 622KB condition graph at offset 0x97996 contains 651 records of exactly 260 bytes each. Partial decode:

- `+152` = target transition/state ref
- `+212` = source state/node id  
- `+216` = label index (references string table)
- `+224` = opcode
- `+229:232` = condition params
- Bytecode at `+0xE0` (24 bytes) varies per record

The dominant family has target=13001, opcode=0x2902, params=(9,0,15). I built 7 single probes and 3 combo probes targeting this family, deployed them to the live game via PAZ patching. Every single one returned no behavioral signal. The condition graph byte[216] label field appears to not be deserialized by the runtime.

---

## The Cheat Engine / Runtime Investigation

Before going full data-driven, I spent 2 days on runtime RE.

### CE Findings

- Guard action ID = 434 (0x1B2)
- Two write paths: +2FE2B1 writes 434 when guard is allowed (from idle), +29C6614 writes 0 when blocked (during attacks)
- TLS flag check at +29C65FE controls which path runs
- The guard block happens UPSTREAM — the action evaluator never even receives a guard request during attacks

### External Injector Testing (WriteProcessMemory)

Using 0xNobody's technique:
- Code cave safe passthrough at +29C6614: NO CRASH — proves the cave mechanism works
- Force R13d = 434 during attacks: CRASH — invalid value in attack context
- Skip the blocked write: CRASH — game expects the write
- 1-byte patch je->jmp at +29C6602: no crash, but no guard either (wrong jump direction)

### The Guard Activation Function (from FearLess CE forum)

A CE table maker named Send found and disassembled the guard activation function. Here's what it does:

**Function at +2712330:**
1. Reads current state byte from `[rbx+6A]`, saves backup to `[rbx+69]`
2. Reads `ebp = [rbx+48]` — this is the transition candidate count
3. Loops `ebp` times, calling an **evaluator function at +2712090** for each candidate
4. If evaluator returns `al=1`: stores winning candidate index in `sil`
5. After loop: if `sil != 0xFF`, activates the transition:
   - `imul rcx, rax, 0xD0` — each candidate is 0xD0 (208) bytes
   - Indexes into an array at `[rbx+40]`
   - Writes `sil` to `[rbx+68]` (current state slot)
   - Sets `[rbx+6A] = 1` (active flag)
   - Calls the transition handler at +2712670
6. If `sil == 0xFF` (no candidate won): timer path runs, eventually resets `[rbx+68] = 0xFF` and `[rbx+6A] = 0`

**Key writes to [rbx+6A]:**
- `+271259C`: `mov byte ptr [rbx+6A], 01` — guard activated
- `+271262E`: `mov [rbx+6A], r13b` — guard deactivated

### The Missing Piece: +2712090

The evaluator at +2712090 is the function that decides "is this transition allowed right now?" It returns al=0 during attacks (block guard) and al=1 during idle (allow guard). I asked Send to step into it, but they provided the wrong function (+270FB30, the input type validator). My follow-up asking for the correct function is still unanswered.

**I also asked Send about a second evaluator.** The function at +270FB30 turned out to be just the input validator — it always returns true for valid gamepad keys. The actual combat blocking is in the evaluator at +2712090 (called via +27123E6 in the guard function). The call pattern is: `movaps xmm1,xmm6 / mov [rsp+20],rcx / mov rcx,rbx / call <target>`.

---

## Full List of Everything I Tried

### Data-Driven (PAZ file modifications)

1. Inline transition patches — add target=0 (guard) to 2 attack states -> No effect
2. Inline transition patches — 26-state PAZ-shift deploy -> Crashed (hashlittle bug)
3. Condition graph probes — patch byte[216] label index -> All returned no_signal
4. Branchset gate removal (10 LZ4 literal bytes) -> Safe, no effect alone
5. Timeline key_guard added to 25 Format A attack states via PAZ-shift -> No effect
6. Timeline + branchset combined -> No effect
7. LZ4 literal chain patching on compressed stream -> Works for byte changes, 12 states patched
8. Timeline key change in State 328 (Format B combo hub) via LZ4 -> No effect
9. Timeline + transition target change combined via LZ4 -> No effect
10. Insert 264 bytes guard sub-blocks into State 328 at +0xA719 -> Corrupts state
11. Overwrite guard blocks at +0x104E in State 328 -> Corrupts save load
12. Overwrite at +0xA619 (effect string refs) -> Corrupts file load
13. Append State 7 (complete guard state) to end of file -> No effect, nothing references it
14. Replace SubPackage — swap content with dualsword_upper -> Guard still doesn't fire
15. Condition graph cluster probes — 4 single probes tested live -> All no_signal
16. Condition graph cluster bundles — 2 bundles tested live -> All no_signal

### Runtime (ASI / Injector / Memory)

17. XInput button suppression (RB/RT when LB pressed) -> No effect
18. XInput dodge injection -> No effect
19. MinHook on InputBlock vfunc[3] -> Installs but never fires (Themida CRC)
20. InputBlock _inputBlockType heap patch (41 instances to 0xFF) -> No effect
21. Raw .paac transition patch in heap (1,479 transitions) -> No effect
22. Component field force-write (91,584 writes at 120Hz) -> No effect
23. ActionChartPackage_BaseData instance scan -> Found 109, none is sword_upper
24. Code cave at +29C6614, force R13d=434 -> CRASH
25. Code cave at +29C6614, skip blocked write -> CRASH
26. Code cave at +29C6614, safe passthrough -> No crash, proves cave works
27. 1-byte je->jmp at +29C6602 -> No crash, no guard (wrong direction)
28. 3-gate patch at +AD4F00 (NOP+NOP+JMP) -> No effect, function never called
29. InputBlockFromCode flag search -> Pattern not found
30. Capture cave at +2B0960 + XInput guard injection -> Wrong function (bounds checker, 139M calls)
31. Evaluator je->jmp at +29C6602 -> Always-blocked (wrong direction)
32. Evaluator NOP at +29C6602 -> CRASH, always-allowed breaks all actions
33. Evaluator call B->A redirect -> No effect
34. Memory scanning (600MB+, 3-way and 4-way scans) -> No clean state tracking address found
35. Ghidra RTTI analysis (5,366 classes) -> No ActionChartEvaluator exists in RTTI

---

## What Actually Works (Proven)

- **PAZ file patching** — game loads modified PAZ data, no integrity check
- **LZ4 recompression** — can produce exact-size output for single-byte changes  
- **WriteProcessMemory** — bypasses Themida CRC from external process
- **Code caves** — working cave at +2712580 fires correctly (mov [rbx+68], sil)
- **XInput hooking** — CDControllerRemap detects guard/attack buttons reliably
- **System DLL hooks** — kernel32, xinput, d3d12 all work (Themida-safe)
- **RTTI vtable scanning** — can find any RTTI class instance in live process
- **pymem heap read/write** — works for any game object

---

## Where I'm Stuck

The evaluator function at **+2712090** is the gate. It gets called in a loop for each transition candidate and returns 0 to block or 1 to allow. During attacks it returns 0 for guard. I need to either:

1. **See inside that function** — get a decompiled/disassembled view of +2712090 to find the specific check that says "you're attacking, block guard." Then patch that one check.

2. **Hook it with SafetyHook** — intercept the function at runtime and override al=1 specifically for guard transitions during attacks. This is the same pattern Orcax-1399 uses in player-status-modifier for stat write interception.

3. **VEH + hardware breakpoints** — set a hardware breakpoint on +2712090 without modifying code bytes (bypasses Themida CRC). Read the registers and call stack to understand what's happening.

The guard activation function (+2712330) is fully mapped. The evaluation loop, the candidate array at [rbx+40] with 0xD0-byte entries, the state slot write at [rbx+68], the active flag at [rbx+6A] — all of that is understood. The ONE thing missing is what happens inside +2712090 when it decides to return 0.

### AOB Pattern to Find the Evaluator Call

If addresses have shifted after a game update, search for these bytes to find the evaluation loop:

```
0F 28 CE 48 89 4C 24 20 48 8B CB E8
```

That's `movaps xmm1,xmm6 / mov [rsp+20],rcx / mov rcx,rbx / call <target>`. The 4 bytes after E8 are the relative offset to the evaluator function.

---

## Important Gotchas

- **Themida blocks ALL code patches in .sdata** — MinHook installs (MH_OK) but hooks silently never fire. Only system DLL hooks and WriteProcessMemory from external process work.
- **sword_upper.paac loads lazily** — only in memory during active combat. Any scanning has to happen while fighting an enemy.
- **ActionChartPackage_BaseData is NOT the combat chart class** — those 109 instances are supplementary charts (riding, fishing, etc.). The actual combat evaluator uses unknown non-RTTI classes.
- **GetModuleHandleA("CrimsonDesert.exe") returns NULL** from ASI context — use GetModuleHandleA(NULL) instead.
- **Memory dump RVAs don't match live process** — always rediscover via RTTI at runtime.
- **Steam Input must be disabled** before testing XInput hooks.
- **Guard action ID is 434** (0x1B2).
- **hashlittle bug** — the commonly used hashlittle (Bob Jenkins lookup3) implementation has a subtle bug that breaks PAZ-shift for directory 0010. The correct implementation is in crimson-desert-unpacker's paz_crypto.py.
- **BDO tools don't work** on Crimson Desert despite same studio.
- **Inventory max slots above 240 cause array overflow crash.**

---

## Key Addresses (These Shift Between Game Updates — Use AOB to Rediscover)

| What | Address (March 2026 build) | How to Find |
|------|---------------------------|-------------|
| Guard activation function | +2712330 | AOB: `48 8B C4 48 89 58 10 48 89 68 18 48 89 70 20 57 41 54 41 55 41 56 41 57 48 83 EC 60` |
| Evaluator (THE gate) | +2712090 | Called from +27123E6. AOB for call site: `0F 28 CE 48 89 4C 24 20 48 8B CB E8` |
| Guard activated write | +271259C | `C6 43 6A 01` (mov byte ptr [rbx+6A], 01) |
| Guard deactivated write | +271262E | `44 88 6B 6A` (mov [rbx+6A], r13b) |
| State slot write | +2712580 | `40 88 73 68` (mov [rbx+68], sil) — working code cave here |
| Input validator (NOT the gate) | +270FB30 | Different function — always returns true for valid keys |
| Game base | 0x140000000 | Always |

---

## Tools and Files Available

All of my research, scripts, extracted files, parsers, and tools are available. I'm happy to share everything with anyone who wants to collaborate.

- .paac binary format parser (Python)
- PAZ extractor with PAMT parser, LZ4, ChaCha20
- Condition graph analysis tools
- Branchset decoder
- Memory scanning scripts (pymem)
- RTTI vtable scanner
- Multiple ASI mod source files (C++, CMake)
- Full .paac format documentation (1368 lines of analysis)
- Extracted and decrypted game XML configs
- Probe test deployment pipeline with automated PAZ patching

If you can help crack open that evaluator function, or if you have BDO .paac experience that might shed light on the guard sub-block mechanism, I'd love to hear from you. Full credit shared on the released mod.
