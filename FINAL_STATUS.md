# Final Status — All Approaches Exhausted in This Session

## What Works
- PAZ file patching is accepted by the game (no integrity check, no crash with clean patches)
- We can modify inline transitions and the game loads the modified data
- pymem read/write to game heap works
- RTTI vtable scanning works in live process
- CDControllerRemap XInput hook detects guard/attack buttons

## What Doesn't Work and Why

### Inline transition patching → NO EFFECT
- 150 states have inline transitions — ALL already include guard (state 0)
- 467 attack sub-states have ZERO inline transitions
- 79 "guardless" states we patched use the CONDITION GRAPH for their actual transitions
- The condition graph (622KB binary, proprietary bytecode) is what controls attack sub-state transitions
- **Conclusion: inline transitions are irrelevant for attack sub-states**

### Condition graph patching → NOT FEASIBLE
- 622KB of undecoded bytecode
- 260-byte repeating records identified but field meanings unknown
- Would need full reverse engineering of the bytecode interpreter

### Runtime object patching → OBJECT NOT FOUND
- sword_upper combat chart does NOT use ActionChartPackage_BaseData class at runtime
- It's lazily loaded during combat and uses an unknown class hierarchy
- The parsed runtime objects have no RTTI entry we can scan for

### Code hooking → BLOCKED BY THEMIDA
- MinHook installs but hooks never fire (CRC protection)

## The Remaining Path

The only unexplored viable approach is **decoding the condition graph**. The 622KB section at the end of sword_upper.paac contains 260-byte records that define transition conditions. Each record has:
- A bytecode section at +0xE0 that varies per record
- Fixed structural elements (-1.0 sentinels, float thresholds)
- References to input keys (the byte at +0xE7 maps to input key indices)

If we can decode just enough of the bytecode to understand:
1. Which records belong to attack sub-states
2. Where the "allowed input" field is
3. How to add "key_guard" as an allowed input

Then we could patch the condition graph in the .paac file (using the proven PAZ patching pipeline) and the game would load it.

## Alternative: Runtime ReadFile Intercept
Hook ReadFile (kernel32) to detect when the game reads sword_upper from PAZ. After the read but before parsing, decompress and patch the condition graph in the buffer. This avoids the LZ4 size constraint since we control the buffer.

Challenge: finding the right moment between decompression and parsing, and the decompressed size changes if we modify the condition graph.

## All Files
- Scripts: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\`
- PAZ backup: `E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.paz.bak`
- .paac analysis: `CDAnimCancel\tools\paac_analysis.txt`
- Condition graph partial analysis: `CDAnimCancel\tools\condition_graph_analysis.txt`
- Progress updates 1-5: `CDAnimCancel\PROGRESS_UPDATE_*.md`
- Handoff prompts: `CDAnimCancel\HANDOFF_PROMPT.md`
