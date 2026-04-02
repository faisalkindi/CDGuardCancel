# CDAnimCancel — Guard Cancel for Crimson Desert

Press guard (LB) during sword attack combos to cancel into block stance.

## Download

Get the latest release from [Nexus Mods](https://www.nexusmods.com/crimsondesert/mods/XXX) or build from source.

## Building

Requires Visual Studio 2022 Build Tools and CMake 3.20+.

```bash
./build.bat
```

Output: `build/bin/Release/CDAnimCancel.asi`

Install: copy `CDAnimCancel.asi` + `CDAnimCancel.ini` to `Crimson Desert\bin64\`

## How It Works

The mod hooks the game's transition evaluator function via [SafetyHook](https://github.com/cursey/safetyhook). When it detects a recent attack (RB/RT) followed by LB, it forces the guard transition's condition check to pass. AOB pattern scanning makes it resilient to game updates.

## Known Issue — Dodge Side Effect

During attack cancels, dodge may trigger alongside guard. The guard and dodge transitions share identical evaluator structures at every level we've analyzed. Separating them requires finding what distinguishes them above the evaluator hook.

**This is the main open problem. See [Crimson_Desert_AnimCancel_Research.md](Crimson_Desert_AnimCancel_Research.md) for the full technical breakdown.**

## Research

This mod is backed by a week of deep reverse engineering. The research document covers:

- Full .paac action chart format (1.2MB sword_upper.paac, 721 nodes)
- 3-layer guard block system (branchset, timeline, guard sub-blocks)
- Decompiled Ghidra output for three evaluator function layers
- 35+ approaches tried and documented
- Cheat Engine findings from the FearLess community
- Button-to-evaluator mapping data
- Complete condition graph analysis (622KB, 651 records)

## Contributing

PRs welcome. The main areas where help is needed:

1. **Eliminate the dodge side effect** — Find what distinguishes guard from dodge evaluator objects. They share identical candCount, condition types, input types, transition data, and condition object fields.
2. **Decode the condition graph** — The 622KB bytecode section in sword_upper.paac controls attack sub-state transitions. Partially decoded.
3. **BDO engine knowledge** — Same studio, similar engine. BDO modders may recognize patterns.

## Credits

- **kindiboy** — Research, development, reverse engineering
- **Send** (FearLess CE) — Guard activation function disassembly
- **init0nee** — Early community feedback
- **cursey** — [SafetyHook](https://github.com/cursey/safetyhook)
- **ThirteenAG** — [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)

## License

MIT
