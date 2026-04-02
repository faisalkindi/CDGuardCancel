# Guard Cancel — Cancel Attacks with Block

Press guard (LB) during sword attack combos to cancel the animation and raise your shield. Skills already cancel attacks in Crimson Desert — this mod extends that to guard.

## What It Does

When you're mid-combo and press LB, your character transitions to guard stance instead of waiting for the attack animation to finish. This gives you a defensive option during aggressive play, similar to how many action games handle guard cancels.

**From idle**, LB works exactly like vanilla — clean guard, no changes.

## How It Works

The mod hooks the game's transition evaluator function using SafetyHook. When it detects that you recently attacked (pressed RB or RT) and then press LB, it forces the guard transition to pass the evaluator's condition check. The mod uses AOB pattern scanning, so it should survive minor game updates.

## Known Limitations

- **Dodge may trigger alongside guard during attack cancels.** The game's evaluator system shares the same mechanism for guard and dodge transitions. Separating them cleanly requires deeper engine work — contributions welcome (see GitHub).
- **From idle, guard works perfectly** with no side effects.
- The mod only activates within a configurable window after your last attack (default 2 seconds). Outside that window, all inputs are vanilla.

## Installation

1. You need an ASI Loader in your `bin64` folder. If you already have one from another mod (like `winmm.dll` or `version.dll` from Ultimate ASI Loader), skip this step.
2. Extract `CDAnimCancel.asi` and `CDAnimCancel.ini` into:
   `...\Crimson Desert\bin64\`
3. Launch the game.

## Configuration

Edit `CDAnimCancel.ini`:

```ini
[General]
Enabled=1
; How long after your last attack the mod stays active (milliseconds)
; Default: 2000. Increase if guard cancel doesn't trigger reliably.
CombatTimeoutMs=2000

[Debug]
; Set to 1 to enable logging (CDAnimCancel.log in bin64)
LogEnabled=0
```

## Uninstall

Delete `CDAnimCancel.asi` and `CDAnimCancel.ini` from your `bin64` folder. No game files are modified.

## Compatibility

- Works with Ultimate ASI Loader, CDUMM, and other ASI mods
- Uses SafetyHook (included) — no MinHook dependency
- AOB pattern scanning adapts to minor game updates
- Steam Input must be disabled for controller input detection

## Technical Details & Contributing

This mod is the result of extensive reverse engineering of Crimson Desert's BlackSpace Engine combat system. The full research, decompiled functions, and all diagnostic data are available on GitHub.

**The dodge side effect is the main open problem.** The guard and dodge transitions share identical evaluator types, condition structures, and fingerprint data — the game distinguishes them at a level above the evaluator hook. If you have experience with BlackSpace Engine or BDO's action chart system, your help would make this mod perfect.

**GitHub:** [link]

## Credits

- **kindiboy** — Research, development, all 35+ approaches tried
- **Send** (FearLess CE) — Guard activation function disassembly
- **init0nee** — Early feedback
- **cursey** — SafetyHook library
- **ThirteenAG** — Ultimate ASI Loader
- **Ghidra** (NSA) — Decompilation of evaluator functions
