# Progress Update 2 — sword_upper ActionChartPackage Found

## Breakthrough

We found the player's sword combat ActionChartPackage object in live memory:

```
Address: 0x4165AB35080
Name:    upperaction/1_pc/1_phm/sword_upper
+0x10 = 3       (chart type — combat charts are type 3)
+0x30 = 45      (matches .paac string table: 45 label entries)
+0x48 = 428     (matches .paac animation paths: 428 .paa files)
```

## Object Layout (256 bytes dumped)

```
+0x000: vtable pointer (0x144A6C610 = ActionChartPackage_BaseData)
+0x008: zeros
+0x010: 03000000 01000100   type=3, flags=0x10001
+0x018: PTR → header data (contains chart name "sword_upper", float params)
+0x020: PTR → string table data ("RightArm", "key_guard", animation paths...)
+0x028: PTR → array of uint32 pairs (node offset table? 0x01,0x30,0x3E,0x4A...)
+0x030: 28000000 28000000   value 40 paired (unknown meaning)
+0x038: PTR → animation path strings
+0x040: PTR → another array (ascending uint32 sequence: 0x01,0x3E,0x77,0xB0...)
+0x048: 6C020000 6C020000   value 620 paired — THIS IS THE NODE COUNT (620 ≈ 617 markers)
+0x050: PTR → more string data (frame event names?)
+0x058: PTR → array data
+0x060: 01000000 01000000   value 1 paired
+0x068: PTR → effect path strings
+0x070: PTR → array data
+0x078: 40000000 40000000   value 64 paired
+0x080: PTR → more data
+0x088: zeros
+0x090: zeros
+0x098: PTR → more data
+0x0A0: PTR → array data
+0x0A8: 0E000000 0E000000   value 14 paired
+0x0B0: PTR → data
+0x0B8: PTR → data
+0x0C0: 0C000000 0C000000   value 12 paired
+0x0C8: PTR → data
+0x0D0: PTR → data
+0x0D8: 18000000 18000000   value 24 paired
+0x0E0: PTR → data
+0x0E8: PTR → data
+0x0F0: 07000000 07000000   value 7 paired
+0x0F8: PTR → data (starts with 0x3F800000 = float 1.0)
```

## Key Pointers to Follow

The object has a repeating structure of `[PTR, PTR, count, count]` groups. Each group likely represents a different data array (nodes, transitions, animations, effects, etc.):

| Offset | PTR1 | PTR2 | Count | Likely Content |
|--------|------|------|-------|----------------|
| +0x18/+0x20 | header | strings | — | Chart name + label string table |
| +0x28/+0x38 | offsets | anim paths | 40 | Node offset table |
| +0x40/+0x50 | offsets | events | 620 | **STATE NODES (matches 617 markers!)** |
| +0x58/+0x68 | data | effects | 1 | Unknown |
| +0x70/+0x80 | data | data | 64 | Unknown |
| +0xA0/+0xB0 | data | data | 14 | Unknown |
| +0xB8/+0xC8 | data | data | 12 | Unknown |
| +0xD0/+0xE0 | data | data | 24 | Unknown |
| +0xE8/+0xF8 | data | data | 7 | Unknown |

**The +0x40 pointer (with count 620 at +0x48) is the most important** — it likely points to the array of parsed state nodes. Each node should contain transition targets.

## What the Pointers Revealed

### +0x18 → Header
Contains chart name string: `"upperaction/1_pc/1_phm/sword_upper"` plus float parameters.

### +0x20 → String Table
Contains the label strings: `"key_guard"`, `"key_norattack"`, `"key_guard_start"`, animation path strings, etc. This matches the .paac string table exactly.

### +0x28 → Node Offset Table
Array of ascending uint32 values: `[1, 48, 62, 74, 88, 98, 109, 114, ...]`. These are likely byte offsets into the state node data (sparse index).

### +0x38 → Animation Path Strings
Contains `.paa` animation file paths like `"1_pc/1_phm/cd_phm_basic_00_01_add_std_idle_upperbody_00.paa"`.

### +0x40 → State Node Array
Array of ascending uint32 values: `[1, 62, 119, 176, 245, 306, 363, 431, ...]`. These are byte offsets into the parsed node data, one per state. With count 620, this matches the ~617 state markers from the .paac.

## What's Missing (Next Steps)

### Step A: Find the CURRENT STATE index
The ActionChartPackage stores the chart definition, but the **current runtime state** (which state the player is currently in) is likely stored in a SEPARATE object — an ActionChart instance or player component that REFERENCES this package. We need to:
1. Search for pointers TO `0x4165AB35080` (what objects reference the sword_upper package?)
2. Those referencing objects likely contain the current state index
3. The current state index is what we need to write to force guard

### Step B: Follow +0x40 pointer deeper
The state node array at +0x40 contains offsets. We need to follow those offsets to find the actual node data, which should contain transition targets. If we can patch THESE (the parsed node data), transitions will change.

### Step C: Find what references the sword_upper package
```python
# Search all heap memory for pointers to 0x4165AB35080
# Whatever object points to this is likely the ActionChart runtime instance
# That instance should have: current_state_index, pending_state, etc.
```

## Other Charts Found (for reference)

| Address | Name | Nodes | Type |
|---------|------|-------|------|
| 0x4165AB35080 | **sword_upper** | 428/620 | 3 |
| 0x4165AB38F80 | battleaxe_upper | 620 | 3 |
| 0x4165AB3E380 | sub_bow_upper | 475 | 3 |
| 0x4165B343000 | rapier_upper | 133 | 3 |
| 0x4165B344B00 | fist_upper | 226 | 3 |
| 0x4165B347B00 | subweapon_upper | 1077 | 3 |
| 0x4165B34FC00 | twohandsword_upper | 588 | 2 |
| 0x4165B8A3480 | dualweapon_upper | 545 | 2 |
| 0x4165B8A6900 | common_skill_upper | 295 | 3 |
| 0x4165A448D00 | basic_hitaction | 1064 | 2 |
| 0x416402F2300 | basic_upper | 181 | 3 |

## Critical Addresses (This Session)

- sword_upper package: `0x4165AB35080`
- InputBlock vtable: `0x144AFCC70`
- ActionChartPackage vtable: `0x144A6C610`
- Game base: `0x140000000`
- InputBlock vfunc[3]: `0x141C8F760` (Themida-protected, can't hook)

## Confirmed Working Capabilities

- pymem attach + read/write to any heap object ✓
- RTTI vtable scanning in live process ✓
- Object instance discovery by vtable ✓
- CDControllerRemap XInput hook sees guard=1 and attacking=1 ✓
- WriteProcessMemory to heap objects (no Themida detection) ✓

## Files

- All scripts: `C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\`
- `find_player_chart.py` — finds and dumps ActionChartPackage objects
- `find_inputblock.py` — finds InputBlock instances
- Previous handoff: `HANDOFF_PROMPT.md`
- Previous update: `PROGRESS_UPDATE.md`
