# Progress Update 3 — Owner Objects Found, State Still Elusive

## What We Did

### Step 1-2: Found sword_upper and its references
- sword_upper ActionChartPackage at `0x4165AB35080` (rediscovered dynamically)
- 5 objects reference it, across 2 vtable types:
  - `0x1447467F8` — 3 objects (ref at +0x18 or +0x1F8)
  - `0x144C0D320` — 2 objects (ref at +0xF0)

### Step 3-4: Monitored all u32 fields (0-720) across idle/attack/guard
**Result: 0 interesting fields.** None of the u32 fields in these 5 objects change between idle, attack, and guard phases.

## What This Means

The 5 referencing objects are **definition/configuration objects**, not runtime state holders. The runtime current state (which state the player is in right now) is stored:
1. Behind one or more pointer dereferences from these objects
2. Or in a completely separate object that connects to the package through an indirect chain
3. Or referenced through the player entity/character controller, not through the package at all

## Architecture Hypothesis

```
PlayerEntity
  └─ CharacterControlActorComponent
       └─ ActionChartEvaluator (runtime state: current_state, pending_state)
            └─ ActionChartPackageSet
                 └─ ActionChartPackage_BaseData (sword_upper — what we found)
```

The current_state is likely 2-3 pointer dereferences away from the package.

## Owner Object Details

### Vtable 0x1447467F8 (3 objects)
- Layout: repeating `[ptr, 0xBF03, ptr, 0xBF03, ptr, 0xBF03, ...]` pattern (pairs of pointer + tag 959)
- Has u32=1 at +0x14, +0x74, +0xD4 (fixed, doesn't change)
- Has u32=255 at +0xC0 (fixed)
- These look like **slot/layer mapping objects** (mapping weapon types to chart packages)

### Vtable 0x144C0D320 (2 objects)
- Sword package referenced at +0xF0
- Not yet deeply examined

## What Has NOT Changed
- pymem read/write works ✓
- RTTI scanning works ✓
- Object discovery by vtable works ✓
- CDControllerRemap XInput hook tracks guard/attack ✓

## Suggested Next Steps (for consultant)

### Option A: Follow pointers deeper
Each owner object has ~30 pointer fields. Follow each pointer, read 256 bytes, check for small integers that change during combat. This is an exponential search but we can automate it.

### Option B: Search from the player entity downward
Instead of going UP from the package, go DOWN from the player. Find the player entity (probably via RTTI: `ClientCharacterControlActorComponent` vtable `0x1449C04A0`... but this address is from the dump, need to rediscover). The player entity should have a member that points to the ActionChart evaluator.

### Option C: Monitor ALL heap for combat-correlated changes
Instead of targeted scanning, do a bulk diff of all writable memory between idle and attack, but filter to only addresses that are within ±4096 bytes of a known owner object address. This narrows the search to the same heap allocations.

### Option D: Forget the state field — patch the parsed transitions
Follow the ActionChartPackage +0x40 pointer (620-entry node offset table). Each entry is an offset into a data area. Follow those offsets to find parsed node structures. Patch transition targets in THOSE structures (not the raw .paac bytes). This is approach #3 fallback from the original plan.

### Option E: VEH page-guard on state read
Place PAGE_GUARD on the memory page containing the ActionChartPackage. When the game accesses it, the exception handler fires. Walk the call stack to find what function is evaluating the chart. That function's local variables or object reference will contain the current state. This is an indirect way to find the state without scanning.

## Files
- `step1_find_owner.py` — finds sword_upper + references
- `step4_monitor_owners.py` — monitors owner fields across combat phases
- `owner_candidates.txt` — full field dumps of 5 owner objects
- `state_fields.txt` — (empty, no changing fields found)
