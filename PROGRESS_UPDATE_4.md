# Progress Update 4 — Top-Down Component Scan Complete, No State Field Found

## What We Did

### Found all player-facing component types via live RTTI
| Class | Vtable | Instances |
|-------|--------|-----------|
| ClientCharacterControlActorComponent | 0x14477C6B8 | 33-56 |
| ClientSkillActorComponent | 0x144789B60 | 81 |
| ClientAttackActorComponent | 0x144748100 | 119 |
| ActionChartPackageGroup | 0x144B37470 | 8-10 |
| ActionChartPackageSet | 0x144B37480 | 8-11 |
| ClientInputActorComponent | 0x14478E108 | 58 |
| FrameEventAccessor | 0x144748300 | 49 |

### Monitored 51,983 u32 fields across all instances during idle→attack→idle→guard
- Found 344 combat-correlated fields
- Top scorer: `CharCtrl[1]+0x1F4` — idle=1, attack=[0,1,256], guard=1 (score 26)
- PkgGroup[7] had ~11 fields toggling 0→1 or 0→2 during attack
- ALL fields were boolean/flag toggles (0/1/2/256), NOT state IDs (0-720 range)

### Force-wrote idle values to all top candidates at 120Hz during attack
- 91,584 writes across 56 CharCtrl instances + 8 PkgGroup instances
- **Guard still did not cancel attacks**

## Conclusions

1. **The combat lock is NOT a simple u32 flag** in any of the standard component types we scanned.
2. **The actual action chart state index is not stored as a plain integer** in the first 1024 bytes of CharCtrl, Skill, Attack, PkgGroup, PkgSet, or Input components.
3. The state is likely:
   - Behind 2+ pointer dereferences inside one of these components
   - In a dynamically allocated evaluator/player object that doesn't have a vtable we scanned
   - Encoded differently (e.g., pointer to current state node, not an integer index)

## What's Left To Try

### Fallback: +0x40 parsed transition patch (RECOMMENDED NOW)
We found the sword_upper ActionChartPackage at a known address. Its +0x40 field points to a 620-entry offset table (one per state node). We should:
1. Follow +0x40 to get the node offset array
2. Follow each offset to find the parsed node data
3. Look for transition target values in the parsed nodes
4. Patch targets to add guard (state 0) as a transition from attack sub-states
5. Unlike the raw .paac patch that failed, these are the PARSED runtime structures

### Bounded pointer walk (parallel, low priority)
From PkgGroup[7], follow pointers up to depth 3, looking for fields with values cycling through 0/7/14/21/28/37 during combos. Cap at 1000 nodes to prevent explosion.

### ReadFile/NtReadFile intercept
Hook the system file read API (not game code — Themida-safe). Detect when sword_upper.paac is loaded, patch bytes before the parser consumes them. This modifies the source data at load time.

### VEH page-guard
Set PAGE_GUARD on ActionChartPackage memory pages. When the evaluator reads transition data, our exception handler fires. Walk the stack to find the evaluator object and its state fields.

## Status
- Game running, pymem attached, all scripts working
- User is available for testing
- Ready for next approach decision
