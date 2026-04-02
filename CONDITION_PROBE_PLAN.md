# Condition Probe Plan

## What Changed

- The 260-byte condition-node tail was previously read with a `+4` offset error.
- Corrected field map:
  - `+152` = target transition/state ref
  - `+212` = source state/node id
  - `+216` = label index
  - `+224` = opcode
  - `+229:232` = condition params
- After correcting that map, the uniform `M0%D` blocks expose real combat labels like
  `key_guard`, `key_guard_start`, and `key_cancel`.

## Why This Path Matters

- We now have **exact-size** `.paac` probes that recompress to the original PAZ slot size.
- That gives us a controlled test path that avoids the broken "compensator" approach and
  does not require runtime hook success first.
- The best candidates are in the same signature family as the existing
  `key_cancel` / `key_guard_start` blocks:
  - `target=13001`
  - `opcode=0x2902`
  - `params=(9, 0, 15)`

## Recommended Test Order

1. `probe_cancel_541`
   - `key_crouch -> key_cancel`
   - Source `1160`
   - Strongest candidate because it is only `42` away from an existing `key_cancel`
     source (`1202`) in the same family.

2. `probe_cancel_212`
   - `LowerLeftArm_1 -> key_cancel`
   - Source `1785`
   - Strong candidate because it sits `50` away from the existing `key_guard_start`
     source (`1735`) in the same family.

3. `probe_guard_423`
   - `NeckAndLeftArm -> key_guard`
   - Source `5161`
   - Best guard probe because it sits right next to an existing `key_guard` cluster
     (`5092-5136`) in the same `(target, opcode, params)` family.

4. `probe_cancel_206`
   - `LeftArmNoSplice -> key_cancel`
   - Exact-size and same family, but source locality is much weaker than the first
     two cancel probes.

5. `probe_guardstart_400`
   - `CharacterMeshEffectWeapon -> key_guard_start`
   - Useful if the cancel probes show no signal and we want to test a direct
     `guard_start` extension inside the live `13001` family.

6. `probe_guard_294`
7. `probe_guard_171`

## Verified Exact Combos

These were verified by recompressing the fully patched file, not by adding delta
values from individual swaps.

- `combo_cancel_near_cluster`
  - `probe_cancel_212 + probe_cancel_541`
- `combo_cancel_guard_signal`
  - `probe_guard_423 + probe_cancel_541`
- `combo_top3_exact`
  - `probe_cancel_212 + probe_guard_423 + probe_cancel_541`

## Built Test Artifacts

Generated under `mod_test/`:

- `probe_cancel_541.paac`
- `probe_cancel_212.paac`
- `probe_guard_423.paac`
- `probe_cancel_206.paac`
- `probe_guardstart_400.paac`
- `probe_guard_294.paac`
- `probe_guard_171.paac`
- `combo_cancel_near_cluster.paac`
- `combo_cancel_guard_signal.paac`
- `combo_top3_exact.paac`

Each has a matching `_comp.bin` file.

Ignore these older artifacts if they are still present in `mod_test/`:

- `combo_cancel_dual.*`
- `combo_mixed_exact.*`

They were generated before the full recompression check was added and do **not**
preserve the original compressed slot size.

## Test Guidance

- Start with **single probes only**.
- If one single probe shows behavioral signal, move to the verified exact combos.
- Do not trust additive compression math for combos; only trust recipes verified by
  full recompression.
- If none of the top 4 probes produce signal, the next best move is to decode the
  meaning of source-id clusters inside the `13001 / (9,0,15)` family before doing
  broader swaps.

## Current Status After Live Testing

These top-4 single probes have now all been tested live and returned `no_signal`:

- `probe_cancel_541`
- `probe_cancel_212`
- `probe_guard_423`
- `probe_cancel_206`

That means the next best path is no longer broad single-node swapping.

## New Pivot: Cluster-Bundle Probes

The `target=13001 / opcode=0x2902 / params=(9,0,15)` family breaks into tight
source-id ladders, especially:

- Cluster 6: `1160-1321`
- Cluster 7: `1405-1794`
- Cluster 10: `3532-3779`

Cluster 7 is currently the most promising because it already contains live
`key_cancel` and `key_guard_start` nodes plus attack-relevant labels like
`key_fistattack`, `key_skill_1`, and `key_skill_2`.

Verified exact bundle probes now built:

- `cluster7_cancel_pair_fist_skill2`
  - `block#35 key_skill_2 -> key_cancel`
  - `block#113 key_fistattack -> key_cancel`
- `cluster7_cancel_pair_crouch_skill1`
  - `block#70 key_crouch -> key_cancel`
  - `block#585 key_skill_1 -> key_cancel`
- `cluster7_cancel_triplet_local`
  - `block#70 key_crouch -> key_cancel`
  - `block#532 key_skill_12_start -> key_cancel`
  - `block#212 LowerLeftArm_1 -> key_cancel`

The supporting analysis report is:

- `tools/condition_family_13001_clusters.txt`
