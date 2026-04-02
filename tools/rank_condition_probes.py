#!/usr/bin/env python3
"""
Rank the exact-size sword_upper condition-graph probe patches.

This script converts the raw exact-size swap list into a practical test order by
scoring each probe against two useful heuristics:

1. Family intent: key_cancel / key_guard_start probes in the shared
   target=13001, params=(9,0,15) family are weighted highest because that
   family already contains the live cancel/guard-start nodes.
2. Source proximity: probes whose source_id sits near existing same-intent
   nodes are more likely to belong to the same gameplay cluster.

The goal is not to "prove" semantics from static bytes alone. It is to produce a
smarter probe order than treating every exact-size candidate equally.
"""

from __future__ import annotations

import pathlib
import struct
from dataclasses import dataclass


SWORD = pathlib.Path(
    r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
)
OUT = pathlib.Path(
    r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\condition_probe_ranking.txt"
)

COND_START = 0x97996
COND_END = 0x12FA79
MARKER = b"M0%D"
BLOCK_SIZE = 260

TARGET_REF_OFF = 152
SOURCE_ID_OFF = 212
LABEL_INDEX_OFF = 216
OPCODE_OFF = 224
PARAM_START_OFF = 229

STRING_TABLE = {
    1: "key_guard",
    3: "LowerLeftArm_1",
    4: "BothHands",
    6: "LeftArmNoSplice",
    7: "NeckAndLeftArm",
    8: "key_fistattack",
    9: "equip_shield",
    11: "CharacterMeshEffectWeapon",
    12: "key_skill_1",
    15: "key_crouch",
    17: "key_guard_start",
    20: "key_cancel",
}

EXACT_RECIPES = [
    {"name": "probe_cancel_541", "block": 541, "old": 15, "new": 20},
    {"name": "probe_cancel_212", "block": 212, "old": 3, "new": 20},
    {"name": "probe_guard_423", "block": 423, "old": 7, "new": 1},
    {"name": "probe_guard_294", "block": 294, "old": 4, "new": 1},
    {"name": "probe_cancel_206", "block": 206, "old": 6, "new": 20},
    {"name": "probe_guardstart_400", "block": 400, "old": 11, "new": 17},
    {"name": "probe_guard_171", "block": 171, "old": 7, "new": 1},
]


@dataclass(frozen=True)
class BlockRec:
    marker_index: int
    file_offset: int
    target_ref: int
    source_id: int
    label: int
    opcode: int
    params: tuple[int, int, int]


def label_name(label: int) -> str:
    return STRING_TABLE.get(label, f"label_{label}")


def is_input_like(label: int) -> bool:
    name = label_name(label)
    return name.startswith("key_") or name == "equip_shield"


def iter_uniform_blocks(data: bytes) -> list[BlockRec]:
    cond = data[COND_START:COND_END]
    offsets = []
    pos = 0
    while True:
        idx = cond.find(MARKER, pos)
        if idx < 0:
            break
        offsets.append(idx)
        pos = idx + 1

    blocks: list[BlockRec] = []
    for marker_index in range(len(offsets) - 1):
        off = offsets[marker_index]
        if offsets[marker_index + 1] - off != BLOCK_SIZE:
            continue
        block = cond[off:off + BLOCK_SIZE]
        blocks.append(
            BlockRec(
                marker_index=len(blocks),
                file_offset=COND_START + off,
                target_ref=struct.unpack_from("<I", block, TARGET_REF_OFF)[0],
                source_id=struct.unpack_from("<H", block, SOURCE_ID_OFF)[0],
                label=struct.unpack_from("<H", block, LABEL_INDEX_OFF)[0],
                opcode=struct.unpack_from("<H", block, OPCODE_OFF)[0],
                params=tuple(block[PARAM_START_OFF:PARAM_START_OFF + 3]),
            )
        )
    return blocks


def nearest_distance(source_id: int, peers: list[int]) -> tuple[int | None, int | None]:
    if not peers:
        return None, None
    best = min((abs(source_id - peer), peer) for peer in peers)
    return best


def intent_weight(new_label: int) -> int:
    if new_label == 20:
        return 300
    if new_label == 17:
        return 280
    if new_label == 1:
        return 230
    return 0


def proximity_bonus(distance: int | None) -> int:
    if distance is None:
        return 0
    # Strongly reward local clusters without letting distance dominate intent.
    return max(0, 120 - min(distance, 120))


def main() -> None:
    data = SWORD.read_bytes()
    blocks = iter_uniform_blocks(data)
    by_sig: dict[tuple[int, int, tuple[int, int, int]], list[BlockRec]] = {}
    for rec in blocks:
        by_sig.setdefault((rec.target_ref, rec.opcode, rec.params), []).append(rec)

    lines: list[str] = []

    def log(msg: str = "") -> None:
        lines.append(msg)
        print(msg)

    scored = []

    for recipe in EXACT_RECIPES:
        rec = blocks[recipe["block"]]
        if rec.label != recipe["old"]:
            raise ValueError(
                f"{recipe['name']}: expected old label {recipe['old']} "
                f"but block #{recipe['block']} has {rec.label}"
            )

        family = by_sig[(rec.target_ref, rec.opcode, rec.params)]
        if recipe["new"] == 20:
            related_labels = {20, 17}
        elif recipe["new"] == 17:
            related_labels = {17, 20}
        else:
            related_labels = {1}

        same_sources = [b.source_id for b in family if b.label == recipe["new"]]
        related_sources = [b.source_id for b in family if b.label in related_labels]
        nearest_same_dist, nearest_same_src = nearest_distance(rec.source_id, same_sources)
        nearest_related_dist, nearest_related_src = nearest_distance(rec.source_id, related_sources)

        score = intent_weight(recipe["new"])
        score += proximity_bonus(nearest_related_dist)
        if is_input_like(rec.label):
            score += 25

        scored.append(
            {
                "recipe": recipe["name"],
                "rec": rec,
                "new": recipe["new"],
                "score": score,
                "nearest_same_dist": nearest_same_dist,
                "nearest_same_src": nearest_same_src,
                "nearest_related_dist": nearest_related_dist,
                "nearest_related_src": nearest_related_src,
                "old_input_like": is_input_like(rec.label),
                "family_size": len(family),
            }
        )

    scored.sort(
        key=lambda item: (
            -item["score"],
            item["nearest_related_dist"] if item["nearest_related_dist"] is not None else 999999,
            item["rec"].marker_index,
        )
    )

    log("=" * 100)
    log("RANKED EXACT-SIZE CONDITION PROBES")
    log("=" * 100)
    log(f"File: {SWORD}")
    log(f"Uniform blocks: {len(blocks)}")
    log()
    log("Ranking heuristic:")
    log("  1. Prefer key_cancel / key_guard_start probes in the live target=13001 family.")
    log("  2. Within a family, prefer source_ids nearest to existing same-intent nodes.")
    log("  3. Give a small bonus when the old label is already input-like.")
    log()

    for index, item in enumerate(scored, start=1):
        rec = item["rec"]
        log(
            f"{index}. {item['recipe']}: block#{rec.marker_index} "
            f"{label_name(rec.label)} -> {label_name(item['new'])} "
            f"src={rec.source_id} target={rec.target_ref} params={rec.params} score={item['score']}"
        )
        log(
            f"   nearest same-intent src: "
            f"{item['nearest_same_src']} (dist {item['nearest_same_dist']})"
        )
        log(
            f"   nearest related src: "
            f"{item['nearest_related_src']} (dist {item['nearest_related_dist']})"
        )
        log(
            f"   family size: {item['family_size']}, old label input-like: {item['old_input_like']}"
        )
        log()

    log("Recommended first-pass test order:")
    for item in scored[:4]:
        rec = item["rec"]
        log(
            f"  - {item['recipe']} ({label_name(rec.label)} -> {label_name(item['new'])}, "
            f"src {rec.source_id}, nearest related dist {item['nearest_related_dist']})"
        )

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nSaved ranking to {OUT}")


if __name__ == "__main__":
    main()
