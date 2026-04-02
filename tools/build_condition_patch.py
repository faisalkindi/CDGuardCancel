#!/usr/bin/env python3
"""
Build experimental sword_upper.paac variants from corrected condition-node label swaps.

This tool does not touch the live PAZ. It writes patched .paac files and their
LZ4-compressed blobs into CDAnimCancel/mod_test so candidate recipes can be
tested safely before any archive patching.
"""

from __future__ import annotations

import argparse
import pathlib
import struct

import lz4.block

SWORD = pathlib.Path(
    r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
)
OUT_DIR = pathlib.Path(
    r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\mod_test"
)

COND_START = 0x97996
COND_END = 0x12FA79
MARKER = b"M0%D"
BLOCK_SIZE = 260
LABEL_INDEX_OFF = 216
TARGET_COMPRESSED_SIZE = 224084

STRING_TABLE = {
    1: "key_guard",
    7: "NeckAndLeftArm",
    8: "key_fistattack",
    9: "equip_shield",
    12: "key_skill_1",
    15: "key_crouch",
    17: "key_guard_start",
    20: "key_cancel",
    21: "CharacterHit",
}

RECIPES = {
    # Exact-size single swaps discovered by condition_graph_patch_candidates.py
    "probe_guard_171": [
        {"block": 171, "old": 7, "new": 1},
    ],
    "probe_cancel_206": [
        {"block": 206, "old": 6, "new": 20},
    ],
    "probe_cancel_212": [
        {"block": 212, "old": 3, "new": 20},
    ],
    "probe_guard_294": [
        {"block": 294, "old": 4, "new": 1},
    ],
    "probe_guardstart_400": [
        {"block": 400, "old": 11, "new": 17},
    ],
    "probe_guard_423": [
        {"block": 423, "old": 7, "new": 1},
    ],
    "probe_cancel_541": [
        {"block": 541, "old": 15, "new": 20},
    ],
    # Verified exact-size combinations. These were confirmed by recompressing
    # the fully patched file, not by summing individual deltas.
    "combo_cancel_near_cluster": [
        {"block": 212, "old": 3, "new": 20},
        {"block": 541, "old": 15, "new": 20},
    ],
    "combo_cancel_guard_signal": [
        {"block": 423, "old": 7, "new": 1},
        {"block": 541, "old": 15, "new": 20},
    ],
    "combo_top3_exact": [
        {"block": 212, "old": 3, "new": 20},
        {"block": 423, "old": 7, "new": 1},
        {"block": 541, "old": 15, "new": 20},
    ],
    # Verified exact cluster-bundle probes from condition_family_13001_clusters.py
    "cluster7_cancel_pair_fist_skill2": [
        {"block": 35, "old": 18, "new": 20},
        {"block": 113, "old": 8, "new": 20},
    ],
    "cluster7_cancel_pair_crouch_skill1": [
        {"block": 70, "old": 15, "new": 20},
        {"block": 585, "old": 12, "new": 20},
    ],
    "cluster7_cancel_triplet_local": [
        {"block": 70, "old": 15, "new": 20},
        {"block": 532, "old": 13, "new": 20},
        {"block": 212, "old": 3, "new": 20},
    ],
}


def label_name(label: int) -> str:
    return STRING_TABLE.get(label, f"label_{label}")


def build_block_index(data: bytes) -> list[int]:
    cond = data[COND_START:COND_END]
    offsets = []
    pos = 0
    while True:
        idx = cond.find(MARKER, pos)
        if idx < 0:
            break
        offsets.append(idx)
        pos = idx + 1

    blocks = []
    for i in range(len(offsets) - 1):
        if offsets[i + 1] - offsets[i] == BLOCK_SIZE:
            blocks.append(COND_START + offsets[i])
    return blocks


def apply_recipe(recipe_name: str) -> tuple[pathlib.Path, pathlib.Path, int]:
    data = bytearray(SWORD.read_bytes())
    blocks = build_block_index(data)
    edits = RECIPES[recipe_name]

    for edit in edits:
        block = edit["block"]
        if block >= len(blocks):
            raise ValueError(f"Block index out of range: {block}")
        label_off = blocks[block] + LABEL_INDEX_OFF
        current = struct.unpack_from("<H", data, label_off)[0]
        if current != edit["old"]:
            raise ValueError(
                f"Recipe {recipe_name}: block {block} expected {edit['old']} "
                f"({label_name(edit['old'])}) but found {current} ({label_name(current)})"
            )
        struct.pack_into("<H", data, label_off, edit["new"])

    comp = lz4.block.compress(bytes(data), store_size=False)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    paac_out = OUT_DIR / f"{recipe_name}.paac"
    comp_out = OUT_DIR / f"{recipe_name}_comp.bin"
    paac_out.write_bytes(data)
    comp_out.write_bytes(comp)
    return paac_out, comp_out, len(comp)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build experimental condition-graph patch variants")
    parser.add_argument("--recipe", help="Recipe name to build")
    parser.add_argument("--list", action="store_true", help="List available recipes")
    args = parser.parse_args()

    if args.list or not args.recipe:
        print("Available recipes:")
        for name, edits in RECIPES.items():
            desc = ", ".join(
                f"block#{e['block']} {label_name(e['old'])}->{label_name(e['new'])}" for e in edits
            )
            print(f"  {name}: {desc}")
        return

    if args.recipe not in RECIPES:
        raise SystemExit(f"Unknown recipe: {args.recipe}")

    paac_out, comp_out, comp_size = apply_recipe(args.recipe)
    delta = comp_size - TARGET_COMPRESSED_SIZE
    print(f"Recipe: {args.recipe}")
    print(f"  paac: {paac_out}")
    print(f"  comp: {comp_out}")
    print(f"  compressed size: {comp_size} (delta {delta:+d})")
    if delta != 0:
        print("  WARNING: compressed blob no longer matches the original PAZ slot size")


if __name__ == "__main__":
    main()
