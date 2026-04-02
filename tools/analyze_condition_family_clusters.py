#!/usr/bin/env python3
"""
Analyze the sword_upper target=13001 / opcode=0x2902 / params=(9,0,15) family.

After four top-ranked single probes produced no gameplay signal, the working
hypothesis is that this family operates in source-id bundles rather than
standalone single nodes. This script:

1. Extracts the target 13001 family from the corrected 260-byte condition nodes.
2. Splits it into source-id clusters using small numeric gaps.
3. Lists the labels and post-condition fields per cluster.
4. Searches for exact-size, fully recompressed pair/triple edits *within* each
   cluster, restricted to cancel / guard_start conversions.
"""

from __future__ import annotations

import itertools
import pathlib
import struct
from collections import Counter

import lz4.block


ROOT = pathlib.Path(r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel")
SWORD = ROOT / r"extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
OUT = ROOT / r"tools\condition_family_13001_clusters.txt"

COND_START = 0x97996
COND_END = 0x12FA79
MARKER = b"M0%D"
BLOCK_SIZE = 260
TARGET_COMPRESSED_SIZE = 224084

TARGET_REF_OFF = 152
SOURCE_ID_OFF = 212
LABEL_INDEX_OFF = 216
OPCODE_OFF = 224
PARAM_START_OFF = 229
POST_A_OFF = 248
POST_B_OFF = 252
POST_C_OFF = 256

TARGET_SIG = (13001, 0x2902, (9, 0, 15))
CLUSTER_GAP = 64
TARGET_LABELS = {17, 20}

STRING_TABLE = {
    0: "common_upper_branchset",
    1: "key_guard",
    2: "NeckAndRightArm",
    3: "LowerLeftArm_1",
    4: "BothHands",
    5: "Spine2_Upper",
    6: "LeftArmNoSplice",
    7: "NeckAndLeftArm",
    8: "key_fistattack",
    9: "equip_shield",
    10: "key_skill_12",
    11: "CharacterMeshEffectWeapon",
    12: "key_skill_1",
    13: "key_skill_12_start",
    14: "key_skill_7",
    15: "key_crouch",
    16: "key_hardattack",
    17: "key_guard_start",
    18: "key_skill_2",
    19: "key_run",
    20: "key_cancel",
    21: "CharacterHit",
    22: "off",
}


def label_name(label: int) -> str:
    return STRING_TABLE.get(label, f"label_{label}")


def read_blocks(data: bytes) -> list[dict]:
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
    for marker_index in range(len(offsets) - 1):
        off = offsets[marker_index]
        if offsets[marker_index + 1] - off != BLOCK_SIZE:
            continue
        base = COND_START + off
        block = cond[off:off + BLOCK_SIZE]
        blocks.append(
            {
                "idx": len(blocks),
                "file_offset": base,
                "label_file_offset": base + LABEL_INDEX_OFF,
                "target": struct.unpack_from("<I", block, TARGET_REF_OFF)[0],
                "src": struct.unpack_from("<H", block, SOURCE_ID_OFF)[0],
                "label": struct.unpack_from("<H", block, LABEL_INDEX_OFF)[0],
                "opcode": struct.unpack_from("<H", block, OPCODE_OFF)[0],
                "params": tuple(block[PARAM_START_OFF:PARAM_START_OFF + 3]),
                "post_a": struct.unpack_from("<I", block, POST_A_OFF)[0],
                "post_b": struct.unpack_from("<I", block, POST_B_OFF)[0],
                "post_c": struct.unpack_from("<I", block, POST_C_OFF)[0],
            }
        )
    return blocks


def cluster_family(family: list[dict]) -> list[list[dict]]:
    ordered = sorted(family, key=lambda rec: (rec["src"], rec["idx"]))
    clusters: list[list[dict]] = []
    current: list[dict] = []
    for rec in ordered:
        if not current:
            current = [rec]
            continue
        if rec["src"] - current[-1]["src"] <= CLUSTER_GAP:
            current.append(rec)
        else:
            clusters.append(current)
            current = [rec]
    if current:
        clusters.append(current)
    return clusters


def compress_size(data: bytes) -> int:
    return len(lz4.block.compress(data, store_size=False))


def apply_swaps(base_data: bytes, swaps: list[tuple[int, int]]) -> int:
    patched = bytearray(base_data)
    for file_off, new_label in swaps:
        struct.pack_into("<H", patched, file_off, new_label)
    return compress_size(patched)


def cluster_candidates(cluster: list[dict], sword_data: bytes) -> tuple[list[str], list[str]]:
    singles = []
    combos = []

    candidates = []
    for rec in cluster:
        for new_label in sorted(TARGET_LABELS):
            if rec["label"] == new_label:
                continue
            candidates.append(
                {
                    "rec": rec,
                    "new_label": new_label,
                }
            )

    for item in candidates:
        rec = item["rec"]
        size = apply_swaps(sword_data, [(rec["label_file_offset"], item["new_label"])])
        if size != TARGET_COMPRESSED_SIZE:
            continue
        singles.append(
            f"  SINGLE exact block#{rec['idx']:3d} src={rec['src']:4d} "
            f"{label_name(rec['label'])}->{label_name(item['new_label'])}"
        )

    for combo_size in (2, 3):
        for group in itertools.combinations(candidates, combo_size):
            file_offsets = [g["rec"]["label_file_offset"] for g in group]
            if len(file_offsets) != len(set(file_offsets)):
                continue
            size = apply_swaps(
                sword_data,
                [(g["rec"]["label_file_offset"], g["new_label"]) for g in group],
            )
            if size != TARGET_COMPRESSED_SIZE:
                continue
            desc = ", ".join(
                f"block#{g['rec']['idx']} src={g['rec']['src']} "
                f"{label_name(g['rec']['label'])}->{label_name(g['new_label'])}"
                for g in group
            )
            combos.append(f"  COMBO exact ({combo_size}) {desc}")

    return singles, combos


def main() -> None:
    sword_data = SWORD.read_bytes()
    blocks = read_blocks(sword_data)
    family = [
        rec
        for rec in blocks
        if (rec["target"], rec["opcode"], rec["params"]) == TARGET_SIG
    ]
    clusters = cluster_family(family)

    lines: list[str] = []

    def log(msg: str = "") -> None:
        lines.append(msg)
        print(msg)

    log("=" * 100)
    log("CONDITION FAMILY CLUSTER ANALYSIS")
    log("=" * 100)
    log(f"File: {SWORD}")
    log(f"Target family: target={TARGET_SIG[0]} opcode=0x{TARGET_SIG[1]:04X} params={TARGET_SIG[2]}")
    log(f"Family size: {len(family)}")
    log(f"Cluster gap threshold: {CLUSTER_GAP}")
    log()

    srcs = sorted(rec["src"] for rec in family)
    deltas = [srcs[i + 1] - srcs[i] for i in range(len(srcs) - 1)]
    log(f"Small source-id delta histogram (<=64): {Counter(d for d in deltas if d <= 64).most_common(20)}")
    log()

    for cluster_index, cluster in enumerate(clusters, start=1):
        start = cluster[0]["src"]
        end = cluster[-1]["src"]
        label_hist = Counter(rec["label"] for rec in cluster)
        log("-" * 100)
        log(
            f"CLUSTER {cluster_index}: src {start} -> {end} "
            f"({len(cluster)} nodes, labels={{{', '.join(f'{label_name(k)}:{v}' for k, v in sorted(label_hist.items()))}}})"
        )
        for rec in cluster:
            log(
                f"  block#{rec['idx']:3d} src={rec['src']:4d} label={label_name(rec['label']):24s} "
                f"post=({rec['post_a']},{rec['post_b']},{rec['post_c']})"
            )
        log()

        singles, combos = cluster_candidates(cluster, sword_data)
        if singles:
            log("  Verified exact singles within cluster:")
            for line in singles[:20]:
                log(line)
        if combos:
            log("  Verified exact combos within cluster:")
            for line in combos[:30]:
                log(line)
        if not singles and not combos:
            log("  No exact cancel/guard_start edits found inside this cluster.")
        log()

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nSaved cluster report to {OUT}")


if __name__ == "__main__":
    main()
