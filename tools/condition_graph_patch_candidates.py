#!/usr/bin/env python3
"""
Rank surgical condition-graph label swaps for sword_upper.paac.

The earlier condition graph analysis identified a stable 260-byte node format,
but its tail-field offsets were shifted by 4 bytes. This script uses the
corrected offsets to:

1. Parse the uniform M0%D blocks.
2. Group nodes by (target_ref, opcode, params) signature.
3. Find families where key_guard / key_guard_start / key_cancel already exist.
4. Propose same-signature label swaps as the lowest-risk patch candidates.
5. Measure LZ4 compressed-size deltas for each individual swap so we know which
   edits are compatible with fixed-size PAZ patching.
"""

from __future__ import annotations

import itertools
import pathlib
import struct
from collections import Counter, defaultdict

import lz4.block

SWORD = pathlib.Path(
    r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
)
OUT = pathlib.Path(
    r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\condition_graph_patch_candidates.txt"
)

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
    23: "RightArm",
    24: "LeftArm",
    25: "key_dash",
    26: "key_skill_9_start",
    27: "key_skill_9",
    28: "key_skill_4",
    29: "key_skill_17",
    30: "key_skill_14_start",
    31: "key_skill_3",
    32: "keyguide_elementalaugment",
    33: "key_skill_18",
    34: "keyguide_cancel",
    35: "flash",
    36: "key_norattack",
    37: "key_skill_8",
    38: "key_skill_8_combo_start",
    39: "keyguide_flashmagnify",
    40: "key_skill_8_combo",
    41: "FullBody",
    42: "keyguide_flash",
    43: "key_kickattack",
    44: "keyguide_attack",
}


def label_name(label: int) -> str:
    return STRING_TABLE.get(label, f"label_{label}")


def iter_uniform_blocks(cond: bytes):
    offsets = []
    pos = 0
    while True:
        idx = cond.find(MARKER, pos)
        if idx < 0:
            break
        offsets.append(idx)
        pos = idx + 1

    for marker_index in range(len(offsets) - 1):
        off = offsets[marker_index]
        if offsets[marker_index + 1] - off != BLOCK_SIZE:
            continue
        block = cond[off:off + BLOCK_SIZE]
        yield {
            "marker_index": marker_index,
            "cond_offset": off,
            "file_offset": COND_START + off,
            "label_file_offset": COND_START + off + LABEL_INDEX_OFF,
            "target_ref": struct.unpack_from("<I", block, TARGET_REF_OFF)[0],
            "source_id": struct.unpack_from("<H", block, SOURCE_ID_OFF)[0],
            "label": struct.unpack_from("<H", block, LABEL_INDEX_OFF)[0],
            "opcode": struct.unpack_from("<H", block, OPCODE_OFF)[0],
            "params": tuple(block[PARAM_START_OFF:PARAM_START_OFF + 3]),
        }


def compress_size(data: bytes) -> int:
    return len(lz4.block.compress(data, store_size=False))


def apply_label_swap(data: bytearray, rec: dict, new_label: int) -> None:
    struct.pack_into("<H", data, rec["label_file_offset"], new_label)


def main() -> None:
    sword = SWORD.read_bytes()
    cond = sword[COND_START:COND_END]
    orig_comp = compress_size(sword)

    lines: list[str] = []

    def log(msg: str = "") -> None:
        lines.append(msg)
        print(msg)

    blocks = list(iter_uniform_blocks(cond))
    by_sig = defaultdict(list)
    for rec in blocks:
        by_sig[(rec["target_ref"], rec["opcode"], rec["params"])].append(rec)

    log("=" * 100)
    log("CONDITION GRAPH PATCH CANDIDATE RANKING")
    log("=" * 100)
    log(f"File: {SWORD}")
    log(f"Uniform blocks: {len(blocks)}")
    log(f"Original LZ4 size: {orig_comp} bytes (target {TARGET_COMPRESSED_SIZE})")
    log()

    special_labels = {1, 17, 20}
    candidate_swaps = []

    for sig, recs in by_sig.items():
        labels = {rec["label"] for rec in recs}
        interesting = labels & special_labels
        if not interesting:
            continue

        target_ref, opcode, params = sig
        label_hist = Counter(rec["label"] for rec in recs)
        log(
            f"SIG target={target_ref:5d} opcode=0x{opcode:04X} params={params} "
            f"labels={{{', '.join(f'{label_name(k)}:{v}' for k, v in sorted(label_hist.items()))}}}"
        )

        for wanted in sorted(interesting):
            for rec in recs:
                if rec["label"] == wanted:
                    continue
                # Avoid proposing obviously bad swaps from non-input UI labels into guard
                if wanted == 1 and rec["label"] in {21, 22, 32, 34, 35, 39, 41, 42, 44}:
                    continue
                patched = bytearray(sword)
                apply_label_swap(patched, rec, wanted)
                new_comp = compress_size(patched)
                delta = new_comp - TARGET_COMPRESSED_SIZE
                candidate_swaps.append({
                    "rec": rec,
                    "new_label": wanted,
                    "new_comp": new_comp,
                    "delta": delta,
                    "sig": sig,
                    "family_labels": dict(label_hist),
                })
                log(
                    f"  swap block#{rec['marker_index']:3d} file+0x{rec['label_file_offset']:06X} "
                    f"{label_name(rec['label'])} -> {label_name(wanted)} "
                    f"src={rec['source_id']:5d} delta={delta:+d}"
                )
        log()

    candidate_swaps.sort(key=lambda item: (abs(item["delta"]), item["rec"]["marker_index"]))

    log("=" * 100)
    log("TOP INDIVIDUAL SIZE-MATCH CANDIDATES")
    log("=" * 100)
    for item in candidate_swaps[:40]:
        rec = item["rec"]
        log(
            f"block#{rec['marker_index']:3d} src={rec['source_id']:5d} "
            f"{label_name(rec['label'])} -> {label_name(item['new_label'])} "
            f"target={rec['target_ref']:5d} opcode=0x{rec['opcode']:04X} "
            f"params={rec['params']} new_comp={item['new_comp']} delta={item['delta']:+d}"
        )
    log()

    exact = [item for item in candidate_swaps if item["delta"] == 0]
    log(f"Exact size-preserving single swaps: {len(exact)}")
    for item in exact[:30]:
        rec = item["rec"]
        log(
            f"  EXACT block#{rec['marker_index']:3d} "
            f"{label_name(rec['label'])} -> {label_name(item['new_label'])} "
            f"target={rec['target_ref']:5d} params={rec['params']}"
        )
    log()

    log("=" * 100)
    log("ACTUAL PAIR COMBINATIONS VERIFIED BY RECOMPRESSION")
    log("=" * 100)
    exact_singles = [item for item in exact if item["rec"]["label_file_offset"]]
    pair_hits = []
    for a, b in itertools.combinations(exact_singles, 2):
        patched = bytearray(sword)
        apply_label_swap(patched, a["rec"], a["new_label"])
        apply_label_swap(patched, b["rec"], b["new_label"])
        new_comp = compress_size(patched)
        if new_comp != TARGET_COMPRESSED_SIZE:
            continue
        pair_hits.append((a, b))

    log(f"Exact verified pair hits: {len(pair_hits)}")
    for a, b in pair_hits:
        ra = a["rec"]
        rb = b["rec"]
        log(
            f"  PAIR A block#{ra['marker_index']:3d} {label_name(ra['label'])}->{label_name(a['new_label'])} | "
            f"B block#{rb['marker_index']:3d} {label_name(rb['label'])}->{label_name(b['new_label'])}"
        )
    log()

    log("=" * 100)
    log("ACTUAL TRIPLE COMBINATIONS VERIFIED BY RECOMPRESSION")
    log("=" * 100)
    triple_hits = []
    for a, b, c in itertools.combinations(exact_singles, 3):
        patched = bytearray(sword)
        apply_label_swap(patched, a["rec"], a["new_label"])
        apply_label_swap(patched, b["rec"], b["new_label"])
        apply_label_swap(patched, c["rec"], c["new_label"])
        new_comp = compress_size(patched)
        if new_comp != TARGET_COMPRESSED_SIZE:
            continue
        triple_hits.append((a, b, c))

    log(f"Exact verified triple hits: {len(triple_hits)}")
    for a, b, c in triple_hits[:30]:
        ra = a["rec"]
        rb = b["rec"]
        rc = c["rec"]
        log(
            f"  TRIPLE blocks #{ra['marker_index']}, #{rb['marker_index']}, #{rc['marker_index']} => "
            f"{label_name(ra['label'])}->{label_name(a['new_label'])}, "
            f"{label_name(rb['label'])}->{label_name(b['new_label'])}, "
            f"{label_name(rc['label'])}->{label_name(c['new_label'])}"
        )
    log()

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nSaved report to {OUT}")


if __name__ == "__main__":
    main()
