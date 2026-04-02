#!/usr/bin/env python3
"""
Step 1: Cross-tabulate condition graph fields to decode the bytecode.

Key question: is byte[229] (key_code) the same as byte[216] (label_index)?
If they correlate 1:1, the control is elsewhere (bytes[252:260] bitfield).
If they differ, byte[229] is the actual input trigger.

Also analyzes the full opcode region (bytes[224:234]) and flags (bytes[252:260]).
"""

import struct
import os
from collections import Counter, defaultdict

SWORD = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
COND_START = 0x97996
COND_END = 0x12FA79

STRING_TABLE = {
    0: "upperaction/1_pc/1_phm/common_upper_branchset",
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
    25: "key_dash",
    27: "key_skill_9",
    28: "key_skill_4",
    29: "key_skill_17",
    31: "key_skill_3",
    33: "key_skill_18",
    36: "key_norattack",
    37: "key_skill_8",
    40: "key_skill_8_combo",
    43: "key_kickattack",
}

def label_name(idx):
    return STRING_TABLE.get(idx, f"?idx={idx}")


def parse_blocks(paac_path, cond_start=None, cond_end=None):
    """Parse M0%D blocks from a .paac file. Auto-detect condition section if offsets not given."""
    with open(paac_path, "rb") as f:
        data = f.read()

    if cond_start is None:
        # Find first M0%D marker
        magic = b'\x4D\x30\x25\x44'
        cond_start = data.find(magic)
        if cond_start == -1:
            return [], data
        cond_end = len(data)

    cond = data[cond_start:cond_end]

    magic = b'\x4D\x30\x25\x44'
    offsets = []
    pos = 0
    while True:
        idx = cond.find(magic, pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + 1

    blocks = []
    for i in range(len(offsets) - 1):
        if offsets[i + 1] - offsets[i] == 260:
            off = offsets[i]
            blocks.append(cond[off:off + 260])

    return blocks, data


def extract_fields(block):
    """Extract all interesting fields from a 260-byte block."""
    return {
        'source_id': struct.unpack_from("<H", block, 212)[0],
        'label_index': block[216],
        'byte_222': block[222],
        'opcode_prefix': block[224:227],  # bytes 224-226
        'opcode_full': block[224:234],     # bytes 224-233
        'key_code': block[229],
        'byte_230': block[230],            # after key_code
        'byte_231_233': block[231:234],
        'byte_237_238': struct.unpack_from("<H", block, 237)[0],
        'byte_240': block[240],
        'target_family': struct.unpack_from("<I", block, 246)[0],
        'flags': block[252:260],
        'byte_80_81': struct.unpack_from("<H", block, 80)[0],
        'byte_92_95': struct.unpack_from("<I", block, 92)[0],
        'byte_4_5': struct.unpack_from("<H", block, 4)[0],
        'byte_8_14': block[8:15],
        'byte_146_153': block[146:154],
    }


def main():
    blocks, _ = parse_blocks(SWORD, COND_START, COND_END)
    print(f"Parsed {len(blocks)} uniform 260-byte blocks from sword_upper.paac\n")

    fields = [extract_fields(b) for b in blocks]

    # ============================================================
    # 1. CROSS-TAB: label_index vs key_code
    # ============================================================
    print("=" * 100)
    print("1. CROSS-TABULATION: byte[216] (label_index) vs byte[229] (key_code)")
    print("=" * 100)

    cross = defaultdict(Counter)  # label -> Counter(key_code)
    for f in fields:
        cross[f['label_index']][f['key_code']] += 1

    # Print as table
    all_key_codes = sorted(set(f['key_code'] for f in fields))
    header = f"{'label_idx':>10s} {'label_name':>30s} | " + " ".join(f"kc={k:#04x}" for k in all_key_codes) + " | total"
    print(header)
    print("-" * len(header))

    for li in sorted(cross.keys()):
        name = label_name(li)[:30]
        counts = [str(cross[li].get(kc, '')).rjust(7) for kc in all_key_codes]
        total = sum(cross[li].values())
        print(f"{li:>10d} {name:>30s} | {' '.join(counts)} | {total:>5d}")

    print()

    # ============================================================
    # 2. REVERSE: key_code -> which labels use it
    # ============================================================
    print("=" * 100)
    print("2. REVERSE: key_code -> label distribution")
    print("=" * 100)

    rev = defaultdict(Counter)
    for f in fields:
        rev[f['key_code']][f['label_index']] += 1

    for kc in sorted(rev.keys()):
        print(f"\n  key_code=0x{kc:02X} ({sum(rev[kc].values())} blocks):")
        for li, cnt in rev[kc].most_common():
            print(f"    label={li:>2d} ({label_name(li):>30s}): {cnt}")

    print()

    # ============================================================
    # 3. CORRELATION CHECK: does label_index == key_code?
    # ============================================================
    print("=" * 100)
    print("3. CORRELATION CHECK: label_index vs key_code")
    print("=" * 100)

    match = sum(1 for f in fields if f['label_index'] == f['key_code'])
    print(f"  Blocks where label_index == key_code: {match} / {len(fields)}")

    # Check 1:1 mapping
    li_to_kc = {}
    for f in fields:
        li = f['label_index']
        kc = f['key_code']
        if li not in li_to_kc:
            li_to_kc[li] = set()
        li_to_kc[li].add(kc)

    print(f"\n  label_index -> key_code mapping (1:many?):")
    for li in sorted(li_to_kc.keys()):
        kcs = sorted(li_to_kc[li])
        marker = " *** MULTI ***" if len(kcs) > 1 else ""
        print(f"    label={li:>2d} ({label_name(li):>30s}) -> key_codes: {[hex(k) for k in kcs]}{marker}")

    print()

    # ============================================================
    # 4. FULL DETAILS FOR GUARD-RELATED BLOCKS
    # ============================================================
    print("=" * 100)
    print("4. ALL GUARD-RELATED BLOCKS (label_index=1 OR key_code that correlates with guard)")
    print("=" * 100)

    for i, f in enumerate(fields):
        if f['label_index'] == 1 or (1 in li_to_kc and f['key_code'] in li_to_kc[1]):
            flags_hex = f['flags'].hex(' ').upper()
            opcode_hex = f['opcode_full'].hex(' ').upper()
            print(f"  Block {i:>3d}: src={f['source_id']:>5d} label={f['label_index']:>2d}({label_name(f['label_index']):>15s}) "
                  f"kc=0x{f['key_code']:02X} tgt={f['target_family']:>6d} "
                  f"opcode=[{opcode_hex}] flags=[{flags_hex}]")

    print()

    # ============================================================
    # 5. OPCODE PREFIX ANALYSIS: bytes[224:226]
    # ============================================================
    print("=" * 100)
    print("5. OPCODE PREFIX: bytes[224:227] distribution")
    print("=" * 100)

    prefix_counts = Counter(f['opcode_prefix'] for f in fields)
    for pfix, cnt in prefix_counts.most_common():
        print(f"  {pfix.hex(' ').upper()}: {cnt}")

    # Cross-tab prefix vs key_code
    print("\n  Prefix vs key_code:")
    px_kc = defaultdict(Counter)
    for f in fields:
        px_kc[f['opcode_prefix'].hex()][f['key_code']] += 1
    for px in sorted(px_kc.keys()):
        dist = ", ".join(f"0x{kc:02X}:{cnt}" for kc, cnt in sorted(px_kc[px].items()))
        print(f"    {px}: {dist}")

    print()

    # ============================================================
    # 6. FLAGS (bytes[252:260]) ANALYSIS BY LABEL
    # ============================================================
    print("=" * 100)
    print("6. FLAGS (bytes[252:260]) — grouped by label_index")
    print("=" * 100)

    flags_by_label = defaultdict(list)
    for f in fields:
        flags_by_label[f['label_index']].append(f['flags'])

    for li in sorted(flags_by_label.keys()):
        flag_set = flags_by_label[li]
        # Compute per-byte bit union and intersection
        union = [0] * 8
        inter = [0xFF] * 8
        for fl in flag_set:
            for j in range(8):
                union[j] |= fl[j]
                inter[j] &= fl[j]
        union_hex = " ".join(f"{b:02X}" for b in union)
        inter_hex = " ".join(f"{b:02X}" for b in inter)
        print(f"  label={li:>2d} ({label_name(li):>30s}) [{len(flag_set):>3d} blocks]: "
              f"union=[{union_hex}] inter=[{inter_hex}]")

    print()

    # ============================================================
    # 7. FLAGS by key_code
    # ============================================================
    print("=" * 100)
    print("7. FLAGS (bytes[252:260]) — grouped by key_code")
    print("=" * 100)

    flags_by_kc = defaultdict(list)
    for f in fields:
        flags_by_kc[f['key_code']].append(f['flags'])

    for kc in sorted(flags_by_kc.keys()):
        flag_set = flags_by_kc[kc]
        union = [0] * 8
        inter = [0xFF] * 8
        for fl in flag_set:
            for j in range(8):
                union[j] |= fl[j]
                inter[j] &= fl[j]
        union_hex = " ".join(f"{b:02X}" for b in union)
        inter_hex = " ".join(f"{b:02X}" for b in inter)
        print(f"  kc=0x{kc:02X} [{len(flag_set):>3d} blocks]: union=[{union_hex}] inter=[{inter_hex}]")

    print()

    # ============================================================
    # 8. BYTE[230] (after key_code) and BYTE[231:234] distribution
    # ============================================================
    print("=" * 100)
    print("8. POST-KEYCODE: byte[230] and bytes[231:234]")
    print("=" * 100)

    print(f"  byte[230] histogram: {dict(Counter(f['byte_230'] for f in fields).most_common())}")
    b231 = Counter(f['byte_231_233'] for f in fields)
    print(f"  bytes[231:234] top patterns:")
    for pat, cnt in b231.most_common(10):
        print(f"    {pat.hex(' ').upper()}: {cnt}")

    print()

    # ============================================================
    # 9. TARGET_FAMILY analysis
    # ============================================================
    print("=" * 100)
    print("9. TARGET_FAMILY (bytes[246:250]) distribution")
    print("=" * 100)

    tgt_counts = Counter(f['target_family'] for f in fields)
    for tgt, cnt in tgt_counts.most_common(10):
        # Which labels target each family?
        labels = Counter(f2['label_index'] for f2 in fields if f2['target_family'] == tgt)
        label_str = ", ".join(f"{label_name(li)}({cnt2})" for li, cnt2 in labels.most_common(5))
        print(f"  family={tgt:>8d} [{cnt:>3d} blocks]: {label_str}")


if __name__ == "__main__":
    main()
