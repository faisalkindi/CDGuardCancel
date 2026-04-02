#!/usr/bin/env python3
"""
Step 4: Find the condition graph evaluator in the memory dump.

Searches the 542MB decrypted memory dump for code that references:
- 0x44253044 (M0%D magic) — comparison/validation
- 0x104 (260 decimal) — block stride
- 0xEF8FF582 (magic at block+84) — validation constant
- 0x0281676D (magic at block+148) — another fixed value

Uses raw pattern matching (no disassembler needed for first pass).
"""

import struct
import os
import time

DUMP_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.bin"
MAP_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.map"
IMAGE_BASE = 0x140000000

# Magic constants from the 260-byte blocks
MAGICS = {
    'M0%D':            0x44253044,
    'block_magic_84':  0xEF8FF582,
    'block_magic_148': 0x0281676D,
    'block_size':      0x00000104,  # 260
    'minus_one':       0xBF800000,  # -1.0f
}


def parse_map(map_path):
    sections = []
    with open(map_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 5:
                continue
            sections.append({
                'file_off': int(parts[0], 16),
                'va': int(parts[1], 16),
                'size': int(parts[2], 16),
                'protect': int(parts[3], 16),
                'type': parts[4],
            })
    return sections


def file_off_to_va(off, sections):
    for s in sections:
        if s['file_off'] <= off < s['file_off'] + s['size']:
            return s['va'] + (off - s['file_off'])
    return None


def main():
    print("[*] Loading memory dump...")
    t0 = time.time()

    sections = parse_map(MAP_PATH)
    code_sections = [s for s in sections if s['type'] == 'CODE']
    data_sections = [s for s in sections if s['type'] == 'DATA']
    total_code = sum(s['size'] for s in code_sections)
    total_data = sum(s['size'] for s in data_sections)

    print(f"[*] {len(code_sections)} CODE sections ({total_code / 1024 / 1024:.1f} MB)")
    print(f"[*] {len(data_sections)} DATA sections ({total_data / 1024 / 1024:.1f} MB)")

    with open(DUMP_PATH, 'rb') as f:
        dump = f.read()
    print(f"[*] Loaded {len(dump) / 1024 / 1024:.1f} MB in {time.time() - t0:.1f}s")

    # ============================================================
    # Phase 1: Search CODE sections for magic constant immediates
    # ============================================================
    print(f"\n[*] Phase 1: Searching CODE sections for magic immediates...")

    for magic_name, magic_val in MAGICS.items():
        needle = struct.pack('<I', magic_val)
        print(f"\n  Searching for {magic_name} = 0x{magic_val:08X} ({needle.hex()})...")

        hits = []
        for s in code_sections:
            start = s['file_off']
            end = start + s['size']
            pos = start
            while pos < end:
                pos = dump.find(needle, pos, end)
                if pos == -1:
                    break
                va = file_off_to_va(pos, sections)
                hits.append((pos, va))
                pos += 1

        print(f"    Found {len(hits)} hits in CODE sections")

        # For each hit, show context (32 bytes before and after)
        for hit_foff, hit_va in hits[:30]:
            ctx_start = max(0, hit_foff - 32)
            ctx_end = min(len(dump), hit_foff + 36)
            ctx = dump[ctx_start:ctx_end]
            # Format as hex
            before = dump[ctx_start:hit_foff].hex(' ')
            at = dump[hit_foff:hit_foff + 4].hex(' ')
            after = dump[hit_foff + 4:ctx_end].hex(' ')
            va_str = f"0x{hit_va:X}" if hit_va else "unmapped"
            rel_to_base = hit_foff - ctx_start
            print(f"    [{va_str}] ...{before} [{at}] {after}...")

        if len(hits) > 30:
            print(f"    ... {len(hits) - 30} more hits not shown")

    # ============================================================
    # Phase 2: Search for block stride 260 in CODE as add/imul
    # ============================================================
    print(f"\n[*] Phase 2: Searching for stride patterns (imul/add with 260)...")

    # x86-64 patterns:
    # ADD reg, 0x104:  various opcodes ending in 04 01 00 00
    # IMUL reg, reg, 0x104: 69 xx 04 01 00 00
    # LEA reg, [reg + 0x104]: various
    # CMP reg, 0x104: 81 xx 04 01 00 00

    stride_needle = struct.pack('<I', 260)  # 04 01 00 00
    hits = []
    for s in code_sections:
        start = s['file_off']
        end = start + s['size']
        pos = start
        while pos < end:
            pos = dump.find(stride_needle, pos, end)
            if pos == -1:
                break
            # Check if this looks like an instruction operand
            # Look at the byte before for opcode clues
            if pos >= 2:
                pre2 = dump[pos - 2:pos]
                pre1 = dump[pos - 1:pos]
                # IMUL r, r, imm32: 69 ModRM imm32
                # ADD r, imm32: 81 C0+r imm32 (or 05 imm32 for EAX)
                # CMP r, imm32: 81 F8+r imm32 (or 3D imm32 for EAX)
                # SUB r, imm32: 81 E8+r imm32
                if pre2[0] == 0x69:  # IMUL
                    va = file_off_to_va(pos - 2, sections)
                    hits.append((pos - 2, va, 'IMUL'))
                elif pre2[0] == 0x81:
                    modrm = pre2[1]
                    reg = (modrm >> 3) & 7
                    if reg == 0:
                        va = file_off_to_va(pos - 2, sections)
                        hits.append((pos - 2, va, 'ADD'))
                    elif reg == 7:
                        va = file_off_to_va(pos - 2, sections)
                        hits.append((pos - 2, va, 'CMP'))
                    elif reg == 5:
                        va = file_off_to_va(pos - 2, sections)
                        hits.append((pos - 2, va, 'SUB'))
                elif pre1[0] == 0x05:  # ADD EAX, imm32
                    va = file_off_to_va(pos - 1, sections)
                    hits.append((pos - 1, va, 'ADD_EAX'))
                elif pre1[0] == 0x3D:  # CMP EAX, imm32
                    va = file_off_to_va(pos - 1, sections)
                    hits.append((pos - 1, va, 'CMP_EAX'))
            pos += 1

    print(f"  Found {len(hits)} instruction-like hits for stride 260")
    for foff, va, insn_type in hits[:50]:
        va_str = f"0x{va:X}" if va else "unmapped"
        ctx = dump[foff:min(foff + 16, len(dump))].hex(' ')
        print(f"    [{va_str}] {insn_type}: {ctx}")
    if len(hits) > 50:
        print(f"    ... {len(hits) - 50} more")

    # ============================================================
    # Phase 3: Search DATA sections for M0%D block templates
    # ============================================================
    print(f"\n[*] Phase 3: Searching DATA for M0%D block instances (in-memory charts)...")

    m0pd = struct.pack('<I', 0x44253044)
    hits = []
    for s in data_sections:
        start = s['file_off']
        end = start + s['size']
        pos = start
        while pos < end:
            pos = dump.find(m0pd, pos, end)
            if pos == -1:
                break
            # Check if this looks like a real block (check magic at +84)
            if pos + 260 <= len(dump):
                magic84 = struct.unpack_from("<I", dump, pos + 84)[0]
                if magic84 == 0xEF8FF582:
                    va = file_off_to_va(pos, sections)
                    hits.append((pos, va))
            pos += 4

    print(f"  Found {len(hits)} valid M0%D blocks in DATA sections")
    if hits:
        print(f"  First 10:")
        for foff, va in hits[:10]:
            va_str = f"0x{va:X}" if va else "unmapped"
            # Read label_index and key_code from this block
            li = dump[foff + 216]
            kc = dump[foff + 229]
            src = struct.unpack_from("<H", dump, foff + 212)[0]
            print(f"    [{va_str}] src={src} label_idx={li} key_code=0x{kc:02X}")

    # ============================================================
    # Phase 4: Find xrefs to DATA M0%D blocks from CODE
    # ============================================================
    if hits:
        print(f"\n[*] Phase 4: Finding CODE xrefs to M0%D block regions...")

        # Take the first block's VA and search for it as an immediate in code
        for block_foff, block_va in hits[:5]:
            if block_va is None:
                continue
            # Search for RIP-relative addressing: the block VA as a 32-bit offset
            # In x86-64, LEA instructions use RIP-relative: target = RIP + disp32
            # So we look for disp32 values that, when added to their RIP, point to block_va
            block_rva = block_va - IMAGE_BASE
            needle_bytes = struct.pack('<Q', block_va)
            print(f"\n  Looking for absolute refs to block at {block_va:#x}...")

            refs = []
            for s in code_sections:
                start = s['file_off']
                end = start + s['size']
                pos = start
                while pos < end:
                    pos = dump.find(needle_bytes, pos, end)
                    if pos == -1:
                        break
                    va = file_off_to_va(pos, sections)
                    refs.append((pos, va))
                    pos += 1

            print(f"    Found {len(refs)} absolute refs")
            for foff, va in refs[:10]:
                ctx = dump[max(0, foff - 8):foff + 16].hex(' ')
                print(f"    [{va:#x}] ...{ctx}")

    # ============================================================
    # Phase 5: Search for field offset constants in CODE
    # ============================================================
    print(f"\n[*] Phase 5: Searching CODE for field offset constants...")

    # Key offsets within the 260-byte block that the evaluator must use:
    field_offsets = {
        0xD4: 'source_id (byte 212)',
        0xD8: 'label_index (byte 216)',
        0xE0: 'opcode_start (byte 224)',
        0xE5: 'key_code (byte 229)',
        0xFC: 'flags_start (byte 252)',
        0x54: 'magic84 (byte 84)',
    }

    for offset_val, desc in field_offsets.items():
        # Search for MOVZX or MOV with this displacement
        # movzx eax, byte [reg+0xD8]: 0F B6 xx D8
        # Only search if the offset fits in a byte (signed: -128 to 127) or uint8
        if offset_val <= 0x7F:
            # Byte displacement: look for xx offset_val patterns
            needle = bytes([offset_val])
        else:
            # Dword displacement: look for 4-byte LE
            needle = struct.pack('<I', offset_val)

        print(f"\n  Offset 0x{offset_val:02X} ({desc}):")
        # This will have too many false positives for byte-sized offsets
        # Only search for the dword-sized ones (>127)
        if offset_val > 0x7F:
            hit_count = 0
            for s in code_sections:
                start = s['file_off']
                end = start + s['size']
                pos = start
                while pos < end:
                    pos = dump.find(needle, pos, end)
                    if pos == -1:
                        break
                    # Check for MOV/MOVZX opcode before
                    if pos >= 3:
                        pre = dump[pos - 3:pos]
                        # 0F B6 xx = MOVZX r32, byte [reg+disp32]
                        # 0F B7 xx = MOVZX r32, word [reg+disp32]
                        # 8B xx = MOV r32, [reg+disp32]
                        if pre[0] == 0x0F and pre[1] in (0xB6, 0xB7):
                            va = file_off_to_va(pos - 3, sections)
                            if va:
                                ctx = dump[pos - 3:pos + 8].hex(' ')
                                if hit_count < 10:
                                    print(f"    [{va:#x}] MOVZX: {ctx}")
                                hit_count += 1
                        elif pre[1] == 0x8B:
                            va = file_off_to_va(pos - 2, sections)
                            if va:
                                ctx = dump[pos - 2:pos + 8].hex(' ')
                                if hit_count < 10:
                                    print(f"    [{va:#x}] MOV: {ctx}")
                                hit_count += 1
                    pos += 1
            print(f"    Total: {hit_count} hits")
        else:
            print(f"    (skipped — byte-sized offset too many false positives)")

    print(f"\n[*] Done in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
