#!/usr/bin/env python3
"""
Disassemble the condition graph evaluator code found via memory dump search.

Key addresses identified:
- 0x1402B4A9B: add ebx, 0x104 (block stride in main loop)
- 0x140733243: cmp byte [rcx+0xE5], 7 (key_code comparison)
- 0x14036xxxx: test byte[0xFC] bit 0 (flags gate)
"""

import struct
import capstone

DUMP_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.bin"
MAP_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.map"
IMAGE_BASE = 0x140000000

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
                'type': parts[4],
            })
    return sections

def va_to_file_off(va, sections):
    for s in sections:
        if s['va'] <= va < s['va'] + s['size']:
            return s['file_off'] + (va - s['va'])
    return None

def disasm_region(dump, sections, center_va, radius=256, label=""):
    """Disassemble a region centered on center_va."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    start_va = center_va - radius
    end_va = center_va + radius

    foff = va_to_file_off(start_va, sections)
    if foff is None:
        print(f"  Cannot map VA {start_va:#x}")
        return

    code = dump[foff:foff + 2 * radius]

    print(f"\n{'='*100}")
    print(f"DISASSEMBLY: {label}")
    print(f"Center: {center_va:#x}, Range: {start_va:#x} - {end_va:#x}")
    print(f"{'='*100}")

    # Known field offsets in 260-byte blocks
    field_offsets = {
        0x50: 'byte[80]',
        0x54: 'magic84',
        0x5C: 'byte[92]',
        0x7E: 'byte[126]',
        0x94: 'byte[148]',
        0x9C: 'byte[156]',
        0xD4: 'source_id',
        0xD8: 'label_index',
        0xDE: 'byte[222]',
        0xE0: 'opcode_start',
        0xE5: 'KEY_CODE',
        0xE6: 'byte[230]',
        0xE7: 'byte[231]',
        0xF5: 'byte[245]',
        0xF6: 'target_family',
        0xFC: 'FLAGS_START',
        0xFD: 'flags[1]',
        0xFE: 'flags[2]',
        0xFF: 'flags[3]',
        0x100: 'flags[4]',
        0x101: 'flags[5]',
        0x102: 'flags[6]',
        0x103: 'flags[7]',
        0x104: 'BLOCK_STRIDE(260)',
    }

    for insn in md.disasm(code, start_va):
        marker = ""
        # Annotate instructions that access block fields
        op_str = insn.op_str
        for off, name in field_offsets.items():
            if f"0x{off:x}" in op_str or f"{off:#x}" in op_str:
                marker = f"  <<< {name}"
                break

        if insn.address == center_va:
            marker += "  ★★★ CENTER ★★★"

        addr_str = f"{insn.address:#x}"
        print(f"  {addr_str}:  {insn.mnemonic:8s} {op_str:50s}{marker}")

        if insn.address > end_va:
            break


def main():
    sections = parse_map(MAP_PATH)
    with open(DUMP_PATH, 'rb') as f:
        dump = f.read()

    # Key addresses to disassemble — focused on actual evaluator code
    targets = [
        (0x140733243, 200, "KEY_CODE CMP 7: movzx eax,[rcx+0xE5]; cmp al,7; jz"),
        (0x14035A2B6, 200, "FLAGS BIT0 TEST: movzx edx,[rax+0xFC]; test dl,1; jz"),
        (0x1403660A6, 200, "FLAGS BIT0 TEST #2: cluster of flag checks"),
        (0x141289980, 200, "KEY_CODE BIT SHIFT: movzx eax,[rsi+0xE5]; shr al,6"),
    ]

    for va, radius, label in targets:
        disasm_region(dump, sections, va, radius, label)


if __name__ == "__main__":
    main()
