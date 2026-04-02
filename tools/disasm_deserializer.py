#!/usr/bin/env python3
"""
Disassemble .paac deserialization functions from the Crimson Desert memory dump.

Targets:
  1. Function containing 0x141289980 (key_code byte copy instruction)
  2. 0x141912ff0 — ActionChartPackage_BaseData::slot[2] (deserializer vtable func)

Goal: Map serialized field offsets (in the .paac 260-byte M0%D blocks) to runtime
object field offsets by finding all reg+offset -> reg+offset move patterns.
"""

import sys, io, os, struct, json
import capstone

# Force UTF-8 stdout
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DUMP_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.bin"
MAP_PATH  = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.map"
RTTI_PATH = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDInstantSkin\tools\dump_rtti_all.json"
IMAGE_BASE = 0x140000000
OUTPUT_PATH = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\deserialization_map.txt"

# Known serialized offsets in the 260-byte M0%D blocks
KNOWN_SERIAL_OFFSETS = {
    0xD4: 'source_id',
    0xD8: 'label_index',
    0xE0: 'opcode_start',
    0xE5: 'key_code',
    0xFC: 'flags',
}

# ─── Map parsing ────────────────────────────────────────────────────────────

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
                'va':       int(parts[1], 16),
                'size':     int(parts[2], 16),
                'type':     parts[4],
            })
    return sections

def va_to_file_off(va, sections):
    for s in sections:
        if s['va'] <= va < s['va'] + s['size']:
            return s['file_off'] + (va - s['va'])
    return None

def read_bytes_at_va(dump, sections, va, count):
    foff = va_to_file_off(va, sections)
    if foff is None:
        return None
    return dump[foff:foff + count]

# ─── Function boundary detection ────────────────────────────────────────────

def find_function_start(dump, sections, addr, max_scan=8192):
    """Scan backwards from addr to find function prologue.

    Strategy: Find runs of 3+ CC bytes (inter-function padding) and take the
    last such boundary before our target address. Single CC bytes can appear
    inside functions (e.g., debug breaks, misaligned data) so we require 3+.
    """
    scan_start = addr - max_scan
    data = read_bytes_at_va(dump, sections, scan_start, max_scan + 64)
    if data is None:
        return addr

    best_start = None

    # Find runs of 3+ consecutive CC bytes, take the instruction after the last run
    i = 0
    while i < max_scan:
        if data[i] == 0xCC:
            j = i
            while j < max_scan and data[j] == 0xCC:
                j += 1
            run_len = j - i
            if run_len >= 3 and j < max_scan:
                candidate_va = scan_start + j
                if candidate_va <= addr:
                    best_start = candidate_va
            i = j
        else:
            i += 1

    if best_start is not None:
        return best_start

    # Fallback: look for common x64 prologues on 16-byte aligned addresses
    for offset in range(max_scan, 0, -1):
        va_cand = scan_start + offset
        if va_cand > addr or va_cand % 16 != 0:
            continue
        b = data[offset:offset+5]
        if len(b) < 5:
            continue
        if (b[:4] == b'\x48\x89\x5C\x24' or    # mov [rsp+x], rbx
            b[:4] == b'\x48\x89\x6C\x24' or    # mov [rsp+x], rbp
            b[:4] == b'\x48\x89\x74\x24' or    # mov [rsp+x], rsi
            b[:4] == b'\x4C\x89\x4C\x24' or    # mov [rsp+x], r9
            b[:3] == b'\x48\x83\xEC' or         # sub rsp, imm8
            b[:3] == b'\x48\x81\xEC' or         # sub rsp, imm32
            b[:2] == b'\x40\x55' or              # REX push rbp
            b[:2] == b'\x40\x53' or              # REX push rbx
            b[0] == 0x55):                        # push rbp
            best_start = va_cand

    return best_start if best_start else addr - 256

def find_function_end(dump, sections, start_va, max_size=8192):
    """Find function end: ret followed by CC padding or next function."""
    data = read_bytes_at_va(dump, sections, start_va, max_size)
    if data is None:
        return start_va + 256

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    last_ret_end = None
    for insn in md.disasm(data, start_va):
        offset = insn.address - start_va
        if offset >= max_size:
            break
        # ret / retn
        if insn.mnemonic in ('ret', 'retn'):
            end_offset = offset + insn.size
            # Check if followed by CC padding or another function
            if end_offset < len(data):
                next_byte = data[end_offset]
                if next_byte == 0xCC:
                    return insn.address + insn.size
                # Could be followed by another ret or jump table — keep looking
                last_ret_end = insn.address + insn.size
        # jmp with no fallthrough (unconditional) followed by CC
        if insn.mnemonic == 'jmp' and not insn.op_str.startswith('['):
            end_offset = offset + insn.size
            if end_offset < len(data) and data[end_offset] == 0xCC:
                return insn.address + insn.size

    return last_ret_end if last_ret_end else start_va + max_size

# ─── Disassembly and field mapping ──────────────────────────────────────────

def disasm_function(dump, sections, func_start, func_end, label=""):
    """Disassemble function and extract offset-to-offset mappings."""
    size = func_end - func_start
    data = read_bytes_at_va(dump, sections, func_start, size)
    if data is None:
        return [], []

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    instructions = []
    for insn in md.disasm(data, func_start):
        if insn.address >= func_end:
            break
        instructions.append(insn)

    return instructions

def extract_offset_mappings(instructions):
    """
    Find patterns where data is loaded from [regA + src_off] then stored to [regB + dst_off].

    Looks for IMMEDIATE load-then-store pairs (within a small window) where:
      1. A register is loaded from [regA + offset]  (mov/movzx/movsx)
      2. That same register (or sub-register) is stored to [regB + offset]
      3. regA != regB (different source and destination objects)
      4. The load result isn't used as a pointer (no intermediate dereference)

    Also handles bit-field extractions like:
      movzx eax, byte [rsi+0xE5]
      shr al, 6
      and al, 1
      mov [rbx+0x126], al
    """
    mappings = []

    # Track the most recent load into each base register family
    # Value: (source_base_reg, source_offset, load_width, load_va, is_transformed)
    pending_loads = {}

    for i, insn in enumerate(instructions):
        mnem = insn.mnemonic

        # ── Load from memory ──
        if mnem in ('mov', 'movzx', 'movsx', 'movsxd'):
            load_match = parse_mem_load(insn)
            if load_match:
                dst_reg, src_reg, src_off, width = load_match
                base_dst = get_base_reg(dst_reg)
                base_src = get_base_reg(src_reg)
                # Only track loads from base+positive_offset (skip stack/rsp/rbp-relative loads
                # unless offset is large enough to be a struct field)
                if base_src not in ('rsp', 'rbp') and src_off >= 0:
                    pending_loads[base_dst] = (base_src, src_off, width, insn.address, False)
                elif base_src in ('rsp', 'rbp') and src_off > 0x40:
                    # Large stack offsets might be struct fields too
                    pending_loads[base_dst] = (base_src, src_off, width, insn.address, False)
                else:
                    # Loading from stack/small offset — invalidate this register as a field source
                    pending_loads.pop(base_dst, None)
                continue

            # ── Store to memory ──
            store_match = parse_mem_store(insn)
            if store_match:
                dst_reg, dst_off, src_reg, width = store_match
                base_src = get_base_reg(src_reg)
                base_dst = get_base_reg(dst_reg)

                if base_src in pending_loads:
                    ld_base_src, ld_src_off, ld_width, ld_addr, transformed = pending_loads[base_src]
                    # Source and dest must be different registers
                    if ld_base_src != base_dst and dst_off >= 0:
                        mappings.append({
                            'src_reg': ld_base_src,
                            'src_off': ld_src_off,
                            'dst_reg': base_dst,
                            'dst_off': dst_off,
                            'width': ld_width,
                            'store_width': width,
                            'load_va': ld_addr,
                            'store_va': insn.address,
                            'transformed': transformed,
                        })
                continue

        # ── Transformations that don't invalidate the load source ──
        # (shr, and, or, add, shl, xor on the loaded register)
        if mnem in ('shr', 'shl', 'and', 'or', 'xor', 'add', 'inc', 'dec', 'not', 'neg'):
            if len(insn.operands) >= 1 and insn.operands[0].type == capstone.x86.X86_OP_REG:
                base = get_base_reg(insn.reg_name(insn.operands[0].reg))
                if base in pending_loads:
                    # Mark as transformed but keep tracking
                    entry = pending_loads[base]
                    pending_loads[base] = (entry[0], entry[1], entry[2], entry[3], True)
            continue

        # ── Clear on call (clobbers rax, rcx, rdx, r8-r11) ──
        if mnem in ('call', 'syscall'):
            for r in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                pending_loads.pop(r, None)
            continue

        # ── Clear specific register on other writes ──
        if len(insn.operands) >= 1 and insn.operands[0].type == capstone.x86.X86_OP_REG:
            base = get_base_reg(insn.reg_name(insn.operands[0].reg))
            if mnem not in ('cmp', 'test'):  # cmp/test don't write
                pending_loads.pop(base, None)

    return mappings

def parse_mem_load(insn):
    """Parse: mov/movzx dst_reg, [src_reg + offset] -> (dst_reg, src_reg, offset, width)"""
    if len(insn.operands) != 2:
        return None
    dst, src = insn.operands
    if dst.type != capstone.x86.X86_OP_REG:
        return None
    if src.type != capstone.x86.X86_OP_MEM:
        return None
    if src.mem.base == 0:
        return None
    # Skip RIP-relative
    if src.mem.base == capstone.x86.X86_REG_RIP:
        return None
    if src.mem.index != 0:
        return None  # skip scaled index forms

    dst_reg = insn.reg_name(dst.reg)
    src_reg = insn.reg_name(src.mem.base)
    src_off = src.mem.disp
    width = src.size
    return (dst_reg, src_reg, src_off, width)

def parse_mem_store(insn):
    """Parse: mov [dst_reg + offset], src_reg -> (dst_reg, offset, src_reg, width)"""
    if insn.mnemonic not in ('mov',):
        return None
    if len(insn.operands) != 2:
        return None
    dst, src = insn.operands
    if dst.type != capstone.x86.X86_OP_MEM:
        return None
    if src.type != capstone.x86.X86_OP_REG:
        return None
    if dst.mem.base == 0:
        return None
    if dst.mem.base == capstone.x86.X86_REG_RIP:
        return None
    if dst.mem.index != 0:
        return None

    dst_reg = insn.reg_name(dst.mem.base)
    dst_off = dst.mem.disp
    src_reg = insn.reg_name(src.reg)
    width = dst.size
    return (dst_reg, dst_off, src_reg, width)

REG_FAMILIES = {
    'al': 'rax', 'ah': 'rax', 'ax': 'rax', 'eax': 'rax', 'rax': 'rax',
    'bl': 'rbx', 'bh': 'rbx', 'bx': 'rbx', 'ebx': 'rbx', 'rbx': 'rbx',
    'cl': 'rcx', 'ch': 'rcx', 'cx': 'rcx', 'ecx': 'rcx', 'rcx': 'rcx',
    'dl': 'rdx', 'dh': 'rdx', 'dx': 'rdx', 'edx': 'rdx', 'rdx': 'rdx',
    'sil': 'rsi', 'si': 'rsi', 'esi': 'rsi', 'rsi': 'rsi',
    'dil': 'rdi', 'di': 'rdi', 'edi': 'rdi', 'rdi': 'rdi',
    'bpl': 'rbp', 'bp': 'rbp', 'ebp': 'rbp', 'rbp': 'rbp',
    'spl': 'rsp', 'sp': 'rsp', 'esp': 'rsp', 'rsp': 'rsp',
    'r8b': 'r8', 'r8w': 'r8', 'r8d': 'r8', 'r8': 'r8',
    'r9b': 'r9', 'r9w': 'r9', 'r9d': 'r9', 'r9': 'r9',
    'r10b': 'r10', 'r10w': 'r10', 'r10d': 'r10', 'r10': 'r10',
    'r11b': 'r11', 'r11w': 'r11', 'r11d': 'r11', 'r11': 'r11',
    'r12b': 'r12', 'r12w': 'r12', 'r12d': 'r12', 'r12': 'r12',
    'r13b': 'r13', 'r13w': 'r13', 'r13d': 'r13', 'r13': 'r13',
    'r14b': 'r14', 'r14w': 'r14', 'r14d': 'r14', 'r14': 'r14',
    'r15b': 'r15', 'r15w': 'r15', 'r15d': 'r15', 'r15': 'r15',
}

def get_base_reg(reg_name):
    return REG_FAMILIES.get(reg_name, reg_name)

def width_str(w):
    return {1: 'byte', 2: 'word', 4: 'dword', 8: 'qword'}.get(w, f'{w}B')

# ─── RTTI vtable lookup ────────────────────────────────────────────────────

def load_rtti(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def find_vtable_owner(rtti_data, func_va):
    """Check if func_va appears in any vtable slots."""
    target = f"0x{func_va:x}"
    results = []
    for entry in rtti_data:
        slots = entry.get('slots', [])
        for idx, slot_va in enumerate(slots):
            if slot_va.lower() == target.lower():
                results.append((entry['name'], entry.get('vtable_va', '?'), idx))
    return results

# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    out_lines = []
    def emit(s=""):
        print(s)
        out_lines.append(s)

    emit("=" * 100)
    emit("PAAC Deserialization Function Disassembler")
    emit("=" * 100)

    # Load resources
    emit("\n[*] Loading memory map...")
    sections = parse_map(MAP_PATH)
    emit(f"    {len(sections)} sections loaded")

    emit("[*] Loading memory dump...")
    with open(DUMP_PATH, 'rb') as f:
        dump = f.read()
    emit(f"    {len(dump):,} bytes loaded")

    emit("[*] Loading RTTI database...")
    rtti_data = load_rtti(RTTI_PATH)
    emit(f"    {len(rtti_data)} RTTI entries loaded")

    targets = [
        (0x141289980, "Function containing key_code copy @ 0x141289980"),
        (0x141912ff0, "ActionChartPackage_BaseData::slot[2] @ 0x141912ff0"),
    ]

    # Resolve jmp thunks: if target VA is a `jmp rel32`, follow it
    # but only if within the dump range (Themida thunks jump outside)
    resolved_targets = []
    for target_va, label in targets:
        code = read_bytes_at_va(dump, sections, target_va, 16)
        if code and code[0] == 0xE9:  # jmp rel32
            rel = struct.unpack_from('<i', code, 1)[0]
            real_target = target_va + 5 + rel
            emit(f"\n[*] {target_va:#x} is a jmp thunk -> {real_target:#x}")
            foff_check = va_to_file_off(real_target, sections)
            if foff_check is not None:
                emit(f"    Resolved to in-dump target, using {real_target:#x}")
                resolved_targets.append((real_target, f"{label} (resolved thunk -> {real_target:#x})"))
            else:
                emit(f"    Target {real_target:#x} is outside dump (Themida?)")
                emit(f"    Using nearest non-thunk function before the thunk")
                # Find the function right before the thunk
                func_start = find_function_start(dump, sections, target_va, max_scan=512)
                if func_start < target_va:
                    resolved_targets.append((func_start, f"{label} (pre-thunk function @ {func_start:#x})"))
                else:
                    resolved_targets.append((target_va, label))
        else:
            resolved_targets.append((target_va, label))
    targets = resolved_targets

    all_mappings = {}  # (src_off, dst_off) -> details

    for target_va, label in targets:
        emit(f"\n{'=' * 100}")
        emit(f"TARGET: {label}")
        emit(f"{'=' * 100}")

        # RTTI vtable lookup
        owners = find_vtable_owner(rtti_data, target_va)
        if owners:
            for name, vt_va, slot_idx in owners:
                emit(f"  RTTI: {name}")
                emit(f"        vtable={vt_va}, slot[{slot_idx}]")
        else:
            emit(f"  RTTI: No vtable match for {target_va:#x}")

        # Find function boundaries
        emit(f"\n  [*] Scanning for function start (backwards from {target_va:#x})...")
        func_start = find_function_start(dump, sections, target_va)
        emit(f"      Function start: {func_start:#x}")

        emit(f"  [*] Scanning for function end...")
        func_end = find_function_end(dump, sections, func_start)
        func_size = func_end - func_start
        emit(f"      Function end:   {func_end:#x} (size: {func_size} bytes)")

        # Disassemble
        emit(f"\n  [*] Disassembling {func_start:#x} - {func_end:#x}...")
        instructions = disasm_function(dump, sections, func_start, func_end, label)
        emit(f"      {len(instructions)} instructions")

        # Print full disassembly
        emit(f"\n  --- Full Disassembly ---")
        for insn in instructions:
            marker = ""
            # Annotate target address
            if insn.address == target_va:
                marker = "  <<<< TARGET"
            # Annotate known serialized offsets in operands
            for off, name in KNOWN_SERIAL_OFFSETS.items():
                hex_off = f"0x{off:x}"
                if hex_off in insn.op_str:
                    marker += f"  <<< serial:{name}"
                    break
            emit(f"    {insn.address:#014x}:  {insn.mnemonic:10s} {insn.op_str:55s}{marker}")

        # Extract offset mappings
        emit(f"\n  --- Offset Mappings (load [regA+X] -> store [regB+Y]) ---")
        mappings = extract_offset_mappings(instructions)

        if not mappings:
            emit("    (no direct reg+off -> reg+off patterns found)")
        else:
            for m in mappings:
                src_ann = ""
                if m['src_off'] in KNOWN_SERIAL_OFFSETS:
                    src_ann = f" ({KNOWN_SERIAL_OFFSETS[m['src_off']]})"
                xform = " [TRANSFORMED]" if m.get('transformed') else ""
                emit(f"    [{m['src_reg']}+0x{m['src_off']:X}]{src_ann} -> "
                     f"[{m['dst_reg']}+0x{m['dst_off']:X}]  "
                     f"width={width_str(m['width'])}  "
                     f"load@{m['load_va']:#x} store@{m['store_va']:#x}{xform}")

                key = (m['src_off'], m['dst_off'])
                if key not in all_mappings:
                    all_mappings[key] = m

    # ─── Summary ────────────────────────────────────────────────────────────
    emit(f"\n{'=' * 100}")
    emit("SERIALIZED -> RUNTIME OFFSET MAPPING SUMMARY")
    emit(f"{'=' * 100}")
    emit(f"{'Serial Offset':>16s}  {'Runtime Offset':>16s}  {'Width':>8s}  {'Xform':>6s}  {'Src->Dst Regs':>16s}  {'Known Name'}")
    emit(f"{'-'*16:>16s}  {'-'*16:>16s}  {'-'*8:>8s}  {'-'*6:>6s}  {'-'*16:>16s}  {'-'*20}")

    for (src_off, dst_off), m in sorted(all_mappings.items()):
        name = KNOWN_SERIAL_OFFSETS.get(src_off, '')
        xf = "yes" if m.get('transformed') else ""
        regs = f"{m['src_reg']}->{m['dst_reg']}"
        emit(f"    0x{src_off:04X}          0x{dst_off:04X}           {width_str(m['width']):>5s}    {xf:>5s}   {regs:>15s}   {name}")

    # Also look for immediate stores (mov [reg+off], imm) and other patterns
    # that might reveal runtime struct layout
    emit(f"\n{'=' * 100}")
    emit("ADDITIONAL ANALYSIS: Immediate stores, LEA patterns, and calls")
    emit(f"{'=' * 100}")

    for target_va, label in targets:
        func_start = find_function_start(dump, sections, target_va)
        func_end = find_function_end(dump, sections, func_start)
        instructions = disasm_function(dump, sections, func_start, func_end)

        emit(f"\n  --- {label} ---")

        # Find LEA instructions (often used to get pointers to sub-structures)
        for insn in instructions:
            if insn.mnemonic == 'lea' and len(insn.operands) == 2:
                dst, src = insn.operands
                if src.type == capstone.x86.X86_OP_MEM and src.mem.disp != 0:
                    if src.mem.base != capstone.x86.X86_REG_RIP:
                        base = insn.reg_name(src.mem.base)
                        d = insn.reg_name(dst.reg)
                        emit(f"    LEA  {d} = [{base}+0x{src.mem.disp:X}]  @ {insn.address:#x}")

            # Find calls (to identify sub-deserializers)
            if insn.mnemonic == 'call':
                emit(f"    CALL {insn.op_str}  @ {insn.address:#x}")

    # Save output
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out_lines) + '\n')
    print(f"\n[*] Output saved to {OUTPUT_PATH}")


if __name__ == '__main__':
    main()
