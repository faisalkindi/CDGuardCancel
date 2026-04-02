#!/usr/bin/env python3
"""
Find the runtime guard suppression code in Crimson Desert memory dump.

Guard (LB) is blocked during attack animations at the CODE level, not in .paac data.
This script finds the responsible check by:
1. Re-discovering key class vtables from the fresh dump via RTTI
2. Disassembling InputBlock slot[3] (main input processing with jump table)
3. Searching CODE sections for guard-specific patterns
4. Extracting AOB pattern for the suppression check
"""

import sys, io, os, struct, time, mmap
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET
    from capstone import x86 as cs_x86
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[!] Capstone not available - disassembly will be limited")

DUMP_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.bin"
MAP_PATH  = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.map"
IMAGE_BASE = 0x140000000
OUTPUT_PATH = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\guard_suppression_analysis.txt"

# Classes we need to find
TARGET_CLASSES = [
    b".?AVStageChart_Function_InputBlock@pa@@",
    b".?AVClientAttackActorComponent@pa@@",
    b".?AVClientInputActorComponent@pa@@",
    b".?AVClientSequencerStage_StageChartProcessor@pa@@",
]

# Output collector
output_lines = []

def log(msg=""):
    print(msg)
    output_lines.append(msg)

def save_output():
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    log(f"\n[*] Output saved to {OUTPUT_PATH}")

# ============================================================
# Map parsing
# ============================================================

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
                'protect':  int(parts[3], 16),
                'type':     parts[4],
            })
    return sections

def va_to_file_off(va, sections):
    for s in sections:
        if s['va'] <= va < s['va'] + s['size']:
            return s['file_off'] + (va - s['va'])
    return None

def file_off_to_va(off, sections):
    for s in sections:
        if s['file_off'] <= off < s['file_off'] + s['size']:
            return s['va'] + (off - s['file_off'])
    return None

def is_code_va(va, sections):
    for s in sections:
        if s['type'] == 'CODE' and s['va'] <= va < s['va'] + s['size']:
            return True
    return False

def is_data_va(va, sections):
    for s in sections:
        if s['type'] == 'DATA' and s['va'] <= va < s['va'] + s['size']:
            return True
    return False

# ============================================================
# RTTI scanning
# ============================================================

def find_rtti_vtables(dump, sections):
    """Find vtables for target classes by scanning for RTTI decorated names."""
    results = {}

    for class_name in TARGET_CLASSES:
        short_name = class_name.split(b'@')[0].replace(b'.?AV', b'').decode('ascii')
        log(f"\n[RTTI] Searching for {short_name}...")

        # Step 1: Find the TypeDescriptor (contains the decorated name string)
        pos = 0
        td_va = None
        while True:
            idx = dump.find(class_name, pos)
            if idx == -1:
                break
            # TypeDescriptor starts 16 bytes before the name string (2 pointers on x64)
            td_file_off = idx - 16
            td_va_candidate = file_off_to_va(td_file_off, sections)
            if td_va_candidate and is_data_va(td_va_candidate, sections):
                td_va = td_va_candidate
                log(f"  TypeDescriptor at VA 0x{td_va:X} (file 0x{td_file_off:X})")
                break
            pos = idx + 1

        if td_va is None:
            log(f"  [!] TypeDescriptor not found for {short_name}")
            continue

        # Step 2: Find CompleteObjectLocator that references this TypeDescriptor
        # COL format (x64): signature(4) + offset(4) + cdOffset(4) + pTypeDescriptor(4, RVA) + ...
        td_rva = td_va - IMAGE_BASE
        td_rva_bytes = struct.pack('<I', td_rva & 0xFFFFFFFF)

        col_va = None
        pos = 0
        while True:
            idx = dump.find(td_rva_bytes, pos)
            if idx == -1:
                break
            # In COL, TD RVA is at offset +12
            col_candidate_off = idx - 12
            col_va_candidate = file_off_to_va(col_candidate_off, sections)
            if col_va_candidate and is_data_va(col_va_candidate, sections):
                # Verify COL signature (should be 1 for x64)
                sig = struct.unpack_from('<I', dump, col_candidate_off)[0]
                if sig == 1:
                    col_va = col_va_candidate
                    log(f"  COL at VA 0x{col_va:X} (file 0x{col_candidate_off:X})")
                    break
            pos = idx + 1

        if col_va is None:
            log(f"  [!] COL not found for {short_name}")
            continue

        # Step 3: Find vtable by searching for pointer to COL
        # vtable[-1] = pointer to COL (on x64, full 8-byte pointer)
        col_ptr_bytes = struct.pack('<Q', col_va)
        pos = 0
        vtable_va = None
        while True:
            idx = dump.find(col_ptr_bytes, pos)
            if idx == -1:
                break
            # vtable starts right after this pointer
            vtable_file_off = idx + 8
            vtable_va_candidate = file_off_to_va(vtable_file_off, sections)
            if vtable_va_candidate and is_data_va(vtable_va_candidate, sections):
                vtable_va = vtable_va_candidate
                log(f"  vtable at VA 0x{vtable_va:X} (file 0x{vtable_file_off:X})")
                break
            pos = idx + 1

        if vtable_va is None:
            log(f"  [!] vtable not found for {short_name}")
            continue

        # Step 4: Read vtable slots (up to 32 slots, stop at first non-code pointer)
        vtable_off = va_to_file_off(vtable_va, sections)
        slots = []
        for i in range(32):
            slot_off = vtable_off + i * 8
            if slot_off + 8 > len(dump):
                break
            slot_va = struct.unpack_from('<Q', dump, slot_off)[0]
            if slot_va == 0 or not is_code_va(slot_va, sections):
                # Some vtable slots might be 0 or point to data (thunks) - be lenient for first few
                if i < 3 and slot_va != 0:
                    slots.append(slot_va)
                    continue
                if i >= 3:
                    break
                slots.append(slot_va)
                continue
            slots.append(slot_va)

        log(f"  {len(slots)} vtable slots:")
        for i, s in enumerate(slots):
            code_marker = "CODE" if is_code_va(s, sections) else "DATA/OTHER"
            log(f"    slot[{i}] = 0x{s:X} ({code_marker})")

        results[short_name] = {
            'td_va': td_va,
            'col_va': col_va,
            'vtable_va': vtable_va,
            'slots': slots,
        }

    return results

# ============================================================
# Disassembly helpers
# ============================================================

def disasm_function(dump, sections, func_va, max_bytes=8192, label=None):
    """Disassemble a function starting at func_va, returns list of instructions."""
    if not HAS_CAPSTONE:
        return []

    off = va_to_file_off(func_va, sections)
    if off is None:
        log(f"  [!] Cannot map VA 0x{func_va:X} to file offset")
        return []

    end = min(off + max_bytes, len(dump))
    code_bytes = dump[off:end]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    instructions = []
    func_end = False
    for insn in md.disasm(code_bytes, func_va):
        instructions.append(insn)
        # Stop at unconditional return (but not first one if very early)
        if insn.mnemonic == 'ret' and len(instructions) > 5:
            # Check if next instruction looks like alignment padding
            next_off = va_to_file_off(insn.address + insn.size, sections)
            if next_off and next_off < len(dump):
                next_byte = dump[next_off]
                if next_byte == 0xCC or next_byte == 0x90:
                    func_end = True
                    break
        # Also stop at int3 sequences
        if insn.mnemonic == 'int3':
            instructions.pop()  # remove int3
            break

    return instructions

def format_insn(insn):
    """Format a single instruction."""
    raw = dump_bytes_hex(insn.bytes)
    return f"  0x{insn.address:X}: {raw:40s} {insn.mnemonic} {insn.op_str}"

def dump_bytes_hex(b):
    return ' '.join(f'{x:02X}' for x in b)

def find_jump_table(instructions, dump, sections):
    """Find jump table pattern in disassembled instructions."""
    results = []
    for i, insn in enumerate(instructions):
        # Look for: lea reg, [rip+disp] followed by movsxd + add + jmp
        # Or: cmp eax/ecx/edx, N; ja default
        if insn.mnemonic == 'cmp' and i + 1 < len(instructions):
            next_insn = instructions[i+1]
            if next_insn.mnemonic in ('ja', 'jae', 'jb', 'jbe'):
                # Found comparison + conditional jump - potential switch
                results.append({
                    'cmp_insn': insn,
                    'jmp_insn': next_insn,
                    'cmp_idx': i,
                })
    return results

# ============================================================
# Phase 2: Deep InputBlock analysis
# ============================================================

def analyze_inputblock(dump, sections, rtti_results):
    """Analyze StageChart_Function_InputBlock in detail."""
    if 'StageChart_Function_InputBlock' not in rtti_results:
        log("\n[!] InputBlock not found, skipping Phase 2")
        return

    info = rtti_results['StageChart_Function_InputBlock']
    slots = info['slots']

    log("\n" + "="*80)
    log("PHASE 2: StageChart_Function_InputBlock Analysis")
    log("="*80)

    # Disassemble each slot
    for i, slot_va in enumerate(slots):
        if not is_code_va(slot_va, sections):
            continue

        log(f"\n--- InputBlock slot[{i}] at 0x{slot_va:X} ---")
        insns = disasm_function(dump, sections, slot_va, max_bytes=16384)

        if not insns:
            log(f"  [!] No instructions decoded")
            continue

        func_size = insns[-1].address + insns[-1].size - insns[0].address
        log(f"  Function size: {func_size} bytes, {len(insns)} instructions")

        # Find jump tables
        jt = find_jump_table(insns, dump, sections)
        if jt:
            log(f"  Found {len(jt)} potential switch/case comparisons:")
            for j in jt:
                log(f"    {format_insn(j['cmp_insn'])}")
                log(f"    {format_insn(j['jmp_insn'])}")

        # Look for interesting patterns in this function
        interesting = []
        for insn in insns:
            op = insn.op_str.lower()
            # Flag checks (test byte/dword)
            if insn.mnemonic == 'test' and ('byte' in op or 'dword' in op):
                interesting.append(('FLAG_CHECK', insn))
            # Comparisons with small immediates (input type IDs)
            elif insn.mnemonic == 'cmp':
                for operand in insn.operands:
                    if operand.type == cs_x86.X86_OP_IMM and 0 < operand.imm < 0x100:
                        interesting.append(('CMP_SMALL', insn))
                        break
            # Calls (to identify what functions it invokes)
            elif insn.mnemonic == 'call':
                interesting.append(('CALL', insn))
            # Conditional jumps after flag checks
            elif insn.mnemonic.startswith('j') and insn.mnemonic not in ('jmp',):
                interesting.append(('COND_JMP', insn))

        if interesting:
            log(f"\n  Interesting patterns ({len(interesting)}):")
            for tag, insn in interesting[:50]:  # limit output
                log(f"    [{tag}] {format_insn(insn)}")

        # For the BIG function (slot[3] expected), do deep analysis
        if func_size > 1000:
            log(f"\n  *** LARGE FUNCTION (slot[{i}]) - Deep analysis ***")
            deep_analyze_inputblock_function(dump, sections, insns, slot_va)

def deep_analyze_inputblock_function(dump, sections, insns, func_va):
    """Deep analysis of the main InputBlock processing function."""

    # Find all switch/case structures
    log(f"\n  [Deep] Looking for switch/case dispatch tables...")

    for idx, insn in enumerate(insns):
        # Pattern: lea reg, [rip+disp]; movsxd; add; jmp reg
        if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
            # Check if this is a jump table base
            for operand in insn.operands:
                if operand.type == cs_x86.X86_OP_MEM and operand.mem.base != 0:
                    # Look ahead for movsxd + add + jmp pattern
                    for j in range(1, min(6, len(insns) - idx)):
                        next_i = insns[idx + j]
                        if next_i.mnemonic == 'jmp' and next_i.operands and next_i.operands[0].type == cs_x86.X86_OP_REG:
                            log(f"    Jump table dispatch at 0x{insn.address:X}:")
                            for k in range(max(0, idx-2), min(len(insns), idx+j+1)):
                                log(f"      {format_insn(insns[k])}")

                            # Try to read the jump table
                            try_read_jump_table(dump, sections, insns, idx, insn)
                            break

    # Find all conditional blocks that reference offsets commonly used for state flags
    log(f"\n  [Deep] Looking for state flag checks...")
    flag_offsets = set()
    for insn in insns:
        if insn.mnemonic in ('test', 'cmp', 'bt', 'movzx', 'mov'):
            for operand in insn.operands:
                if operand.type == cs_x86.X86_OP_MEM:
                    disp = operand.mem.disp
                    if 0x80 <= disp <= 0x500:
                        flag_offsets.add(disp)

    if flag_offsets:
        sorted_offs = sorted(flag_offsets)
        log(f"    Referenced struct offsets: {', '.join(f'0x{o:X}' for o in sorted_offs)}")

    # Print full disassembly of first 200 instructions for manual review
    log(f"\n  [Deep] First 300 instructions of function at 0x{func_va:X}:")
    for insn in insns[:300]:
        log(format_insn(insn))

    if len(insns) > 300:
        log(f"  ... ({len(insns) - 300} more instructions)")

def try_read_jump_table(dump, sections, insns, lea_idx, lea_insn):
    """Try to decode a jump table referenced by lea instruction."""
    # The lea loads the base address of the table
    # Table entries are typically 4-byte relative offsets

    # Get the RIP-relative address from the lea
    for operand in lea_insn.operands:
        if operand.type == cs_x86.X86_OP_MEM:
            disp = operand.mem.disp
            table_va = lea_insn.address + lea_insn.size + disp
            table_off = va_to_file_off(table_va, sections)

            if table_off is None:
                log(f"      Jump table VA 0x{table_va:X} - cannot map to file")
                return

            log(f"      Jump table at VA 0x{table_va:X} (file 0x{table_off:X})")

            # Read up to 64 entries
            entries = []
            for i in range(64):
                entry_off = table_off + i * 4
                if entry_off + 4 > len(dump):
                    break
                rel = struct.unpack_from('<i', dump, entry_off)[0]
                target_va = table_va + rel
                if not is_code_va(target_va, sections):
                    break
                entries.append((i, rel, target_va))

            if entries:
                log(f"      {len(entries)} jump table entries:")
                for i, rel, target in entries:
                    log(f"        case {i}: -> 0x{target:X} (rel {rel:+d})")
            return

# ============================================================
# Phase 3: Search for guard-specific patterns
# ============================================================

def search_guard_patterns(dump, sections):
    """Search CODE sections for guard-related patterns."""
    log("\n" + "="*80)
    log("PHASE 3: Guard-specific pattern search")
    log("="*80)

    code_sections = [s for s in sections if s['type'] == 'CODE']

    # 3a: Search for string references
    log("\n[3a] Searching for guard-related strings in entire dump...")
    guard_strings = [
        b'key_guard', b'KEY_GUARD', b'Guard', b'guard',
        b'input_block', b'InputBlock', b'INPUT_BLOCK',
        b'canGuard', b'can_guard', b'isBlocking', b'is_blocking',
        b'block_input', b'BlockInput',
        b'attack_guard', b'AttackGuard',
    ]

    for gs in guard_strings:
        pos = 0
        count = 0
        while count < 10:
            idx = dump.find(gs, pos)
            if idx == -1:
                break
            va = file_off_to_va(idx, sections)
            # Get surrounding context
            ctx_start = max(0, idx - 8)
            ctx_end = min(len(dump), idx + len(gs) + 32)
            ctx = dump[ctx_start:ctx_end]
            # Check if it's a proper string (printable ASCII around it)
            count += 1
            region = "CODE" if va and is_code_va(va, sections) else "DATA" if va and is_data_va(va, sections) else "???"
            va_str = f"0x{va:X}" if va else "N/A"
            log(f"  Found '{gs.decode('ascii', errors='replace')}' at file 0x{idx:X} (VA {va_str}) [{region}]")
            # Show a wider context as hex
            wider_start = max(0, idx - 16)
            wider_end = min(len(dump), idx + len(gs) + 48)
            hex_ctx = dump[wider_start:wider_end].hex()
            log(f"    Context: ...{hex_ctx}...")
            pos = idx + 1

        if count == 0:
            pass  # don't log misses to keep output clean

    # 3b: Search for specific hash values that might represent "guard" action
    log("\n[3b] Searching for potential guard action hashes/IDs...")
    # Common input type enum values to check
    # We'll look for code that compares against small values (0-20 range)
    # alongside conditional jumps

    # 3c: Find xrefs to InputBlock vtable slots in code
    log("\n[3c] Searching for cross-references to key functions in CODE...")

def find_code_xrefs(dump, sections, target_va, label=""):
    """Find all code locations that reference target_va via RIP-relative addressing."""
    code_sections = [s for s in sections if s['type'] == 'CODE']
    results = []

    for sec in code_sections:
        sec_off = sec['file_off']
        sec_size = sec['size']
        sec_va = sec['va']

        # Search for RIP-relative references
        # A call/jmp to target would be: E8/E9 <32-bit-relative>
        # A lea/mov referencing target: <opcode> <modrm> <32-bit-disp>

        for offset in range(sec_off, sec_off + sec_size - 5):
            # Check for CALL rel32
            if dump[offset] == 0xE8:
                rel = struct.unpack_from('<i', dump, offset + 1)[0]
                call_va = sec_va + (offset - sec_off) + 5 + rel
                if call_va == target_va:
                    caller_va = sec_va + (offset - sec_off)
                    results.append(('CALL', caller_va))

    if results:
        log(f"  Found {len(results)} xrefs to {label} (0x{target_va:X}):")
        for typ, va in results[:20]:
            log(f"    [{typ}] from 0x{va:X}")

    return results

# ============================================================
# Phase 4: Broader attack-state + guard analysis
# ============================================================

def analyze_attack_component(dump, sections, rtti_results):
    """Analyze ClientAttackActorComponent for guard-related flags."""
    if 'ClientAttackActorComponent' not in rtti_results:
        log("\n[!] ClientAttackActorComponent not found")
        return

    info = rtti_results['ClientAttackActorComponent']
    slots = info['slots']

    log("\n" + "="*80)
    log("PHASE 4a: ClientAttackActorComponent Analysis")
    log("="*80)

    for i, slot_va in enumerate(slots[:8]):
        if not is_code_va(slot_va, sections):
            continue
        insns = disasm_function(dump, sections, slot_va, max_bytes=4096)
        if not insns:
            continue
        func_size = insns[-1].address + insns[-1].size - insns[0].address
        log(f"\n  slot[{i}] at 0x{slot_va:X}: {func_size} bytes, {len(insns)} insns")

        # Look for functions that set/clear boolean flags
        has_flag_ops = False
        for insn in insns:
            if insn.mnemonic in ('mov', 'or', 'and') and 'byte' in insn.op_str.lower():
                for op in insn.operands:
                    if op.type == cs_x86.X86_OP_MEM and 0x100 <= op.mem.disp <= 0x400:
                        if not has_flag_ops:
                            log(f"    Flag-like byte operations:")
                            has_flag_ops = True
                        log(f"      {format_insn(insn)}")

def analyze_input_component(dump, sections, rtti_results):
    """Analyze ClientInputActorComponent for input filtering."""
    if 'ClientInputActorComponent' not in rtti_results:
        log("\n[!] ClientInputActorComponent not found")
        return

    info = rtti_results['ClientInputActorComponent']
    slots = info['slots']

    log("\n" + "="*80)
    log("PHASE 4b: ClientInputActorComponent Analysis")
    log("="*80)

    for i, slot_va in enumerate(slots[:8]):
        if not is_code_va(slot_va, sections):
            continue
        insns = disasm_function(dump, sections, slot_va, max_bytes=8192)
        if not insns:
            continue
        func_size = insns[-1].address + insns[-1].size - insns[0].address
        log(f"\n  slot[{i}] at 0x{slot_va:X}: {func_size} bytes, {len(insns)} insns")

        # For large functions, look for input type dispatch
        if func_size > 500:
            log(f"    *** LARGE FUNCTION - checking for input dispatch ***")
            jt = find_jump_table(insns, dump, sections)
            for j in jt:
                log(f"    Switch: {format_insn(j['cmp_insn'])}")
                log(f"            {format_insn(j['jmp_insn'])}")

# ============================================================
# Phase 5: Scan for common guard-block patterns
# ============================================================

def scan_guard_block_patterns(dump, sections):
    """Search for common code patterns that would block guard during attacks."""
    log("\n" + "="*80)
    log("PHASE 5: Broad pattern scan for guard suppression")
    log("="*80)

    code_sections = [s for s in sections if s['type'] == 'CODE']
    if not code_sections:
        log("[!] No code sections found")
        return

    if not HAS_CAPSTONE:
        log("[!] Capstone required for pattern scan")
        return

    # Strategy: Search for the pattern where:
    # 1. A function reads an "is attacking" bool/flags
    # 2. Then checks input type == guard
    # 3. Then returns 0 / jumps to "blocked"

    # Alternative: search for functions that reference both
    # ClientAttackActorComponent offsets AND input type comparisons

    # Search for key byte patterns in CODE
    log("\n[5a] Searching for 'test + jnz/jz' patterns near 'cmp reg, small_imm'...")

    # Pattern: test byte ptr [reg+offset], mask; jnz/jz skip
    # Followed within ~20 bytes by: cmp eax/ecx, small_value

    # Let's search for all locations where we see:
    # cmp [reg+disp], 0  or  test byte [reg+disp], mask
    # where disp is in a plausible range for component state flags

    # More targeted: find functions that do BOTH:
    # - Read from an object at offset typical for "isAttacking" (0x1C0-0x300 range)
    # - Compare against an input type ID
    # - Then conditionally skip/block

    # Let's search for specific opcode sequences
    patterns_to_find = []

    # Pattern A: cmp dword/byte [reg+0x???], 0; jz/jnz ... (checking if state == 0)
    # This is very common, so filter by context

    # Pattern B: Search for string "key_guard" xrefs
    log("\n[5b] Searching for 'key_guard' string and code references to it...")

    # Find all occurrences of "key_guard"
    guard_str = b'key_guard'
    pos = 0
    guard_string_vas = []
    while True:
        idx = dump.find(guard_str, pos)
        if idx == -1:
            break
        va = file_off_to_va(idx, sections)
        if va:
            guard_string_vas.append(va)
            log(f"  'key_guard' at VA 0x{va:X}")
        pos = idx + 1

    # For each guard string location, search code for RIP-relative references to it
    if guard_string_vas:
        log(f"\n  Searching code for references to 'key_guard' addresses...")
        for guard_va in guard_string_vas:
            # Search for LEA instructions that compute this address
            for sec in code_sections:
                sec_data = dump[sec['file_off']:sec['file_off']+sec['size']]
                # A lea with RIP-relative addressing: 48 8D xx yy yy yy yy
                # The displacement = target - (current_ip + insn_size)
                for off in range(len(sec_data) - 7):
                    insn_va = sec['va'] + off
                    # Check for LEA patterns (various REX + 8D combinations)
                    b0 = sec_data[off]
                    b1 = sec_data[off+1] if off+1 < len(sec_data) else 0
                    b2 = sec_data[off+2] if off+2 < len(sec_data) else 0

                    # REX.W LEA reg, [rip+disp32]
                    if b0 in (0x48, 0x4C) and b1 == 0x8D and (b2 & 0x07) == 0x05:
                        disp = struct.unpack_from('<i', sec_data, off+3)[0]
                        target = insn_va + 7 + disp
                        if target == guard_va:
                            log(f"    CODE XREF to 'key_guard' from VA 0x{insn_va:X}")
                            # Disassemble surrounding function
                            disasm_around(dump, sections, insn_va, context_before=64, context_after=128)

    # Pattern C: Look for functions that read "InputBlock" type data
    # The StageChart_Function_InputBlock likely has a method that decides
    # whether to block input based on input type

    log("\n[5c] Searching for common input-blocking code patterns...")
    log("  Looking for: test/cmp on struct member + conditional return/skip")

    # Search for a very specific pattern: a function that returns 0 or 1
    # based on checking a flag AND an input type
    # This would look like:
    #   movzx eax, byte ptr [rcx+OFFSET]  (read isAttacking flag)
    #   test al, al
    #   jz .allow
    #   cmp edx, GUARD_TYPE_ID
    #   jne .allow
    #   xor eax, eax  (return 0 = blocked)
    #   ret
    # .allow:
    #   mov eax, 1
    #   ret

    # Let's look for all short functions (< 100 bytes) that:
    # - Have a conditional return pattern
    # - Reference struct members

    # Search for xor eax,eax; ret pattern (return false/0)
    ret_false_pattern = bytes([0x33, 0xC0, 0xC3])  # xor eax,eax; ret
    ret_false_2 = bytes([0x31, 0xC0, 0xC3])  # xor eax,eax; ret (alternate encoding)

    count = 0
    for sec in code_sections:
        sec_data = dump[sec['file_off']:sec['file_off']+sec['size']]
        pos = 0
        while pos < len(sec_data) - 3:
            idx = sec_data.find(ret_false_pattern, pos)
            if idx == -1:
                idx = sec_data.find(ret_false_2, pos)
            if idx == -1:
                break

            # Look backward for guard-related comparisons
            # Check the preceding 80 bytes for interesting patterns
            start = max(0, idx - 80)
            preceding = sec_data[start:idx]

            # Does it contain a comparison with a small immediate?
            has_cmp = False
            has_flag_check = False
            for p in range(len(preceding) - 3):
                # cmp reg, imm8 patterns
                if preceding[p] in (0x83, 0x80) and p + 2 < len(preceding):
                    imm = preceding[p+2]
                    if 1 <= imm <= 30:
                        has_cmp = True
                # test byte ptr patterns
                if preceding[p] == 0xF6 or (preceding[p] == 0x84):
                    has_flag_check = True

            if has_cmp and has_flag_check:
                func_va = sec['va'] + idx - 80  # approximate function start
                ret_va = sec['va'] + idx
                count += 1
                if count <= 30:
                    log(f"    Candidate at VA ~0x{ret_va:X}: has cmp+test before return-false")
                    # Disassemble to check
                    disasm_around(dump, sections, ret_va, context_before=80, context_after=16)

            pos = idx + 1

    log(f"  Total candidates with cmp+test+ret_false: {count}")

def disasm_around(dump, sections, va, context_before=64, context_after=64):
    """Disassemble a region around a VA."""
    if not HAS_CAPSTONE:
        return

    start_va = va - context_before
    off = va_to_file_off(start_va, sections)
    if off is None:
        return

    total_bytes = context_before + context_after
    end = min(off + total_bytes, len(dump))
    code_bytes = dump[off:end]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    log(f"    --- Disassembly 0x{start_va:X} to 0x{start_va+total_bytes:X} ---")
    for insn in md.disasm(code_bytes, start_va):
        marker = " <<<" if insn.address == va else ""
        raw = dump_bytes_hex(insn.bytes)
        log(f"      0x{insn.address:X}: {raw:40s} {insn.mnemonic} {insn.op_str}{marker}")

# ============================================================
# Phase 6: Focused search for InputBlock's input-type dispatch
# ============================================================

def analyze_all_inputblock_functions(dump, sections, rtti_results):
    """Find and analyze ALL functions called by InputBlock, not just vtable slots."""
    if 'StageChart_Function_InputBlock' not in rtti_results:
        return

    info = rtti_results['StageChart_Function_InputBlock']
    slots = info['slots']

    log("\n" + "="*80)
    log("PHASE 6: Deep InputBlock call graph analysis")
    log("="*80)

    # For each vtable slot, find all CALL targets
    all_callees = set()
    for i, slot_va in enumerate(slots):
        if not is_code_va(slot_va, sections):
            continue
        insns = disasm_function(dump, sections, slot_va, max_bytes=16384)
        for insn in insns:
            if insn.mnemonic == 'call':
                for op in insn.operands:
                    if op.type == cs_x86.X86_OP_IMM:
                        target = op.imm
                        if is_code_va(target, sections):
                            all_callees.add(target)

    log(f"\n  InputBlock vtable functions call {len(all_callees)} unique functions")

    # Now disassemble each callee looking for input type comparisons
    guard_candidates = []
    for callee_va in sorted(all_callees):
        insns = disasm_function(dump, sections, callee_va, max_bytes=4096)
        if not insns:
            continue

        func_size = insns[-1].address + insns[-1].size - insns[0].address

        # Check if this function has a switch/case or input type comparison
        has_switch = False
        has_small_cmp = False
        small_cmps = []

        for insn in insns:
            if insn.mnemonic == 'cmp':
                for op in insn.operands:
                    if op.type == cs_x86.X86_OP_IMM:
                        v = op.imm & 0xFFFFFFFF
                        if 0x10 <= v <= 0x80:
                            has_small_cmp = True
                            small_cmps.append((insn, v))

        jt = find_jump_table(insns, dump, sections)
        if jt:
            has_switch = True

        if has_switch or (has_small_cmp and len(small_cmps) >= 2):
            log(f"\n  Interesting callee at 0x{callee_va:X} ({func_size} bytes)")
            if has_switch:
                for j in jt:
                    log(f"    Switch: {format_insn(j['cmp_insn'])}")
            for insn, v in small_cmps:
                log(f"    CMP: {format_insn(insn)} (value=0x{v:X}={v})")

            guard_candidates.append(callee_va)

    # Deep dive into candidates
    for cand_va in guard_candidates[:5]:
        log(f"\n  === Deep dive: 0x{cand_va:X} ===")
        insns = disasm_function(dump, sections, cand_va, max_bytes=8192)
        for insn in insns[:200]:
            log(format_insn(insn))

# ============================================================
# Main
# ============================================================

def main():
    global dump  # for helper functions

    t0 = time.time()
    log("="*80)
    log("Crimson Desert Guard Suppression Analysis")
    log(f"Dump: {DUMP_PATH}")
    log(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("="*80)

    # Load map
    sections = parse_map(MAP_PATH)
    code_sections = [s for s in sections if s['type'] == 'CODE']
    data_sections = [s for s in sections if s['type'] == 'DATA']
    log(f"\n[*] Map: {len(code_sections)} CODE sections ({sum(s['size'] for s in code_sections)/1024/1024:.1f} MB)")
    log(f"[*] Map: {len(data_sections)} DATA sections ({sum(s['size'] for s in data_sections)/1024/1024:.1f} MB)")

    # Load dump
    log(f"\n[*] Loading memory dump...")
    with open(DUMP_PATH, 'rb') as f:
        dump = f.read()
    log(f"[*] Loaded {len(dump)/1024/1024:.1f} MB in {time.time()-t0:.1f}s")

    # Phase 1: RTTI vtable discovery
    log("\n" + "="*80)
    log("PHASE 1: RTTI Vtable Discovery")
    log("="*80)
    rtti_results = find_rtti_vtables(dump, sections)

    if not rtti_results:
        log("\n[!!!] No RTTI classes found! Cannot proceed.")
        save_output()
        return

    # Phase 2: InputBlock analysis
    analyze_inputblock(dump, sections, rtti_results)

    # Phase 3: Guard string/pattern search
    search_guard_patterns(dump, sections)

    # Phase 4: Attack + Input component analysis
    analyze_attack_component(dump, sections, rtti_results)
    analyze_input_component(dump, sections, rtti_results)

    # Phase 5: Broad pattern scan
    scan_guard_block_patterns(dump, sections)

    # Phase 6: InputBlock call graph
    analyze_all_inputblock_functions(dump, sections, rtti_results)

    # Summary
    elapsed = time.time() - t0
    log(f"\n{'='*80}")
    log(f"Analysis complete in {elapsed:.1f}s")
    log(f"{'='*80}")

    save_output()

if __name__ == '__main__':
    main()
