#!/usr/bin/env python3
"""
Disassemble the condition graph evaluator functions from Crimson Desert memory dump.

Targets RTTI vtable slots for:
- ClientSequencerStage_StageChartProcessor (main chart processing)
- ITimelineExitCondition (exit condition interface)
- CommonExitCondition (concrete exit condition)

Maps runtime field accesses at known offsets (0x110, 0x126, 0x120, etc.)
and traces decision logic (comparisons, switch tables, call graph).
"""

import sys, io, os, struct, json, re
import capstone
from capstone import x86 as cs_x86

# Force UTF-8 stdout
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DUMP_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.bin"
MAP_PATH  = r"E:\SteamLibrary\steamapps\common\Crimson Desert\bin64\CrimsonDesert_dump.map"
RTTI_PATH = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDInstantSkin\tools\dump_rtti_all.json"
IMAGE_BASE = 0x140000000
OUTPUT_PATH = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\evaluator_analysis.txt"

# ---- Runtime field offsets we're looking for ----
RUNTIME_FIELDS = {
    0xE8:  'dword from byte[0]',
    0xF0:  'dword from byte[120]',
    0xF6:  'word from byte[124]',
    0x110: 'opcode_start (condition bytecode ptr)',
    0x120: 'byte[228]',
    0x122: 'bit-packed flags (byte[113]/[116])',
    0x124: 'byte[117]',
    0x126: 'key_code (bit 6 extracted)',
}

# ---- Known RTTI vtable info ----
VTABLE_SLOTS = {
    # ClientSequencerStage_StageChartProcessor
    0x140449640: 'StageChartProcessor::slot[0] (main process)',
    0x14044f110: 'StageChartProcessor::slot[4] (evaluateTransitions?)',
    0x1404528d0: 'StageChartProcessor::slot[5] (evaluateConditions?)',
    0x140467fc0: 'StageChartProcessor::slot[6]',
    0x140469e10: 'StageChartProcessor::slot[7]',
    # ITimelineExitCondition
    0x1409e5930: 'ITimelineExitCondition::slot[0] (canExit)',
    0x1409e6550: 'ITimelineExitCondition::slot[1]',
    # CommonExitCondition
    0x141b20e90: 'CommonExitCondition::slot[0] (concrete check)',
    0x141b21440: 'CommonExitCondition::slot[1]',
}

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

# ============================================================
# Register helpers
# ============================================================

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

# ============================================================
# Function boundary detection
# ============================================================

def find_function_start(dump, sections, addr, max_scan=8192):
    """Scan backwards from addr to find function prologue."""
    scan_start = addr - max_scan
    data = read_bytes_at_va(dump, sections, scan_start, max_scan + 64)
    if data is None:
        return addr

    best_start = None

    # Find runs of 3+ consecutive CC bytes
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

    # Fallback: look for common x64 prologues
    for offset in range(max_scan, 0, -1):
        va_cand = scan_start + offset
        if va_cand > addr or va_cand % 16 != 0:
            continue
        b = data[offset:offset+5]
        if len(b) < 5:
            continue
        if (b[:4] == b'\x48\x89\x5C\x24' or
            b[:4] == b'\x48\x89\x6C\x24' or
            b[:4] == b'\x48\x89\x74\x24' or
            b[:4] == b'\x4C\x89\x4C\x24' or
            b[:3] == b'\x48\x83\xEC' or
            b[:3] == b'\x48\x81\xEC' or
            b[:2] == b'\x40\x55' or
            b[:2] == b'\x40\x53' or
            b[0] == 0x55):
            best_start = va_cand

    return best_start if best_start else addr - 256

def find_function_end(dump, sections, start_va, max_size=16384):
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
        if insn.mnemonic in ('ret', 'retn'):
            end_offset = offset + insn.size
            if end_offset < len(data):
                next_byte = data[end_offset]
                if next_byte == 0xCC:
                    return insn.address + insn.size
                last_ret_end = insn.address + insn.size
        if insn.mnemonic == 'jmp' and not insn.op_str.startswith('['):
            end_offset = offset + insn.size
            if end_offset < len(data) and data[end_offset] == 0xCC:
                return insn.address + insn.size

    return last_ret_end if last_ret_end else start_va + max_size

# ============================================================
# Resolve jmp thunks
# ============================================================

def resolve_thunk(dump, sections, va):
    """If VA is a jmp rel32, follow it (if target is in dump)."""
    code = read_bytes_at_va(dump, sections, va, 16)
    if code and code[0] == 0xE9:
        rel = struct.unpack_from('<i', code, 1)[0]
        real_target = va + 5 + rel
        foff = va_to_file_off(real_target, sections)
        if foff is not None:
            return real_target, True
    return va, False

# ============================================================
# Disassembly
# ============================================================

def disasm_function(dump, sections, func_start, func_end):
    """Disassemble function, return list of capstone instructions."""
    size = func_end - func_start
    data = read_bytes_at_va(dump, sections, func_start, size)
    if data is None:
        return []

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    instructions = []
    for insn in md.disasm(data, func_start):
        if insn.address >= func_end:
            break
        instructions.append(insn)
    return instructions

# ============================================================
# Phase 2: Find Runtime Field Access
# ============================================================

def find_field_accesses(instructions):
    """Find instructions that access known runtime field offsets."""
    accesses = []
    for i, insn in enumerate(instructions):
        for op in insn.operands:
            if op.type == cs_x86.X86_OP_MEM:
                disp = op.mem.disp
                if disp in RUNTIME_FIELDS:
                    base_reg = insn.reg_name(op.mem.base) if op.mem.base else 'none'
                    if base_reg in ('rip', 'rsp', 'rbp', 'esp', 'ebp', 'sp', 'bp'):
                        continue  # skip stack-relative and RIP-relative
                    accesses.append({
                        'idx': i,
                        'va': insn.address,
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str,
                        'offset': disp,
                        'field': RUNTIME_FIELDS[disp],
                        'base_reg': base_reg,
                    })
    return accesses

def print_access_context(instructions, access, emit):
    """Print instruction + 5 lines before/after for context."""
    idx = access['idx']
    start = max(0, idx - 5)
    end = min(len(instructions), idx + 6)

    emit(f"\n  ACCESS: [{access['base_reg']}+0x{access['offset']:X}] = {access['field']}")
    emit(f"  At: {access['va']:#x}  {access['mnemonic']} {access['op_str']}")
    emit(f"  Context:")
    for j in range(start, end):
        insn = instructions[j]
        marker = " <<<" if j == idx else ""
        emit(f"    {insn.address:#014x}:  {insn.mnemonic:10s} {insn.op_str}{marker}")

# ============================================================
# Phase 3: Trace Decision Logic
# ============================================================

def trace_decision_logic(instructions, accesses, emit):
    """For functions accessing key_code (0x126) or opcode (0x110),
    find comparisons, branches, and switch/jump tables."""

    has_key_fields = any(a['offset'] in (0x126, 0x110) for a in accesses)
    if not has_key_fields:
        return

    emit(f"\n  --- Decision Logic Trace ---")

    # Collect all cmp/test/je/jne/jz/jnz instructions
    comparisons = []
    branches = []
    jump_tables = []

    for i, insn in enumerate(instructions):
        mnem = insn.mnemonic

        if mnem in ('cmp', 'test'):
            ops = insn.op_str
            comparisons.append({
                'idx': i,
                'va': insn.address,
                'mnemonic': mnem,
                'op_str': ops,
            })

        if mnem.startswith('j') and mnem != 'jmp':
            branches.append({
                'idx': i,
                'va': insn.address,
                'mnemonic': mnem,
                'op_str': insn.op_str,
            })

        # Detect switch/jump table: lea reg, [rip+X] followed by indirect jmp
        if mnem == 'lea' and len(insn.operands) == 2:
            src = insn.operands[1]
            if src.type == cs_x86.X86_OP_MEM and src.mem.base == cs_x86.X86_REG_RIP:
                # Check if within a few instructions there's a jmp [reg+...]
                for j in range(i+1, min(i+8, len(instructions))):
                    nxt = instructions[j]
                    if nxt.mnemonic == 'jmp' and len(nxt.operands) == 1:
                        op0 = nxt.operands[0]
                        if op0.type == cs_x86.X86_OP_MEM and op0.mem.index != 0:
                            table_base = insn.address + insn.size + src.mem.disp
                            jump_tables.append({
                                'lea_va': insn.address,
                                'jmp_va': nxt.address,
                                'table_base': table_base,
                                'lea_str': insn.op_str,
                                'jmp_str': nxt.op_str,
                            })
                            break

    emit(f"\n  Comparisons ({len(comparisons)}):")
    for c in comparisons:
        # Check if this comparison involves a register that was loaded from a key field
        emit(f"    {c['va']:#014x}:  {c['mnemonic']:6s} {c['op_str']}")

    emit(f"\n  Conditional branches ({len(branches)}):")
    for b in branches:
        emit(f"    {b['va']:#014x}:  {b['mnemonic']:6s} -> {b['op_str']}")

    if jump_tables:
        emit(f"\n  Switch/Jump Tables ({len(jump_tables)}):")
        for jt in jump_tables:
            emit(f"    LEA @ {jt['lea_va']:#x}: {jt['lea_str']}")
            emit(f"    JMP @ {jt['jmp_va']:#x}: {jt['jmp_str']}")
            emit(f"    Table base VA: {jt['table_base']:#x}")
            # Try to read jump table entries
            read_jump_table(jt['table_base'], instructions, emit)

    # Extract comparison constants against key_code
    emit(f"\n  Key comparison targets:")
    for c in comparisons:
        # Look for immediate operand
        for i_c, insn in enumerate(instructions):
            if insn.address == c['va']:
                for op in insn.operands:
                    if op.type == cs_x86.X86_OP_IMM:
                        emit(f"    cmp/test ... , {op.imm:#x} ({op.imm}) @ {c['va']:#x}")
                break

def read_jump_table(table_base_va, instructions, emit):
    """Attempt to read and print switch table entries."""
    # Jump tables typically contain int32 offsets from table_base
    # We'll try to read up to 32 entries
    pass  # We'll implement this with dump access in the main flow

# ============================================================
# Phase 4: Cross-Reference Calls
# ============================================================

def extract_calls(instructions, dump, sections):
    """Extract all call targets and resolve them."""
    calls = []
    for insn in instructions:
        if insn.mnemonic == 'call':
            if len(insn.operands) == 1:
                op = insn.operands[0]
                if op.type == cs_x86.X86_OP_IMM:
                    target = op.imm
                    # Resolve thunk
                    resolved, was_thunk = resolve_thunk(dump, sections, target)
                    calls.append({
                        'call_va': insn.address,
                        'target': target,
                        'resolved': resolved if was_thunk else target,
                        'was_thunk': was_thunk,
                        'indirect': False,
                    })
                elif op.type == cs_x86.X86_OP_MEM:
                    # Indirect call through memory (vtable dispatch)
                    base = insn.reg_name(op.mem.base) if op.mem.base else 'none'
                    disp = op.mem.disp
                    idx_reg = insn.reg_name(op.mem.index) if op.mem.index else 'none'
                    calls.append({
                        'call_va': insn.address,
                        'target': None,
                        'resolved': None,
                        'was_thunk': False,
                        'indirect': True,
                        'indirect_str': insn.op_str,
                        'base_reg': base,
                        'disp': disp,
                    })
                elif op.type == cs_x86.X86_OP_REG:
                    calls.append({
                        'call_va': insn.address,
                        'target': None,
                        'resolved': None,
                        'was_thunk': False,
                        'indirect': True,
                        'indirect_str': insn.op_str,
                    })
    return calls

def print_call_graph(calls, func_label, emit):
    """Print calls and identify any that match known vtable slots."""
    emit(f"\n  --- Call Graph ---")
    for c in calls:
        if c['indirect']:
            s = c.get('indirect_str', '?')
            label = ""
            emit(f"    {c['call_va']:#014x}:  call {s}  (indirect)")
        else:
            target = c['target']
            resolved = c['resolved']
            label = VTABLE_SLOTS.get(target, VTABLE_SLOTS.get(resolved, ''))
            thunk_note = f" (thunk -> {resolved:#x})" if c['was_thunk'] else ""
            if label:
                emit(f"    {c['call_va']:#014x}:  call {target:#x}{thunk_note}  <<< {label}")
            else:
                emit(f"    {c['call_va']:#014x}:  call {target:#x}{thunk_note}")

# ============================================================
# RTTI lookup
# ============================================================

def load_rtti(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def find_vtable_owner(rtti_data, func_va):
    target = f"0x{func_va:x}"
    results = []
    for entry in rtti_data:
        slots = entry.get('slots', [])
        for idx, slot_va in enumerate(slots):
            if slot_va.lower() == target.lower():
                results.append((entry['name'], entry.get('vtable_va', '?'), idx))
    return results

# ============================================================
# Main
# ============================================================

def main():
    out_lines = []
    def emit(s=""):
        print(s)
        out_lines.append(s)

    emit("=" * 100)
    emit("Condition Graph Evaluator Disassembly Analysis")
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

    # Target functions to disassemble
    targets = [
        (0x140449640, 'StageChartProcessor::slot[0] (main process method)'),
        (0x14044f110, 'StageChartProcessor::slot[4] (evaluateTransitions?)'),
        (0x1404528d0, 'StageChartProcessor::slot[5] (evaluateConditions?)'),
        (0x1409e5930, 'ITimelineExitCondition::slot[0] (canExit)'),
        (0x141b20e90, 'CommonExitCondition::slot[0] (concrete check)'),
    ]

    # Global collections
    all_field_accesses = {}  # field_offset -> list of (func_label, access)
    all_call_targets = {}    # target_va -> list of caller func labels
    func_results = []

    for target_va, label in targets:
        emit(f"\n{'#' * 100}")
        emit(f"# FUNCTION: {label}")
        emit(f"# Target VA: {target_va:#x}")
        emit(f"{'#' * 100}")

        # Resolve thunk
        resolved_va, was_thunk = resolve_thunk(dump, sections, target_va)
        if was_thunk:
            emit(f"  [*] Thunk at {target_va:#x} -> resolved to {resolved_va:#x}")
            work_va = resolved_va
        else:
            work_va = target_va

        # Check if VA is accessible
        foff = va_to_file_off(work_va, sections)
        if foff is None:
            emit(f"  [!] VA {work_va:#x} is NOT in dump (Themida-packed region?)")
            emit(f"  [!] Skipping this function.")
            func_results.append((label, target_va, None, None, [], [], []))
            continue

        # RTTI lookup
        owners = find_vtable_owner(rtti_data, target_va)
        if owners:
            for name, vt_va, slot_idx in owners:
                emit(f"  RTTI: {name} vtable={vt_va} slot[{slot_idx}]")
        else:
            emit(f"  RTTI: No direct vtable match for {target_va:#x}")

        # Find function boundaries
        emit(f"\n  [*] Finding function boundaries...")
        func_start = find_function_start(dump, sections, work_va)
        func_end = find_function_end(dump, sections, func_start)
        func_size = func_end - func_start
        emit(f"      Start: {func_start:#x}")
        emit(f"      End:   {func_end:#x}")
        emit(f"      Size:  {func_size} bytes ({func_size:#x})")

        # Disassemble
        emit(f"\n  [*] Disassembling...")
        instructions = disasm_function(dump, sections, func_start, func_end)
        emit(f"      {len(instructions)} instructions")

        if not instructions:
            emit(f"  [!] No instructions decoded.")
            func_results.append((label, target_va, func_start, func_end, [], [], []))
            continue

        # Full disassembly listing
        emit(f"\n  {'='*90}")
        emit(f"  FULL DISASSEMBLY: {func_start:#x} - {func_end:#x}")
        emit(f"  {'='*90}")
        for insn in instructions:
            # Annotate known runtime field accesses
            annotation = ""
            for op in insn.operands:
                if op.type == cs_x86.X86_OP_MEM:
                    disp = op.mem.disp
                    base = insn.reg_name(op.mem.base) if op.mem.base else 'none'
                    if base not in ('rip', 'rsp', 'rbp', 'esp', 'ebp'):
                        if disp in RUNTIME_FIELDS:
                            annotation = f"  <<< {RUNTIME_FIELDS[disp]}"
                        elif disp in VTABLE_SLOTS:
                            annotation = f"  <<< VTABLE: {VTABLE_SLOTS[disp]}"

            # Annotate calls to known vtable slots
            if insn.mnemonic == 'call' and len(insn.operands) == 1:
                op0 = insn.operands[0]
                if op0.type == cs_x86.X86_OP_IMM:
                    t = op0.imm
                    rt, _ = resolve_thunk(dump, sections, t)
                    if t in VTABLE_SLOTS:
                        annotation = f"  <<< {VTABLE_SLOTS[t]}"
                    elif rt in VTABLE_SLOTS:
                        annotation = f"  <<< thunk -> {VTABLE_SLOTS[rt]}"

            emit(f"    {insn.address:#014x}:  {insn.mnemonic:10s} {insn.op_str:55s}{annotation}")

        # Phase 2: Field accesses
        emit(f"\n  {'='*90}")
        emit(f"  PHASE 2: Runtime Field Accesses")
        emit(f"  {'='*90}")
        accesses = find_field_accesses(instructions)
        if accesses:
            emit(f"  Found {len(accesses)} field access(es):")
            for a in accesses:
                print_access_context(instructions, a, emit)
                key = a['offset']
                if key not in all_field_accesses:
                    all_field_accesses[key] = []
                all_field_accesses[key].append((label, a))
        else:
            emit(f"  No accesses to tracked runtime fields found in this function.")

        # Phase 3: Decision logic
        emit(f"\n  {'='*90}")
        emit(f"  PHASE 3: Decision Logic Trace")
        emit(f"  {'='*90}")
        trace_decision_logic(instructions, accesses, emit)

        # Phase 4: Call graph
        emit(f"\n  {'='*90}")
        emit(f"  PHASE 4: Call Graph")
        emit(f"  {'='*90}")
        calls = extract_calls(instructions, dump, sections)
        print_call_graph(calls, label, emit)

        for c in calls:
            if not c['indirect'] and c['target']:
                t = c['resolved'] or c['target']
                if t not in all_call_targets:
                    all_call_targets[t] = []
                all_call_targets[t].append(label)

        func_results.append((label, target_va, func_start, func_end, instructions, accesses, calls))

    # ============================================================
    # Global Summary
    # ============================================================

    emit(f"\n{'#' * 100}")
    emit(f"# GLOBAL SUMMARY")
    emit(f"{'#' * 100}")

    # Field access summary
    emit(f"\n--- Runtime Field Access Summary ---")
    for offset in sorted(RUNTIME_FIELDS.keys()):
        field = RUNTIME_FIELDS[offset]
        if offset in all_field_accesses:
            emit(f"\n  [0x{offset:X}] {field}:")
            for func_label, a in all_field_accesses[offset]:
                emit(f"    In {func_label}:")
                emit(f"      {a['va']:#x}  {a['mnemonic']} {a['op_str']}")
        else:
            emit(f"\n  [0x{offset:X}] {field}: NOT ACCESSED in any scanned function")

    # Call graph cross-references
    emit(f"\n--- Call Target Cross-References ---")
    emit(f"  Targets that are also known RTTI vtable slots:")
    found_xrefs = False
    for t, callers in sorted(all_call_targets.items()):
        slot_name = VTABLE_SLOTS.get(t, None)
        if slot_name:
            found_xrefs = True
            emit(f"    {t:#x} ({slot_name})")
            for c in callers:
                emit(f"      <- called from: {c}")
    if not found_xrefs:
        emit(f"    (none found)")

    # Check indirect calls for vtable dispatch patterns
    emit(f"\n  All unique direct call targets:")
    unique_targets = sorted(set(all_call_targets.keys()))
    for t in unique_targets:
        callers = all_call_targets[t]
        slot_name = VTABLE_SLOTS.get(t, '')
        annotation = f"  ({slot_name})" if slot_name else ""
        emit(f"    {t:#014x}{annotation}  <- {', '.join(callers)}")

    # Function size summary
    emit(f"\n--- Function Size Summary ---")
    for label, target_va, func_start, func_end, instructions, accesses, calls in func_results:
        if func_start and func_end:
            size = func_end - func_start
            emit(f"  {label}")
            emit(f"    {func_start:#x} - {func_end:#x}  ({size} bytes, {len(instructions)} insns, "
                 f"{len(accesses)} field hits, {len(calls)} calls)")
        else:
            emit(f"  {label}")
            emit(f"    NOT IN DUMP")

    # Save output
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out_lines) + '\n')
    print(f"\n[*] Output saved to {OUTPUT_PATH}")


if __name__ == '__main__':
    main()
