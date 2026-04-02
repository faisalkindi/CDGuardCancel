#!/usr/bin/env python3
"""
Comprehensive parser for Crimson Desert .paac (PA Action Chart) binary format.

Parses state machines, transitions, string tables, animation paths, and the
condition graph tail section. Generates a detailed analysis report.

Usage:
    py -3 paac_parser.py <path_to.paac> [--output <report.txt>]
    py -3 paac_parser.py  (defaults to sword_upper.paac with paac_analysis.txt output)
"""

import struct
import sys
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Transition:
    threshold: float      # animation-progress threshold (0.0 = immediate)
    sentinel: float       # always -1.0 (0xBF800000)
    target_state: int     # index of destination state
    sequence: int         # priority / ordering index

@dataclass
class StateNode:
    index: int                        # sequential index in the marker list
    marker_offset: int                # file offset of the marker pattern start
    state_start: int                  # file offset of state start (marker - 2)
    label_idx: int                    # string table index (0xFFFF = no label)
    label_name: str                   # resolved label string
    speed: float                      # frame rate / speed value (typically 50.0)
    body_size: int                    # bytes from state start to transitions start
    transitions: List[Transition]     # outgoing transitions
    transition_count_offset: int      # file offset of the uint8 transition count
    transition_data_offset: int       # file offset of first transition record
    state_end: int                    # file offset of end of transitions
    config_end: int                   # file offset after 64-byte config block
    raw_body_extra_size: int          # size of body beyond the standard header

@dataclass
class StringEntry:
    index: int
    offset: int
    length: int
    text: str

@dataclass
class AnimPath:
    index: int
    offset: int
    length: int
    path: str

@dataclass
class ConditionRecord:
    offset: int
    raw_bytes: bytes
    floats: List[float]
    ints: List[int]

@dataclass
class PaacFile:
    filepath: str
    filesize: int
    # Header
    header_node_count: int
    header_speed: float
    header_flags: int
    header_raw: bytes
    # States
    states: List[StateNode]
    # String tables
    label_count: int
    labels: List[StringEntry]
    label_table_offset: int
    # Animation paths
    anim_path_count: int
    anim_paths: List[AnimPath]
    anim_path_table_offset: int
    # Additional string tables
    extra_tables: List[Tuple[int, int, List[StringEntry]]]  # (offset, count, entries)
    # Condition graph
    condition_section_offset: int
    condition_section_size: int
    condition_records: List[ConditionRecord]


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

class PaacParser:
    MARKER_FLOAT = 50.0  # 0x42480000
    MARKER_BYTES = b'\x00\x00\x48\x42'
    SENTINEL_BYTES = b'\x00\x00\x80\xbf'  # float -1.0
    CONFIG_BLOCK_SIZE = 64
    TRANSITION_RECORD_SIZE = 16

    def __init__(self, filepath: str):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            self.data = f.read()
        self.filesize = len(self.data)

    def u8(self, off: int) -> int:
        return self.data[off]

    def u16(self, off: int) -> int:
        return struct.unpack_from('<H', self.data, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from('<I', self.data, off)[0]

    def f32(self, off: int) -> float:
        return struct.unpack_from('<f', self.data, off)[0]

    def read_string(self, off: int) -> Tuple[str, int]:
        """Read a length-prefixed string. Returns (text, total_bytes_consumed)."""
        slen = self.data[off]
        raw = self.data[off + 1: off + 1 + slen]
        null_pos = raw.find(b'\x00')
        if null_pos >= 0:
            text = raw[:null_pos].decode('ascii', errors='replace')
        else:
            text = raw.decode('ascii', errors='replace')
        return text, 1 + slen

    # ------------------------------------------------------------------
    # 1. Header
    # ------------------------------------------------------------------
    def parse_header(self) -> Tuple[int, float, int, bytes]:
        node_count = self.u32(0)
        speed = self.f32(8)
        flags = self.u32(0x18)
        raw = self.data[0:0x44]
        return node_count, speed, flags, raw

    # ------------------------------------------------------------------
    # 2. Find state markers
    # ------------------------------------------------------------------
    def find_state_markers(self) -> List[int]:
        """Find all state markers: [uint16][00 00 48 42][00 bc]."""
        markers = []
        data = self.data
        end = len(data) - 9
        i = 2
        while i < end:
            if (data[i + 2:i + 6] == self.MARKER_BYTES and
                    data[i + 6] == 0x00 and data[i + 7] == 0xbc):
                markers.append(i)
                i += 100  # skip ahead (states are at least ~170 bytes)
            else:
                i += 1
        return markers

    # ------------------------------------------------------------------
    # 3. Parse transitions for a state
    # ------------------------------------------------------------------
    def find_transitions(self, region_start: int, region_end: int) -> Tuple[List[Transition], int, int]:
        """
        Scan a region for a transition block.
        Returns (transitions, count_offset, data_offset).
        """
        data = self.data
        best_block = None

        for j in range(region_start + 0x50, region_end):
            count = data[j]
            if count < 1 or count > 60:
                continue
            rec_start = j + 1
            rec_end = rec_start + count * self.TRANSITION_RECORD_SIZE
            if rec_end > region_end:
                continue

            # Validate all sentinels
            valid = True
            for k in range(count):
                sent_off = rec_start + k * 16 + 4
                if data[sent_off:sent_off + 4] != self.SENTINEL_BYTES:
                    valid = False
                    break
            if not valid:
                continue

            # Validate all targets are reasonable
            all_valid_targets = True
            for k in range(count):
                target = self.u32(rec_start + k * 16 + 8)
                if target > 2000:  # generous upper bound
                    all_valid_targets = False
                    break
            if not all_valid_targets:
                continue

            # Check that after transitions there's a config block pattern
            after = rec_end
            if after + 8 <= len(data):
                # Config block typically starts with 00 00 00 00 then a float
                first_4 = self.u32(after)
                if first_4 == 0 or (after + 4 < len(data) and 0 < self.f32(after + 4) < 100):
                    pass  # looks good
                else:
                    # Might still be valid, but prefer blocks closer to end
                    pass

            # Prefer the block closest to region_end (transitions are at the end)
            if best_block is None or j > best_block[0]:
                trans = []
                for k in range(count):
                    rec = rec_start + k * 16
                    t = Transition(
                        threshold=self.f32(rec),
                        sentinel=self.f32(rec + 4),
                        target_state=self.u32(rec + 8),
                        sequence=self.u32(rec + 12),
                    )
                    trans.append(t)
                best_block = (j, trans, j, rec_start)

        if best_block:
            return best_block[1], best_block[2], best_block[3]
        return [], -1, -1

    # ------------------------------------------------------------------
    # 4. Parse all states
    # ------------------------------------------------------------------
    def parse_states(self, markers: List[int], labels: List[StringEntry]) -> List[StateNode]:
        label_map = {e.index: e.text for e in labels}
        states = []

        for si, m in enumerate(markers):
            # State structure: [uint16 label at m][float speed at m+2][00 bc at m+6]
            label_idx = self.u16(m)
            speed = self.f32(m + 2)
            state_start = m - 2  # 2 bytes before the label field

            # Determine region end
            if si + 1 < len(markers):
                region_end = markers[si + 1] - 2  # next state start
            else:
                # Last state: estimate end as label table offset - some padding
                region_end = min(m + 3000, self.filesize)

            # Find transitions
            trans, count_off, data_off = self.find_transitions(m, region_end)

            if trans:
                state_end = data_off + len(trans) * self.TRANSITION_RECORD_SIZE
                config_end = state_end + self.CONFIG_BLOCK_SIZE
            else:
                # No transitions found - estimate end
                if si + 1 < len(markers):
                    config_end = markers[si + 1] - 2
                    state_end = config_end - self.CONFIG_BLOCK_SIZE
                else:
                    state_end = m + 400
                    config_end = state_end + self.CONFIG_BLOCK_SIZE

            label_name = label_map.get(label_idx, f"<none>" if label_idx == 0xFFFF else f"label_{label_idx}")

            body_size = (count_off - m) if count_off >= 0 else (state_end - m)

            node = StateNode(
                index=si,
                marker_offset=m,
                state_start=state_start,
                label_idx=label_idx,
                label_name=label_name,
                speed=speed,
                body_size=body_size,
                transitions=trans,
                transition_count_offset=count_off,
                transition_data_offset=data_off,
                state_end=state_end,
                config_end=config_end,
                raw_body_extra_size=0,
            )
            states.append(node)

        return states

    # ------------------------------------------------------------------
    # 5. Find and parse string tables
    # ------------------------------------------------------------------
    def find_label_table(self) -> Tuple[int, int, List[StringEntry]]:
        """Find the label string table by scanning for 'key_guard'."""
        idx = self.data.find(b'key_guard')
        if idx < 0:
            idx = self.data.find(b'key_norattack')
        if idx < 0:
            return -1, 0, []

        # Walk backwards from key_guard to find the table start.
        # String format: [uint8 length] [length bytes including null terminator]
        # So total per string = 1 + length. Previous string's length byte is at
        # current_offset - previous_length - 1.
        off = idx - 1  # length byte of 'key_guard'
        while off > 0:
            found_prev = False
            for check_len in range(1, 256):
                candidate_start = off - check_len - 1  # -1 for the length byte itself
                if candidate_start < 0:
                    break
                if self.data[candidate_start] == check_len:
                    candidate_str = self.data[candidate_start + 1: candidate_start + 1 + check_len]
                    printable = sum(1 for b in candidate_str if 32 <= b < 127 or b == 0)
                    if printable >= check_len * 0.8:
                        off = candidate_start
                        found_prev = True
                        break
            if not found_prev:
                break

        table_start = off
        count_offset = table_start

        # Parse strings forward. Labels include:
        # - The first entry (often a branchset path with '/')
        # - Short key/mask names (key_guard, NeckAndRightArm, etc.)
        # Stop when we hit a uint16 that's an animation path count followed by paths.
        labels = []
        parse_off = table_start
        str_idx = 0
        while parse_off < self.filesize:
            slen = self.data[parse_off]
            if slen == 0:
                break
            if parse_off + 1 + slen > self.filesize:
                break
            raw = self.data[parse_off + 1: parse_off + 1 + slen]
            null_pos = raw.find(b'\x00')
            if null_pos >= 0:
                text = raw[:null_pos].decode('ascii', errors='replace')
            else:
                text = raw.decode('ascii', errors='replace')

            # Detect transition to animation path table:
            # The anim path table starts with uint16 count, then paths with .paa
            # Check if the NEXT 2 bytes after this string form a uint16 count
            # followed by a length-prefixed .paa path.
            next_off = parse_off + 1 + slen
            if next_off + 4 < self.filesize:
                maybe_count = struct.unpack_from('<H', self.data, next_off)[0]
                if 50 < maybe_count < 2000:
                    # Check if the data after the uint16 looks like a path
                    path_len_off = next_off + 2
                    if path_len_off < self.filesize:
                        path_slen = self.data[path_len_off]
                        if path_slen > 20 and path_len_off + 1 + path_slen <= self.filesize:
                            path_text = self.data[path_len_off + 1: path_len_off + 1 + path_slen]
                            if b'.paa' in path_text:
                                # This is the last label before anim paths
                                labels.append(StringEntry(
                                    index=str_idx, offset=parse_off,
                                    length=slen, text=text,
                                ))
                                break

            labels.append(StringEntry(
                index=str_idx,
                offset=parse_off,
                length=slen,
                text=text,
            ))
            parse_off += 1 + slen
            str_idx += 1

            if str_idx > 500:
                break

        label_count = len(labels)

        # Find count value before table
        for delta in [1, 2, 3]:
            candidate = table_start - delta
            if candidate >= 0:
                val = self.u8(candidate)
                if val == label_count:
                    count_offset = candidate
                    break
                if delta >= 2:
                    val16 = self.u16(candidate)
                    if val16 == label_count:
                        count_offset = candidate
                        break

        return count_offset, label_count, labels

    def parse_anim_paths(self, after_labels_offset: int) -> Tuple[int, int, List[AnimPath]]:
        """Parse the animation path table starting at the given offset."""
        count = self.u16(after_labels_offset)
        if count == 0 or count > 10000:
            return after_labels_offset, 0, []

        paths = []
        off = after_labels_offset + 2
        for i in range(count):
            if off >= self.filesize:
                break
            plen = self.data[off]
            if plen == 0:
                break
            raw = self.data[off + 1: off + 1 + plen]
            null_pos = raw.find(b'\x00')
            if null_pos >= 0:
                text = raw[:null_pos].decode('ascii', errors='replace')
            else:
                text = raw.decode('ascii', errors='replace')
            paths.append(AnimPath(index=i, offset=off, length=plen, path=text))
            off += 1 + plen

        return after_labels_offset, count, paths

    def parse_extra_string_tables(self, start_offset: int) -> List[Tuple[int, int, List[StringEntry]]]:
        """Parse additional string tables (camera paths, effects, blend paths, etc.)."""
        tables = []
        off = start_offset

        for _ in range(20):  # safety limit
            if off + 2 > self.filesize:
                break
            count = self.u16(off)
            if count == 0:
                # Table with 0 entries - skip the count
                tables.append((off, 0, []))
                off += 2
                continue
            if count > 5000:
                break

            entries = []
            parse_off = off + 2
            valid = True
            for i in range(count):
                if parse_off >= self.filesize:
                    valid = False
                    break
                slen = self.data[parse_off]
                if slen == 0 or parse_off + 1 + slen > self.filesize:
                    valid = False
                    break
                raw = self.data[parse_off + 1: parse_off + 1 + slen]
                printable = sum(1 for b in raw if 32 <= b < 127 or b == 0)
                if printable < slen * 0.5:
                    valid = False
                    break
                null_pos = raw.find(b'\x00')
                if null_pos >= 0:
                    text = raw[:null_pos].decode('ascii', errors='replace')
                else:
                    text = raw.decode('ascii', errors='replace')
                entries.append(StringEntry(index=i, offset=parse_off, length=slen, text=text))
                parse_off += 1 + slen

            if valid and entries:
                tables.append((off, count, entries))
                off = parse_off
            else:
                break

        return tables

    # ------------------------------------------------------------------
    # 6. Parse condition graph (tail section)
    # ------------------------------------------------------------------
    def analyze_condition_section(self, start_offset: int) -> Tuple[int, List[ConditionRecord]]:
        """Analyze the condition/transition graph section at the end of the file."""
        section_size = self.filesize - start_offset
        records = []

        # Look for repeating patterns
        # The section has structured data with floats, -1.0 sentinels, and indices

        # Scan for sentinel-pairs (two -1.0 values 8 bytes apart = 80-byte condition blocks)
        off = start_offset
        block_starts = []

        # Find blocks by looking for patterns
        while off < self.filesize - 80:
            # Check for the 80-byte condition block pattern:
            # Contains two -1.0 sentinels about 8 bytes apart
            # and float values that look like animation thresholds
            chunk = self.data[off:off + 80]
            sentinel_count = 0
            for k in range(0, len(chunk) - 3):
                if chunk[k:k + 4] == self.SENTINEL_BYTES:
                    sentinel_count += 1

            if sentinel_count >= 2:
                # Check for float values in reasonable range
                floats_found = []
                for k in range(0, len(chunk) - 3, 4):
                    fval = struct.unpack_from('<f', chunk, k)[0]
                    if 0 < abs(fval) < 100 and fval != -1.0:
                        floats_found.append(fval)

                if floats_found:
                    rec = ConditionRecord(
                        offset=off,
                        raw_bytes=chunk,
                        floats=floats_found,
                        ints=[],
                    )
                    records.append(rec)
                    block_starts.append(off)

            off += 1
            # If we found a block, skip ahead
            if block_starts and block_starts[-1] == off - 1:
                off = off - 1 + 80

        return section_size, records[:1000]  # cap for sanity

    # ------------------------------------------------------------------
    # 7. Full parse
    # ------------------------------------------------------------------
    def parse(self) -> PaacFile:
        print(f"Parsing {self.filepath} ({self.filesize:,} bytes)...")

        # Header
        node_count, speed, flags, header_raw = self.parse_header()
        print(f"  Header: node_count={node_count}, speed={speed:.4f}, flags=0x{flags:08x}")

        # State markers
        markers = self.find_state_markers()
        print(f"  Found {len(markers)} state markers")

        # String tables
        label_offset, label_count, labels = self.find_label_table()
        print(f"  Labels: {label_count} strings at 0x{label_offset:x}")

        # States
        states = self.parse_states(markers, labels)
        total_trans = sum(len(s.transitions) for s in states)
        print(f"  Parsed {len(states)} states with {total_trans} total transitions")

        # Animation paths
        if labels:
            last_label = labels[-1]
            after_labels = last_label.offset + 1 + last_label.length
        else:
            after_labels = label_offset + 2

        anim_offset, anim_count, anim_paths = self.parse_anim_paths(after_labels)
        print(f"  Animation paths: {anim_count} at 0x{anim_offset:x}")

        # Extra string tables
        if anim_paths:
            last_path = anim_paths[-1]
            after_anims = last_path.offset + 1 + last_path.length
        else:
            after_anims = anim_offset + 2

        extra_tables = self.parse_extra_string_tables(after_anims)
        print(f"  Extra string tables: {len(extra_tables)}")

        # Condition section
        if extra_tables:
            last_table_offset, last_count, last_entries = extra_tables[-1]
            if last_entries:
                last_entry = last_entries[-1]
                cond_start = last_entry.offset + 1 + last_entry.length
            else:
                cond_start = last_table_offset + 2
        else:
            cond_start = after_anims

        # Skip any trailing zero-count tables
        while cond_start + 2 < self.filesize and self.u16(cond_start) == 0:
            cond_start += 2

        cond_size, cond_records = self.analyze_condition_section(cond_start)
        print(f"  Condition section: 0x{cond_start:x} - 0x{self.filesize:x} ({cond_size:,} bytes, {len(cond_records)} record candidates)")

        return PaacFile(
            filepath=self.filepath,
            filesize=self.filesize,
            header_node_count=node_count,
            header_speed=speed,
            header_flags=flags,
            header_raw=header_raw,
            states=states,
            label_count=label_count,
            labels=labels,
            label_table_offset=label_offset,
            anim_path_count=anim_count,
            anim_paths=anim_paths,
            anim_path_table_offset=anim_offset,
            extra_tables=extra_tables,
            condition_section_offset=cond_start,
            condition_section_size=cond_size,
            condition_records=cond_records,
        )


# ---------------------------------------------------------------------------
# Analysis and report generation
# ---------------------------------------------------------------------------

class PaacAnalyzer:
    def __init__(self, paac: PaacFile):
        self.paac = paac
        self._build_transition_maps()

    def _build_transition_maps(self):
        """Build forward and reverse transition maps."""
        self.forward_map: Dict[int, List[Tuple[int, float, int]]] = defaultdict(list)
        self.reverse_map: Dict[int, List[Tuple[int, float, int]]] = defaultdict(list)
        self.all_target_states: set = set()

        for state in self.paac.states:
            for t in state.transitions:
                self.forward_map[state.index].append((t.target_state, t.threshold, t.sequence))
                self.reverse_map[t.target_state].append((state.index, t.threshold, t.sequence))
                self.all_target_states.add(t.target_state)

    def find_guard_state(self) -> int:
        """Find the state index that represents 'guard' (key_guard label)."""
        for s in self.paac.states:
            if 'guard' in s.label_name.lower() and 'start' not in s.label_name.lower():
                return s.index
        # Fallback: state 0 often transitions to many states
        return 0

    def get_guard_blocked_states(self, guard_state: int) -> List[int]:
        """Find states that CANNOT transition to the guard state."""
        blocked = []
        for s in self.paac.states:
            targets = {t.target_state for t in s.transitions}
            if guard_state not in targets and len(s.transitions) > 0:
                blocked.append(s.index)
        return blocked

    def classify_attack_states(self) -> Dict[str, List[int]]:
        """Classify states based on their animation references and transitions."""
        categories = defaultdict(list)

        for state in self.paac.states:
            # Check if state transitions suggest attack behavior
            has_guard_transition = any(
                t.target_state == self.find_guard_state()
                for t in state.transitions
            )

            # Check transition targets and thresholds
            has_threshold_transitions = any(
                t.threshold > 0 for t in state.transitions
            )

            # Classify
            if len(state.transitions) == 0:
                categories['no_transitions'].append(state.index)
            elif has_guard_transition and not has_threshold_transitions:
                categories['immediate_guard_access'].append(state.index)
            elif has_guard_transition and has_threshold_transitions:
                categories['delayed_guard_access'].append(state.index)
            elif not has_guard_transition and has_threshold_transitions:
                categories['guard_blocked_with_thresholds'].append(state.index)
            elif not has_guard_transition:
                categories['guard_blocked_no_thresholds'].append(state.index)

        return dict(categories)

    def find_attack_chains(self) -> List[List[int]]:
        """Find chains of states that form attack combos."""
        chains = []
        visited = set()

        for start_state in self.paac.states:
            if start_state.index in visited:
                continue
            if len(start_state.transitions) == 0:
                continue

            # Follow transition chains
            chain = [start_state.index]
            current = start_state.index
            chain_visited = {current}

            while True:
                # Find the highest-sequence transition that isn't back to start
                next_states = [(t.target_state, t.sequence, t.threshold)
                               for t in self.paac.states[current].transitions
                               if t.target_state not in chain_visited
                               and t.target_state < len(self.paac.states)]
                if not next_states:
                    break
                # Pick the one with the lowest threshold (most likely to be a combo continuation)
                next_states.sort(key=lambda x: (x[2], x[1]))
                next_state = next_states[0][0]
                chain.append(next_state)
                chain_visited.add(next_state)
                current = next_state
                if len(chain) > 20:  # safety limit
                    break

            if len(chain) > 2:
                chains.append(chain)
                visited.update(chain)

        return chains

    def analyze_condition_patterns(self) -> Dict[str, any]:
        """Analyze patterns in the condition graph section."""
        if not self.paac.condition_records:
            return {'message': 'No condition records found'}

        results = {}

        # Float value distribution
        all_floats = []
        for rec in self.paac.condition_records:
            all_floats.extend(rec.floats)
        float_counter = Counter(round(f, 4) for f in all_floats)
        results['common_float_values'] = float_counter.most_common(20)

        # Size of condition section
        results['section_size'] = self.paac.condition_section_size
        results['section_start'] = self.paac.condition_section_offset
        results['record_count'] = len(self.paac.condition_records)

        return results

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    def generate_report(self) -> str:
        lines = []
        p = self.paac

        def ln(s=''):
            lines.append(s)

        def section(title):
            ln()
            ln('=' * 80)
            ln(f'  {title}')
            ln('=' * 80)

        # ---- FILE OVERVIEW ----
        section('FILE OVERVIEW')
        ln(f'File: {p.filepath}')
        ln(f'Size: {p.filesize:,} bytes (0x{p.filesize:x})')
        ln(f'Header node count: {p.header_node_count}')
        ln(f'Header speed: {p.header_speed:.4f}')
        ln(f'Header flags: 0x{p.header_flags:08x}')
        ln(f'States found (via marker): {len(p.states)}')
        ln(f'  (Header says {p.header_node_count} -- difference of {p.header_node_count - len(p.states)}'
           f' may include sub-nodes in condition graph)')
        total_trans = sum(len(s.transitions) for s in p.states)
        ln(f'Total transitions: {total_trans}')
        ln(f'Label strings: {p.label_count}')
        ln(f'Animation paths: {p.anim_path_count}')
        ln(f'Extra string tables: {len(p.extra_tables)}')

        # ---- MEMORY MAP ----
        section('FILE MEMORY MAP')
        ln(f'0x{0:08x} - 0x{0x43:08x}  Header ({0x44} bytes)')
        if p.states:
            first_state = p.states[0].state_start
            last_state = p.states[-1].config_end
            ln(f'0x{first_state:08x} - 0x{last_state:08x}  State records ({last_state - first_state:,} bytes)')
        ln(f'0x{p.label_table_offset:08x} - 0x{p.anim_path_table_offset:08x}  Label string table ({p.label_count} entries)')
        if p.anim_paths:
            anim_end = p.anim_paths[-1].offset + 1 + p.anim_paths[-1].length
            ln(f'0x{p.anim_path_table_offset:08x} - 0x{anim_end:08x}  Animation paths ({p.anim_path_count} entries)')
        for i, (off, cnt, entries) in enumerate(p.extra_tables):
            if entries:
                end = entries[-1].offset + 1 + entries[-1].length
                ln(f'0x{off:08x} - 0x{end:08x}  Extra table {i} ({cnt} entries)')
            else:
                ln(f'0x{off:08x}                  Extra table {i} ({cnt} entries, empty)')
        ln(f'0x{p.condition_section_offset:08x} - 0x{p.filesize:08x}  Condition graph ({p.condition_section_size:,} bytes)')

        # ---- LABEL STRING TABLE ----
        section('LABEL STRING TABLE')
        ln(f'Offset: 0x{p.label_table_offset:x}')
        ln(f'Count: {p.label_count}')
        ln()
        for e in p.labels:
            ln(f'  [{e.index:3d}] len={e.length:3d} @0x{e.offset:x}: "{e.text}"')

        # Key labels for analysis
        key_labels = {}
        for e in p.labels:
            if 'guard' in e.text.lower():
                key_labels['guard'] = e.index
            if 'norattack' in e.text.lower():
                key_labels['norattack'] = e.index
            if 'hardattack' in e.text.lower():
                key_labels['hardattack'] = e.index

        ln()
        ln(f'Key labels: {key_labels}')

        # ---- ANIMATION PATHS (summary) ----
        section('ANIMATION PATHS (summary)')
        ln(f'Count: {p.anim_path_count}')
        if p.anim_paths:
            # Categorize by keyword
            categories = defaultdict(int)
            for ap in p.anim_paths:
                path_lower = ap.path.lower()
                if 'att_combo' in path_lower:
                    categories['attack_combo'] += 1
                elif 'att_normal' in path_lower:
                    categories['attack_normal'] += 1
                elif 'att_' in path_lower:
                    categories['attack_other'] += 1
                elif 'guard' in path_lower or 'grd' in path_lower:
                    categories['guard'] += 1
                elif 'idle' in path_lower:
                    categories['idle'] += 1
                elif 'move' in path_lower or 'walk' in path_lower or 'run' in path_lower:
                    categories['movement'] += 1
                elif 'jump' in path_lower:
                    categories['jump'] += 1
                elif 'skill' in path_lower:
                    categories['skill'] += 1
                elif 'damage' in path_lower or 'hit' in path_lower:
                    categories['hit_reaction'] += 1
                else:
                    categories['other'] += 1

            for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
                ln(f'  {cat}: {cnt}')

            ln()
            ln('Attack animations:')
            for ap in p.anim_paths:
                if 'att_' in ap.path.lower():
                    ln(f'  [{ap.index:3d}] {ap.path}')

        # ---- STATE LIST ----
        section('COMPLETE STATE LIST')
        trans_dist = Counter(len(s.transitions) for s in p.states)
        ln(f'Transition count distribution:')
        for cnt, num in sorted(trans_dist.items()):
            ln(f'  {cnt} transitions: {num} states')

        ln()
        ln(f'{"Idx":>4s}  {"Offset":>8s}  {"Label":>20s}  {"Trans":>5s}  {"Targets":s}')
        ln('-' * 80)
        for s in p.states:
            targets = ', '.join(str(t.target_state) for t in s.transitions[:8])
            if len(s.transitions) > 8:
                targets += '...'
            label_str = s.label_name[:20]
            ln(f'{s.index:4d}  0x{s.marker_offset:06x}  {label_str:>20s}  {len(s.transitions):5d}  [{targets}]')

        # ---- TRANSITION MAP ----
        section('TRANSITION MAP')
        ln('Forward transitions (state -> targets):')
        for si in sorted(self.forward_map.keys())[:100]:
            targets_str = ', '.join(
                f'{t}(thresh={th:.2f},seq={sq})'
                for t, th, sq in self.forward_map[si]
            )
            ln(f'  State {si:4d} -> {targets_str}')
        if len(self.forward_map) > 100:
            ln(f'  ... ({len(self.forward_map) - 100} more states with transitions)')

        ln()
        ln('Most targeted states (reverse map):')
        target_counts = Counter()
        for target, sources in self.reverse_map.items():
            target_counts[target] = len(sources)
        for target, cnt in target_counts.most_common(30):
            if target < len(p.states):
                label = p.states[target].label_name
            else:
                label = f'<state {target} not in marker set>'
            ln(f'  State {target:4d} ({label}): targeted by {cnt} states')

        # ---- GUARD ANALYSIS ----
        section('GUARD TRANSITION ANALYSIS')
        guard_state = self.find_guard_state()
        ln(f'Guard state: {guard_state}')
        if guard_state < len(p.states):
            gs = p.states[guard_state]
            ln(f'  Label: {gs.label_name}')
            ln(f'  Own transitions: {len(gs.transitions)}')
            for t in gs.transitions:
                ln(f'    -> state {t.target_state} (thresh={t.threshold:.4f}, seq={t.sequence})')

        blocked = self.get_guard_blocked_states(guard_state)
        ln(f'\nStates that CANNOT transition to guard (state {guard_state}): {len(blocked)} of {len(p.states)}')
        ln(f'States that CAN transition to guard: {len(p.states) - len(blocked) - len([s for s in p.states if len(s.transitions) == 0])}')
        ln(f'States with no transitions at all: {len([s for s in p.states if len(s.transitions) == 0])}')

        ln()
        ln('Guard-blocked states with transitions (likely attack sub-states):')
        guard_blocked_with_trans = [si for si in blocked if len(p.states[si].transitions) > 0]
        for si in guard_blocked_with_trans[:50]:
            s = p.states[si]
            targets = ', '.join(str(t.target_state) for t in s.transitions)
            ln(f'  State {si:4d} ({s.label_name}): transitions to [{targets}]')
        if len(guard_blocked_with_trans) > 50:
            ln(f'  ... ({len(guard_blocked_with_trans) - 50} more)')

        # ---- STATE CLASSIFICATION ----
        section('STATE CLASSIFICATION')
        categories = self.classify_attack_states()
        for cat_name, state_list in sorted(categories.items()):
            ln(f'{cat_name}: {len(state_list)} states')
            for si in state_list[:10]:
                s = p.states[si]
                ln(f'  State {si:4d} ({s.label_name}): {len(s.transitions)} transitions')
            if len(state_list) > 10:
                ln(f'  ... ({len(state_list) - 10} more)')
            ln()

        # ---- ATTACK CHAINS ----
        section('ATTACK COMBO CHAINS')
        chains = self.find_attack_chains()
        ln(f'Found {len(chains)} chains (>2 states):')
        for i, chain in enumerate(chains[:30]):
            chain_str = ' -> '.join(str(s) for s in chain)
            # Check if any state in chain is guard-blocked
            blocked_in_chain = [s for s in chain if s in blocked]
            ln(f'  Chain {i}: {chain_str}')
            if blocked_in_chain:
                ln(f'    Guard-blocked in chain: {blocked_in_chain}')
        if len(chains) > 30:
            ln(f'  ... ({len(chains) - 30} more chains)')

        # ---- CONDITION GRAPH ----
        section('CONDITION GRAPH ANALYSIS')
        cond_analysis = self.analyze_condition_patterns()
        ln(f'Section start: 0x{cond_analysis.get("section_start", 0):x}')
        ln(f'Section size: {cond_analysis.get("section_size", 0):,} bytes')
        ln(f'Record candidates found: {cond_analysis.get("record_count", 0)}')

        if 'common_float_values' in cond_analysis:
            ln()
            ln('Most common float values in condition section:')
            for fval, cnt in cond_analysis['common_float_values']:
                ln(f'  {fval:10.4f}: {cnt} occurrences')

        ln()
        ln('Condition section structure analysis:')
        ln(f'  The tail section ({cond_analysis.get("section_size", 0):,} bytes) contains the')
        ln(f'  transition condition graph. Each state\'s transitions reference conditions')
        ln(f'  that must be met (input keys pressed, animation progress, etc.).')
        ln(f'  The section contains 80-byte blocks with:')
        ln(f'    - Float pairs (animation progress thresholds)')
        ln(f'    - -1.0 sentinel values (same as transition sentinels)')
        ln(f'    - Integer references (likely string table indices for input keys)')
        ln(f'  These blocks define WHEN transitions are allowed.')

        # ---- FEASIBILITY ASSESSMENT ----
        section('PATCHING FEASIBILITY ASSESSMENT')

        ln('GOAL: Add guard (block) transitions to attack sub-states so players')
        ln('      can cancel attack animations by pressing guard (LB).')
        ln()

        ln('APPROACH A: Add new transition entries to attack states')
        ln('  STATUS: VERY DIFFICULT')
        ln('  Each state\'s transition count is a uint8 at a fixed offset.')
        ln('  Adding a transition would require:')
        ln('    1. Incrementing the count byte')
        ln('    2. Inserting 16 bytes for the new transition record')
        ln('    3. Shifting ALL subsequent data (string tables, condition graph)')
        ln('    4. Updating all absolute offsets in the file')
        ln('  RISK: File format likely has no slack space. Insertion would break')
        ln('        offsets throughout the file.')
        ln()

        # Check if any states have low-priority transitions we could replace
        replaceable = []
        for si in guard_blocked_with_trans:
            s = p.states[si]
            # Look for transitions with high sequence numbers (low priority)
            for t in s.transitions:
                if t.sequence >= 5 and t.threshold > 0.3:
                    replaceable.append((si, t))

        ln('APPROACH B: Replace low-priority transitions with guard transitions')
        ln(f'  STATUS: POSSIBLE for {len(replaceable)} transitions')
        if replaceable:
            ln('  These transitions have high sequence numbers and late thresholds,')
            ln('  making them candidates for replacement:')
            for si, t in replaceable[:20]:
                s = p.states[si]
                ln(f'    State {si} ({s.label_name}): seq={t.sequence} thresh={t.threshold:.2f} target={t.target_state}')
                ln(f'      -> Replace target with guard state {guard_state}')
            if len(replaceable) > 20:
                ln(f'    ... ({len(replaceable) - 20} more)')
        else:
            ln('  No suitable replacement candidates found.')
        ln('  RISK: Replacing transitions changes combo behavior. The replaced')
        ln('        transition\'s original function would be lost.')
        ln()

        ln('APPROACH C: Modify condition graph to allow blocked transitions')
        ln('  STATUS: REQUIRES MORE RE')
        ln('  The 80-byte condition blocks in the tail section define WHEN')
        ln('  transitions are allowed. If guard transitions exist but are')
        ln('  gated by conditions (e.g., "not during attack"), modifying')
        ln('  those conditions could enable them.')
        ln('  RISK: Condition format not fully decoded. Blind patching could')
        ln('        break all transitions.')
        ln()

        ln('APPROACH D: Runtime hook (ASI mod)')
        ln('  STATUS: MOST FEASIBLE')
        ln('  Instead of patching the .paac file:')
        ln('    1. Hook the action chart evaluation function in memory')
        ln('    2. When the player presses guard during an attack state,')
        ln('       force the state machine to transition to the guard state')
        ln('    3. This bypasses the condition graph entirely')
        ln('  ADVANTAGES:')
        ln('    - No file modification needed (works across game updates)')
        ln('    - Can be toggled on/off')
        ln('    - Doesn\'t break other transitions')
        ln('  REQUIREMENTS:')
        ln('    - Find the ActionChart::evaluate() function in memory')
        ln('    - Understand how the current state index is stored')
        ln('    - Hook to inject guard transitions at runtime')
        ln()

        ln('RECOMMENDATION: Use APPROACH D (runtime hook) as the primary method.')
        ln('APPROACH B (transition replacement) is a viable fallback for specific')
        ln('attack states where a low-priority transition can be sacrificed.')
        ln()

        # Summary statistics for modding
        ln('KEY STATISTICS FOR MODDING:')
        ln(f'  Total states: {len(p.states)}')
        ln(f'  States with transitions: {len([s for s in p.states if s.transitions])}')
        ln(f'  Guard-blocked states (with transitions): {len(guard_blocked_with_trans)}')
        ln(f'  Replaceable transitions: {len(replaceable)}')
        ln(f'  Transition record size: {PaacParser.TRANSITION_RECORD_SIZE} bytes')
        ln(f'  Transition format: [float32 threshold][float32 -1.0][uint32 target][uint32 seq]')
        ln(f'  Config block size: {PaacParser.CONFIG_BLOCK_SIZE} bytes (between states)')

        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Cross-file validation
# ---------------------------------------------------------------------------

def cross_validate(filepath1: str, filepath2: str):
    """Compare two .paac files to validate format assumptions."""
    lines = []

    def ln(s=''):
        lines.append(s)

    section_title = f'CROSS-VALIDATION: {os.path.basename(filepath1)} vs {os.path.basename(filepath2)}'
    ln()
    ln('=' * 80)
    ln(f'  {section_title}')
    ln('=' * 80)

    p1 = PaacParser(filepath1)
    p2 = PaacParser(filepath2)

    h1 = p1.parse_header()
    h2 = p2.parse_header()

    m1 = p1.find_state_markers()
    m2 = p2.find_state_markers()

    ln(f'{os.path.basename(filepath1)}:')
    ln(f'  Size: {p1.filesize:,} bytes')
    ln(f'  Header node count: {h1[0]}')
    ln(f'  Header speed: {h1[1]:.4f}')
    ln(f'  State markers found: {len(m1)}')
    ln(f'  Difference (header - markers): {h1[0] - len(m1)}')

    ln(f'{os.path.basename(filepath2)}:')
    ln(f'  Size: {p2.filesize:,} bytes')
    ln(f'  Header node count: {h2[0]}')
    ln(f'  Header speed: {h2[1]:.4f}')
    ln(f'  State markers found: {len(m2)}')
    ln(f'  Difference (header - markers): {h2[0] - len(m2)}')

    # Check state structure consistency
    ln()
    ln('State record structure consistency:')

    for name, parser, markers in [
        (os.path.basename(filepath1), p1, m1),
        (os.path.basename(filepath2), p2, m2),
    ]:
        deltas = [markers[i + 1] - markers[i] for i in range(min(10, len(markers) - 1))]
        ln(f'  {name}: first 10 inter-marker deltas = {deltas}')

        # Check post-marker pattern consistency
        patterns = Counter()
        for m in markers[:50]:
            if m + 12 <= parser.filesize:
                pat = tuple(parser.data[m + 6:m + 18])
                patterns[pat] += 1
        ln(f'  {name}: {len(patterns)} unique post-marker patterns in first 50 states')

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    default_dir = r'C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm'
    default_file = os.path.join(default_dir, 'sword_upper.paac')
    default_output = r'C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\tools\paac_analysis.txt'
    basic_file = os.path.join(default_dir, 'basic_upper.paac')

    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        filepath = default_file

    output_path = default_output
    for i, arg in enumerate(sys.argv):
        if arg == '--output' and i + 1 < len(sys.argv):
            output_path = sys.argv[i + 1]

    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    # Parse the main file
    parser = PaacParser(filepath)
    paac = parser.parse()

    # Analyze
    analyzer = PaacAnalyzer(paac)
    report = analyzer.generate_report()

    # Cross-validate with basic_upper if available
    if os.path.isfile(basic_file) and os.path.abspath(filepath) != os.path.abspath(basic_file):
        xval = cross_validate(filepath, basic_file)
        report += '\n' + xval

    # Write report
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"\nReport written to: {output_path}")
    print(f"Report size: {len(report):,} characters")

    # Print summary to console
    print("\n--- SUMMARY ---")
    print(f"States: {len(paac.states)}")
    print(f"Total transitions: {sum(len(s.transitions) for s in paac.states)}")
    print(f"Labels: {paac.label_count}")
    print(f"Animation paths: {paac.anim_path_count}")

    guard_state = analyzer.find_guard_state()
    blocked = analyzer.get_guard_blocked_states(guard_state)
    blocked_with_trans = [si for si in blocked if len(paac.states[si].transitions) > 0]
    print(f"Guard state: {guard_state}")
    print(f"Guard-blocked states (with transitions): {len(blocked_with_trans)}")
    print(f"Recommendation: Runtime hook (ASI mod) for animation cancel")


if __name__ == '__main__':
    main()
