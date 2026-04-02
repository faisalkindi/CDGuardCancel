#!/usr/bin/env python3
"""
Build the guard-from-attack patch for sword_upper.paac.

Adds a guard transition (target=0, thresh=0.0) to the 26 states that lack it,
by replacing their transition to node 112 (one of 5 similar animation variants;
nodes 88, 94, 100, 106 remain intact).

The patch is an in-place 16-byte replacement per state — file size unchanged.
"""

import struct
import shutil
import os

INPUT = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted\actionchart\bin__\upperaction\1_pc\1_phm\sword_upper.paac"
OUTPUT = r"C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\mod_test\sword_upper_guard_patch.paac"

MAGIC = b'\x4D\x30\x25\x44'
SENTINEL = b'\x00\x00\x80\xBF'

# Guard transition: [thresh=0.0] [sentinel=-1.0] [target=0] [seq=0]
GUARD_TRANS = struct.pack('<f', 0.0) + struct.pack('<f', -1.0) + struct.pack('<I', 0) + struct.pack('<I', 0)


def find_state_markers(data, start, end):
    markers = []
    pos = start
    while pos < end:
        idx = data.find(MAGIC, pos, end)
        if idx == -1:
            break
        markers.append(idx)
        pos = idx + 1
    return markers


def find_transitions(data, off, size):
    """Find all inline transitions in a state record."""
    rec = data[off:off + size]
    transitions = []
    p = 0
    while True:
        idx = rec.find(SENTINEL, p)
        if idx == -1:
            break
        if idx >= 4 and idx + 8 <= len(rec):
            thresh = struct.unpack_from('<f', rec, idx - 4)[0]
            target = struct.unpack_from('<I', rec, idx + 4)[0]
            seq = struct.unpack_from('<I', rec, idx + 8)[0]
            if 0.0 <= thresh <= 10.0 and target < 50000 and seq < 5000:
                transitions.append({
                    'abs_off': off + idx - 4,
                    'thresh': thresh,
                    'target': target,
                    'seq': seq,
                })
        p = idx + 1
    return transitions


def main():
    data = bytearray(open(INPUT, 'rb').read())
    original_size = len(data)
    print(f"Input: {INPUT}")
    print(f"Size: {original_size} bytes")

    # Find state markers in state record area
    markers = find_state_markers(data, 0x44, 0x8E96A)
    print(f"State markers: {len(markers)}")

    # Find large states (>16 bytes)
    large_states = []
    for i in range(len(markers)):
        end = markers[i + 1] if i + 1 < len(markers) else 0x8E96A
        size = end - markers[i]
        if size > 16:
            large_states.append((i, markers[i], size))

    # Identify unguarded states
    unguarded = []
    for si, off, size in large_states:
        trans = find_transitions(data, off, size)
        has_guard = any(t['target'] == 0 for t in trans)
        if not has_guard and trans:
            unguarded.append((si, off, size, trans))

    print(f"Unguarded states: {len(unguarded)}")

    # Build patches
    patches = []
    for si, off, size, trans in unguarded:
        # Strategy: replace the transition to target=112 with guard (target=0)
        # If no target=112, replace target=1073 or the last transition
        target_112 = [t for t in trans if t['target'] == 112]
        target_1073 = [t for t in trans if t['target'] == 1073]

        if target_112:
            victim = target_112[0]  # Replace first target=112
        elif target_1073:
            victim = target_1073[-1]  # Replace last target=1073
        else:
            victim = trans[-1]  # Fallback: replace last transition

        patches.append({
            'state': si,
            'offset': victim['abs_off'],
            'old_target': victim['target'],
            'old_thresh': victim['thresh'],
            'old_seq': victim['seq'],
        })

    print(f"\nPatches to apply: {len(patches)}")
    for p in patches:
        old_bytes = data[p['offset']:p['offset'] + 16]
        print(f"  State {p['state']:>3d} @0x{p['offset']:06X}: "
              f"target={p['old_target']:>5d} thresh={p['old_thresh']:.4f} seq={p['old_seq']:>2d} -> GUARD")

    # Apply patches
    for p in patches:
        data[p['offset']:p['offset'] + 16] = GUARD_TRANS

    # Verify size unchanged
    assert len(data) == original_size, f"Size changed! {original_size} -> {len(data)}"

    # Verify guard transitions now exist
    for si, off, size, _ in unguarded:
        trans = find_transitions(data, off, size)
        has_guard = any(t['target'] == 0 for t in trans)
        if not has_guard:
            print(f"  WARNING: State {si} still has no guard after patch!")

    # Write output
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'wb') as f:
        f.write(data)

    print(f"\nOutput: {OUTPUT}")
    print(f"Size: {len(data)} bytes (unchanged: {len(data) == original_size})")
    print(f"Patches applied: {len(patches)}")

    # Verify by re-reading
    verify = open(OUTPUT, 'rb').read()
    diff_count = sum(1 for a, b in zip(open(INPUT, 'rb').read(), verify) if a != b)
    print(f"Bytes changed: {diff_count} (expected {len(patches) * 16} = {len(patches)} patches * 16 bytes)")


if __name__ == "__main__":
    main()
