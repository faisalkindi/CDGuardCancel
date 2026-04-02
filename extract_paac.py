#!/usr/bin/env python3
"""Extract specific .paac files from PAZ directory 0010 for animation cancel research."""

import sys
import os

# Add PAZUnpacker to path
sys.path.insert(0, r'C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\PAZUnpacker')
from paz_extract import parse_pamt, extract_file

GAME_DIR = r'E:\SteamLibrary\steamapps\common\Crimson Desert'
OUTPUT_DIR = r'C:\Users\faisa\Ai\Mods Dev\CrimsonDesert-Mods\CDAnimCancel\extracted'
SUBDIR = '0010'

# Files to extract: sword_upper.paac, basic_hitaction.paac, and all player combat .paac files
TARGETS = [
    # Primary targets
    'sword_upper.paac',
    'basic_hitaction.paac',
    # All player weapon upper action charts (combat state machines)
    'battleaxe_upper.paac',
    'dualsword_upper.paac',
    'dualweapon_upper.paac',
    'fist_upper.paac',
    'longsword_upper.paac',
    'twohandsword_upper.paac',
    'dagger_upper.paac',
    # Player lower hitaction
    'basic_lower_hitaction.paac',
    # Attack info (damage data for sword)
    'sword_upper.paatt',
    'basic_hitaction.paatt',
    # Common skill (may contain guard/block)
    'common_skill_upper.paac',
    # Basic upper (may have guard transitions)
    'basic_upper.paac',
]

def main():
    pamt_path = os.path.join(GAME_DIR, SUBDIR, '0.pamt')
    print(f'Parsing {pamt_path}...')
    pamt = parse_pamt(pamt_path)
    print(f'  {pamt["n_files"]} files in directory {SUBDIR}')

    # Find matching files (player character files in 1_pc/1_phm/)
    target_set = set(t.lower() for t in TARGETS)
    to_extract = []
    for fr in pamt['file_records']:
        fname = fr['filename'].lower()
        full_path = fr['dir_path'] + '/' + fr['filename']
        # Match by filename for player files only (1_pc/1_phm path)
        if fname in target_set and '1_pc/1_phm' in fr['dir_path']:
            to_extract.append(fr)
        # Also get the common hitaction files (monster/shared)
        elif fname == 'common_hitaction.paac' and 'upperaction/2_mon' in fr['dir_path']:
            to_extract.append(fr)

    print(f'\nFound {len(to_extract)} files to extract:')
    for fr in to_extract:
        full_path = fr['dir_path'] + '/' + fr['filename']
        print(f'  {fr["type_code"]:04x} {fr["compressed_size"]:>10,} -> {fr["decompressed_size"]:>10,}  {full_path}')

    # Extract
    paz_handles = {}
    extracted = []
    try:
        for fr in to_extract:
            data, is_encrypted = extract_file(GAME_DIR, SUBDIR, fr, paz_handles)
            if data is None:
                print(f'  ERROR: Could not read {fr["filename"]}')
                continue
            if is_encrypted:
                print(f'  ENCRYPTED: {fr["filename"]} (skipping)')
                continue

            # Write to output, preserving directory structure
            full_path = fr['dir_path'] + '/' + fr['filename']
            out_path = os.path.join(OUTPUT_DIR, full_path)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as f:
                f.write(data)

            size = len(data)
            extracted.append((out_path, size))
            print(f'  OK: {full_path} ({size:,} bytes)')
    finally:
        for fh in paz_handles.values():
            fh.close()

    print(f'\n{"="*60}')
    print(f'Extracted {len(extracted)} files to {OUTPUT_DIR}')
    print(f'\nFile sizes:')
    total = 0
    for path, size in extracted:
        rel = os.path.relpath(path, OUTPUT_DIR)
        print(f'  {size:>12,}  {rel}')
        total += size
    print(f'  {"":>12}  --------')
    print(f'  {total:>12,}  TOTAL')


if __name__ == '__main__':
    main()
