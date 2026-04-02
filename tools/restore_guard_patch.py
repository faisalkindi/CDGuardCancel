#!/usr/bin/env python3
"""Restore original PAZ and PAMT from backups."""

import shutil
import os
import sys

PAZ_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.paz"
PAZ_BACKUP = PAZ_PATH + ".bak"
PAMT_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.pamt"
PAMT_BACKUP = PAMT_PATH + ".bak"
PAPGT_PATH = r"E:\SteamLibrary\steamapps\common\Crimson Desert\papgt"
PAPGT_BACKUP = PAPGT_PATH + ".bak"

def main():
    print("Restoring original files...")

    for src, dst, name in [(PAZ_BACKUP, PAZ_PATH, "PAZ"), (PAMT_BACKUP, PAMT_PATH, "PAMT"), (PAPGT_BACKUP, PAPGT_PATH, "PAPGT")]:
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(f"  {name}: Restored from backup")
        else:
            print(f"  {name}: No backup found at {src}")

    print("Done.")

if __name__ == "__main__":
    main()
    input("Press Enter to close...")
