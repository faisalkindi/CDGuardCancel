#!/usr/bin/env python3
"""
Deploy exact-size sword_upper condition probes into the live 0.paz slot.

This script is intentionally narrow:
- It only knows about the verified single probes and verified exact combos.
- It patches the already-confirmed sword_upper compressed slot in-place.
- It can identify what is currently installed by comparing slot hashes.
- It appends every apply/restore/record action to PROBE_TEST_LOG.csv.

Usage examples:
  py -3 tools\\deploy_condition_probe.py list
  py -3 tools\\deploy_condition_probe.py status
  py -3 tools\\deploy_condition_probe.py apply probe_cancel_541
  py -3 tools\\deploy_condition_probe.py restore
  py -3 tools\\deploy_condition_probe.py record probe_cancel_541 signal --notes "Guard came out once on 3rd combo hit"
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MOD_TEST = ROOT / "mod_test"
LOG_PATH = ROOT / "PROBE_TEST_LOG.csv"

GAME_PAZ = Path(r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.paz")
BACKUP_PAZ = Path(r"E:\SteamLibrary\steamapps\common\Crimson Desert\0010\0.paz.bak")

SLOT_OFFSET = 225_322_576
SLOT_SIZE = 224_084

PROBE_ORDER = [
    "probe_cancel_541",
    "probe_cancel_212",
    "probe_guard_423",
    "probe_cancel_206",
    "probe_guardstart_400",
    "probe_guard_294",
    "probe_guard_171",
    "combo_cancel_near_cluster",
    "combo_cancel_guard_signal",
    "combo_top3_exact",
    "cluster7_cancel_pair_fist_skill2",
    "cluster7_cancel_pair_crouch_skill1",
    "cluster7_cancel_triplet_local",
]

PROBE_DESCRIPTIONS = {
    "probe_cancel_541": "key_crouch -> key_cancel (src 1160, target 13001)",
    "probe_cancel_212": "LowerLeftArm_1 -> key_cancel (src 1785, target 13001)",
    "probe_guard_423": "NeckAndLeftArm -> key_guard (src 5161, target 0)",
    "probe_cancel_206": "LeftArmNoSplice -> key_cancel (src 3751, target 13001)",
    "probe_guardstart_400": "CharacterMeshEffectWeapon -> key_guard_start (src 3267, target 13001)",
    "probe_guard_294": "BothHands -> key_guard (src 4121, target 0)",
    "probe_guard_171": "NeckAndLeftArm -> key_guard (src 1330, target 0)",
    "combo_cancel_near_cluster": "probe_cancel_212 + probe_cancel_541",
    "combo_cancel_guard_signal": "probe_guard_423 + probe_cancel_541",
    "combo_top3_exact": "probe_cancel_212 + probe_guard_423 + probe_cancel_541",
    "cluster7_cancel_pair_fist_skill2": "cluster 7: key_skill_2 + key_fistattack -> key_cancel",
    "cluster7_cancel_pair_crouch_skill1": "cluster 7: key_crouch + key_skill_1 -> key_cancel",
    "cluster7_cancel_triplet_local": "cluster 7: key_crouch + key_skill_12_start + LowerLeftArm_1 -> key_cancel",
}

OUTCOME_CHOICES = {
    "signal",
    "partial",
    "no_signal",
    "crash",
    "blocked",
    "not_tested",
}


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_slot(path: Path) -> bytes:
    with path.open("rb") as fh:
        fh.seek(SLOT_OFFSET)
        data = fh.read(SLOT_SIZE)
    if len(data) != SLOT_SIZE:
        raise RuntimeError(f"Expected {SLOT_SIZE} bytes from {path}, got {len(data)}")
    return data


def write_slot(path: Path, blob: bytes) -> None:
    if len(blob) != SLOT_SIZE:
        raise ValueError(f"Expected probe blob of {SLOT_SIZE} bytes, got {len(blob)}")
    with path.open("r+b") as fh:
        fh.seek(SLOT_OFFSET)
        fh.write(blob)


def ensure_log() -> None:
    if LOG_PATH.exists():
        return
    with LOG_PATH.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "timestamp",
                "action",
                "probe",
                "status_before",
                "status_after",
                "outcome",
                "notes",
            ]
        )


def append_log(
    action: str,
    probe: str,
    status_before: str,
    status_after: str,
    outcome: str = "",
    notes: str = "",
) -> None:
    ensure_log()
    with LOG_PATH.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([now_iso(), action, probe, status_before, status_after, outcome, notes])


def game_running() -> bool:
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq CrimsonDesert.exe"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return "CrimsonDesert.exe" in proc.stdout


def available_probes() -> dict[str, Path]:
    probes: dict[str, Path] = {}
    for name in PROBE_ORDER:
        blob = MOD_TEST / f"{name}_comp.bin"
        if not blob.exists():
            continue
        if blob.stat().st_size != SLOT_SIZE:
            continue
        probes[name] = blob
    return probes


def identify_status(live_blob: bytes, probes: dict[str, Path]) -> tuple[str, str]:
    live_hash = sha256_hex(live_blob)
    backup_blob = read_slot(BACKUP_PAZ)
    if live_blob == backup_blob:
        return "original", live_hash

    for name, path in probes.items():
        if live_blob == path.read_bytes():
            return name, live_hash

    return "unknown_modified", live_hash


def print_status(probes: dict[str, Path]) -> str:
    live_blob = read_slot(GAME_PAZ)
    status_name, live_hash = identify_status(live_blob, probes)
    print(f"Live PAZ:    {GAME_PAZ}")
    print(f"Backup PAZ:  {BACKUP_PAZ}")
    print(f"Slot:        0x{SLOT_OFFSET:X} ({SLOT_SIZE} bytes)")
    print(f"Installed:   {status_name}")
    print(f"Slot sha256: {live_hash}")
    if game_running():
        print("Warning: CrimsonDesert.exe is currently running.")
    return status_name


def cmd_list(_: argparse.Namespace) -> int:
    probes = available_probes()
    current = identify_status(read_slot(GAME_PAZ), probes)[0]
    print("Available verified probes:")
    for idx, name in enumerate(PROBE_ORDER, start=1):
        blob = probes.get(name)
        mark = " [installed]" if name == current else ""
        state = "ready" if blob else "missing"
        print(f"  {idx}. {name}: {PROBE_DESCRIPTIONS[name]} [{state}]{mark}")
    print("\nRecommended first-pass order:")
    for name in PROBE_ORDER[:4]:
        print(f"  - {name}")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    probes = available_probes()
    print_status(probes)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    probes = available_probes()
    if args.probe not in probes:
        print(f"Unknown or unavailable probe: {args.probe}", file=sys.stderr)
        return 1

    before = identify_status(read_slot(GAME_PAZ), probes)[0]
    if before == "unknown_modified" and not args.force:
        print(
            "Refusing to overwrite an unknown modified slot. "
            "Run `status`, restore first, or re-run with --force.",
            file=sys.stderr,
        )
        return 1

    if game_running():
        print("Warning: CrimsonDesert.exe appears to be running. Patch will affect a future load, not the current session.")

    blob = probes[args.probe].read_bytes()
    if args.dry_run:
        after = args.probe
    else:
        write_slot(GAME_PAZ, blob)
        after = identify_status(read_slot(GAME_PAZ), probes)[0]
        append_log("apply", args.probe, before, after, notes=args.notes or "")

    print(f"Applied:     {args.probe}{' (dry-run)' if args.dry_run else ''}")
    print(f"Description: {PROBE_DESCRIPTIONS[args.probe]}")
    print(f"Before:      {before}")
    print(f"After:       {after}")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    probes = available_probes()
    before = identify_status(read_slot(GAME_PAZ), probes)[0]
    if game_running():
        print("Warning: CrimsonDesert.exe appears to be running. Restore will affect a future load, not the current session.")

    original_blob = read_slot(BACKUP_PAZ)
    if args.dry_run:
        after = "original"
    else:
        write_slot(GAME_PAZ, original_blob)
        after = identify_status(read_slot(GAME_PAZ), probes)[0]
        append_log("restore", "original", before, after, notes=args.notes or "")

    print(f"Restored live slot from backup{' (dry-run)' if args.dry_run else ''}.")
    print(f"Before: {before}")
    print(f"After:  {after}")
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    probes = available_probes()
    current = identify_status(read_slot(GAME_PAZ), probes)[0]
    probe = args.probe or current
    if probe == "original":
        print("Nothing probe-specific is currently installed. Pass --probe to record against a specific test.", file=sys.stderr)
        return 1
    append_log("record", probe, current, current, outcome=args.outcome, notes=args.notes or "")
    print(f"Recorded outcome for {probe}: {args.outcome}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deploy and track exact-size sword_upper probe blobs")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List verified probes and their order").set_defaults(func=cmd_list)
    sub.add_parser("status", help="Show which probe is currently installed").set_defaults(func=cmd_status)

    apply_p = sub.add_parser("apply", help="Install a verified probe into the live PAZ slot")
    apply_p.add_argument("probe", choices=PROBE_ORDER)
    apply_p.add_argument("--force", action="store_true", help="Allow overwrite when the live slot is unknown_modified")
    apply_p.add_argument("--dry-run", action="store_true", help="Show what would be applied without writing the live PAZ")
    apply_p.add_argument("--notes", help="Optional note stored in the test log")
    apply_p.set_defaults(func=cmd_apply)

    restore_p = sub.add_parser("restore", help="Restore the original sword_upper slot from 0.paz.bak")
    restore_p.add_argument("--dry-run", action="store_true", help="Show what would be restored without writing the live PAZ")
    restore_p.add_argument("--notes", help="Optional note stored in the test log")
    restore_p.set_defaults(func=cmd_restore)

    record_p = sub.add_parser("record", help="Append a live test result to the log")
    record_p.add_argument("outcome", choices=sorted(OUTCOME_CHOICES))
    record_p.add_argument("--probe", help="Probe name to associate with the result; defaults to the currently installed probe")
    record_p.add_argument("--notes", help="Observed behavior, crash details, or test context")
    record_p.set_defaults(func=cmd_record)

    return parser


def main() -> int:
    if not GAME_PAZ.exists():
        print(f"Missing live PAZ: {GAME_PAZ}", file=sys.stderr)
        return 1
    if not BACKUP_PAZ.exists():
        print(f"Missing backup PAZ: {BACKUP_PAZ}", file=sys.stderr)
        return 1

    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
