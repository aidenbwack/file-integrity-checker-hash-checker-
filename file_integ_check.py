#!/usr/bin/env python3
"""Simple file integrity checker.

Usage:
  thing.py init   [-m MANIFEST] [PATH]
  thing.py check  [-m MANIFEST] [PATH]
  thing.py hash   FILE
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

DEFAULT_MANIFEST = ".integrity.json"


@dataclass(frozen=True)
class FileRecord:
    path: str
    sha256: str


def iter_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_manifest(path: str) -> Dict[str, FileRecord]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    records: Dict[str, FileRecord] = {}
    for item in raw.get("files", []):
        records[item["path"]] = FileRecord(path=item["path"], sha256=item["sha256"])
    return records


def save_manifest(path: str, root: str, records: List[FileRecord]) -> None:
    data = {
        "root": os.path.abspath(root),
        "algorithm": "sha256",
        "files": [
            {"path": record.path, "sha256": record.sha256} for record in records
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def build_manifest(root: str, manifest_path: str) -> None:
    root = os.path.abspath(root)
    records: List[FileRecord] = []
    for abs_path in iter_files(root):
        rel_path = os.path.relpath(abs_path, root)
        if os.path.abspath(abs_path) == os.path.abspath(manifest_path):
            continue
        records.append(FileRecord(path=rel_path, sha256=sha256_file(abs_path)))
    save_manifest(manifest_path, root, records)


def check_manifest(root: str, manifest_path: str) -> int:
    root = os.path.abspath(root)
    expected = load_manifest(manifest_path)
    seen: Dict[str, str] = {}

    for abs_path in iter_files(root):
        rel_path = os.path.relpath(abs_path, root)
        if os.path.abspath(abs_path) == os.path.abspath(manifest_path):
            continue
        seen[rel_path] = sha256_file(abs_path)

    missing = sorted(set(expected.keys()) - set(seen.keys()))
    added = sorted(set(seen.keys()) - set(expected.keys()))

    modified: List[Tuple[str, str, str]] = []
    for path, record in expected.items():
        if path in seen and record.sha256 != seen[path]:
            modified.append((path, record.sha256, seen[path]))

    ok = True
    if missing:
        ok = False
        print("Missing files:")
        for path in missing:
            print(f"  - {path}")
    if added:
        ok = False
        print("Unexpected files:")
        for path in added:
            print(f"  - {path}")
    if modified:
        ok = False
        print("Modified files:")
        for path, expected_hash, actual_hash in modified:
            print(f"  - {path}\n    expected: {expected_hash}\n    actual:   {actual_hash}")

    if ok:
        print("OK: all files match manifest")
        return 0

    return 1


def hash_single_file(path: str) -> int:
    if not os.path.isfile(path):
        print(f"Not a file: {path}", file=sys.stderr)
        return 2
    print(sha256_file(path))
    return 0


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple file integrity checker")
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="Create a manifest for a path")
    init_parser.add_argument("path", nargs="?", default=".", help="Root path")
    init_parser.add_argument(
        "-m", "--manifest", default=DEFAULT_MANIFEST, help="Manifest file name"
    )

    check_parser = sub.add_parser("check", help="Verify files against manifest")
    check_parser.add_argument("path", nargs="?", default=".", help="Root path")
    check_parser.add_argument(
        "-m", "--manifest", default=DEFAULT_MANIFEST, help="Manifest file name"
    )

    hash_parser = sub.add_parser("hash", help="Hash a single file")
    hash_parser.add_argument("file", help="File to hash")

    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    if args.command == "hash":
        return hash_single_file(args.file)

    root = os.path.abspath(args.path)
    manifest_path = os.path.abspath(os.path.join(root, args.manifest))

    if args.command == "init":
        build_manifest(root, manifest_path)
        print(f"Wrote manifest: {manifest_path}")
        return 0

    if args.command == "check":
        if not os.path.exists(manifest_path):
            print(f"Manifest not found: {manifest_path}", file=sys.stderr)
            return 2
        return check_manifest(root, manifest_path)

    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
