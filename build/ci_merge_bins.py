"""Merge per-variant CI binary artifacts into the repository bin layout."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def copy_tree(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        destination = target / item.name
        if item.is_dir():
            shutil.copytree(item, destination, dirs_exist_ok=True)
        else:
            shutil.copy2(item, destination)


def parse_artifact_name(name: str) -> tuple[str, str] | None:
    parts = name.split("__", 2)
    if len(parts) != 3 or parts[0] != "nextssl":
        return None
    return parts[1], parts[2]


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge CI binary artifacts into bin/<platform>/<variant>/.")
    parser.add_argument("artifacts_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    if args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.artifacts_dir.exists():
        return 0

    for artifact_dir in sorted(path for path in args.artifacts_dir.iterdir() if path.is_dir()):
        parsed = parse_artifact_name(artifact_dir.name)
        if not parsed:
            continue
        platform, variant = parsed
        copy_tree(artifact_dir, args.output_dir / platform / variant)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())