"""Merge per-variant CI log artifacts into the repository log layout."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    if len(parts) != 3 or parts[0] != "logs":
        return None
    return parts[1], parts[2]


def read_result(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def format_summary_line(variant_dir: Path) -> str:
    variant = variant_dir.name
    result = read_result(variant_dir / "result.txt")
    status = result.get("status", "unknown")
    if status == "success":
        return f"{variant}: SUCCESS"
    if status == "failed":
        exit_code = result.get("exit_code", "?")
        reason = result.get("reason")
        suffix = f"FAILED ({exit_code})"
        if reason:
            suffix = f"{suffix} [{reason}]"
        return f"{variant}: {suffix}"
    if status == "skipped":
        reason = result.get("reason", "queue stopped after an earlier failure")
        return f"{variant}: SKIPPED ({reason})"
    return f"{variant}: UNKNOWN"


def generate_summaries(output_dir: Path) -> None:
    for platform_dir in sorted(path for path in output_dir.iterdir() if path.is_dir()):
        variant_dirs = sorted(path for path in platform_dir.iterdir() if path.is_dir())
        if not variant_dirs:
            continue
        write_lines(platform_dir / "SUMMARY.txt", [format_summary_line(path) for path in variant_dirs])


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge CI log artifacts into logs/<platform>/<variant>/.")
    parser.add_argument("artifacts_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    if args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    for artifact_dir in sorted(path for path in args.artifacts_dir.iterdir() if path.is_dir()):
        parsed = parse_artifact_name(artifact_dir.name)
        if not parsed:
            continue
        platform, variant = parsed
        copy_tree(artifact_dir, args.output_dir / platform / variant)

    generate_summaries(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())