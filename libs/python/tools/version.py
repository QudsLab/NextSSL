#!/usr/bin/env python3
"""
Update the ``version`` field in ``libs/python/pyproject.toml``.

Usage:
    python libs/python/tools/version.py --set 0.1.0
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def set_version(version: str) -> None:
    toml_path = Path(__file__).parent.parent / "pyproject.toml"
    if not toml_path.exists():
        print(f"[ERROR] pyproject.toml not found: {toml_path}", file=sys.stderr)
        sys.exit(1)

    content = toml_path.read_text(encoding="utf-8")
    new_content, n_subs = re.subn(
        r'^(version\s*=\s*")[^"]*(")',
        rf"\g<1>{version}\g<2>",
        content,
        flags=re.MULTILINE,
    )
    if n_subs == 0:
        print(
            f"[ERROR] No 'version = \"...\"' field found in {toml_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    toml_path.write_text(new_content, encoding="utf-8")
    print(f"[OK] Version set to {version!r} in {toml_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Set package version in pyproject.toml")
    parser.add_argument("--set", required=True, metavar="VERSION",
                        help="Version string, e.g. 0.1.0")
    args = parser.parse_args()
    set_version(args.set)


if __name__ == "__main__":
    main()
