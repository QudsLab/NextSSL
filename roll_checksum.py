"""
gen_index.py
────────────
Walk bin/ and write bin/bins.json — a nested mirror of the directory tree
where every binary file is mapped to its GitHub raw download URL.

Structure mirrors bin/ exactly:
{
    "windows": {
    "primary": {
        "main":      "https://raw.githubusercontent.com/…/bin/windows/primary/main.dll",
        "main_lite": "https://raw.githubusercontent.com/…/bin/windows/primary/main_lite.dll"
    },
    "main": { … },
    "base": { … },
    "partial": { "core": { … }, … }
    },
    "linux":   { … },
    "mac":     { … },
    "web":     { … }
}

Usage
    python gen_index.py
    python gen_index.py --bin-dir bin --repo QudsLab/NextSSL --branch main
    python gen_index.py --out bin/bins.json
"""

import argparse
import json
import os
import sys

_BIN_EXTS  = {'.dll', '.so', '.dylib', '.wasm'}
_SKIP_FILES = {'bins.json'}

RAW_BASE = 'https://raw.githubusercontent.com/{repo}/{branch}'


def _insert(tree: dict, parts: list[str], url: str) -> None:
    """Recursively insert url into nested dict using parts as path segments."""
    node = tree
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = url


def build_tree(bin_dir: str, repo: str, branch: str) -> dict:
    base_url = f'{RAW_BASE.format(repo=repo, branch=branch)}/{bin_dir}'
    tree: dict = {}

    for root, dirs, files in os.walk(bin_dir):
        dirs.sort()
        for fname in sorted(files):
            if fname in _SKIP_FILES:
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _BIN_EXTS:
                continue

            full_path = os.path.join(root, fname)
            rel_posix = full_path.replace('\\', '/').lstrip('./')
            # rel_posix is like "bin/windows/primary/main.dll"
            # strip leading "bin/" to get the tree path
            tree_rel = rel_posix[len(bin_dir):].lstrip('/')
            # stem without extension becomes dict key
            stem = os.path.splitext(fname)[0]
            segments = tree_rel.split('/')
            # Replace last segment (filename) with stem
            key_path = segments[:-1] + [stem]

            url = f'{base_url}/{tree_rel}'
            _insert(tree, key_path, url)

    return tree


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate bin/bins.json index')
    parser.add_argument('--bin-dir', default='bin',
                        help='Root bin directory (default: bin)')
    parser.add_argument('--repo', default='QudsLab/NextSSL',
                        help='GitHub owner/repo (default: QudsLab/NextSSL)')
    parser.add_argument('--branch', default='main',
                        help='Git branch (default: main)')
    parser.add_argument('--out', default=None,
                        help='Output file (default: {bin-dir}/bins.json)')
    args = parser.parse_args()

    bin_dir = args.bin_dir.rstrip('/\\')
    if not os.path.isdir(bin_dir):
        print(f'[gen_index] ERROR: bin dir not found: {bin_dir}', file=sys.stderr)
        return 1

    out_path = args.out or os.path.join(bin_dir, 'bins.json')

    tree = build_tree(bin_dir, args.repo, args.branch)

    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(tree, f, indent=2, sort_keys=True)
        f.write('\n')

    # Count files
    total = sum(
        1 for r, _, fs in os.walk(bin_dir)
        for fname in fs
        if os.path.splitext(fname)[1].lower() in _BIN_EXTS and fname not in _SKIP_FILES
    )
    print(f'[gen_index] wrote {total} entries → {out_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
