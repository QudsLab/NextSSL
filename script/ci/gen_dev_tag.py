"""
script/ci/gen_dev_tag.py
────────────────────────
Compute a deterministic dev release tag from the MD5 of all files
under src/ (sorted by relative path, content included in hash).

Output:  dev-{first 8 hex digits}   e.g.  dev-a3f7c912
Exit code 0 on success, 1 if src-dir does not exist.
"""

import argparse
import hashlib
import os
import sys


def md5_of_dir(src_dir: str) -> str:
    h = hashlib.md5()
    for root, dirs, files in os.walk(src_dir):
        dirs.sort()                          # deterministic traversal
        for name in sorted(files):
            abs_path = os.path.join(root, name)
            rel_path = os.path.relpath(abs_path, src_dir).replace('\\', '/')
            h.update(rel_path.encode())      # path contributes to hash
            with open(abs_path, 'rb') as f:
                h.update(f.read())           # content contributes to hash
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--src-dir', default='src',
                    help='Directory to hash (default: src)')
    args = ap.parse_args()
    if not os.path.isdir(args.src_dir):
        print(f'error: {args.src_dir!r} is not a directory', file=sys.stderr)
        return 1
    print(f'dev-{md5_of_dir(args.src_dir)[:8]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
