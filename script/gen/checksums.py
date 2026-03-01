"""
script/gen/checksums.py
───────────────────────
Generate bin/{platform}/checksums.json after every build.

The JSON contains SHA-256 hashes of every compiled binary.
There are NO timestamps, NO build IDs, NO host-system data in the output.
Identical source code → identical binaries → identical checksums, always.

CI uploads bin/{platform}/checksums.json as a release artifact.
Download users verify their copy with:
    python script/gen/checksums.py --platform windows --verify

Usage
    python script/gen/checksums.py --platform windows
    python script/gen/checksums.py --platform linux
    python script/gen/checksums.py --platform mac
    python script/gen/checksums.py --platform web
    python script/gen/checksums.py --platform windows --verify
    python script/gen/checksums.py --platform windows --out path/to/custom.json
"""

import argparse
import hashlib
import json
import os
import sys

_SCHEMA_VERSION = 'checksums/v1'
_HASH_ALGO      = 'sha256'
_BIN_EXTS       = {'.dll', '.so', '.dylib', '.wasm'}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _collect(bin_dir: str) -> dict:
    """Walk bin_dir and return {relative_posix_path: sha256_hex}, sorted."""
    entries = {}
    for root, _dirs, files in os.walk(bin_dir):
        for fname in sorted(files):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _BIN_EXTS:
                continue
            full = os.path.join(root, fname)
            rel  = os.path.relpath(full, bin_dir).replace('\\', '/')
            entries[rel] = _sha256(full)
    # Sort by path for a deterministic, diffable file
    return dict(sorted(entries.items()))


def generate(bin_dir: str, out_path: str) -> int:
    """Compute checksums and write JSON.  Returns 0 on success, 1 on error."""
    if not os.path.isdir(bin_dir):
        print(f'[checksums] ERROR: bin_dir not found: {bin_dir}', file=sys.stderr)
        return 1

    files = _collect(bin_dir)
    if not files:
        print(f'[checksums] WARNING: no binaries found under {bin_dir}', file=sys.stderr)

    manifest = {
        'schema':  _SCHEMA_VERSION,
        'algo':    _HASH_ALGO,
        'files':   files,
    }

    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        # sort_keys=True and indent=2 → stable, human-readable, diffable output
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write('\n')

    print(f'[checksums] wrote {len(files)} entries → {out_path}')
    return 0


def verify(bin_dir: str, manifest_path: str) -> int:
    """Compare live file hashes against a saved manifest.  Returns 0 if all match."""
    if not os.path.isfile(manifest_path):
        print(f'[checksums] ERROR: manifest not found: {manifest_path}', file=sys.stderr)
        return 1

    with open(manifest_path, 'r', encoding='utf-8') as f:
        manifest = json.load(f)

    expected = manifest.get('files', {})
    algo     = manifest.get('algo', _HASH_ALGO)
    if algo != _HASH_ALGO:
        print(f'[checksums] ERROR: unsupported hash algo in manifest: {algo}', file=sys.stderr)
        return 1

    actual  = _collect(bin_dir)
    ok      = True
    missing = sorted(set(expected) - set(actual))
    extra   = sorted(set(actual)   - set(expected))

    for path in missing:
        print(f'[MISSING]  {path}')
        ok = False

    for path in extra:
        print(f'[EXTRA]    {path}')

    for path in sorted(set(expected) & set(actual)):
        if expected[path] != actual[path]:
            print(f'[MISMATCH] {path}')
            print(f'           expected: {expected[path]}')
            print(f'           actual:   {actual[path]}')
            ok = False
        else:
            print(f'[OK]       {path}')

    if ok:
        print(f'\n[checksums] all {len(expected)} files verified OK')
    else:
        print(f'\n[checksums] VERIFICATION FAILED')
    return 0 if ok else 1


def _resolve_paths(args) -> tuple:
    """Return (bin_dir, out_path) from parsed args."""
    project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..'))
    bin_dir  = os.path.join(project_root, 'bin', args.platform)
    out_path = args.out or os.path.join(bin_dir, 'checksums.json')
    return bin_dir, out_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Generate or verify bin/{platform}/checksums.json')
    parser.add_argument('--platform', required=True,
                        choices=['windows', 'linux', 'mac', 'web'],
                        help='Target platform (selects bin/{platform}/)')
    parser.add_argument('--verify', action='store_true',
                        help='Verify existing checksums.json instead of regenerating')
    parser.add_argument('--out', metavar='PATH',
                        help='Override output/input JSON path')
    args = parser.parse_args()

    bin_dir, out_path = _resolve_paths(args)

    if args.verify:
        return verify(bin_dir, out_path)
    return generate(bin_dir, out_path)


if __name__ == '__main__':
    sys.exit(main())
