#!/usr/bin/env python3
"""Read release.toml (version base and its stage) for the CI release jobs.

    python3 tools/release_info.py --check        exit 1 when release.toml is invalid or its base differs from
                                                 the major.minor of Cargo.toml (CI guard)
    python3 tools/release_info.py <key> [sha]    print one value:
        version   <base>.<GITHUB_RUN_NUMBER> (run number 0 outside CI)
        stage     pre-release | release
        note      free text for the release notes
        tag       v<version>+<first 7 chars of sha>
"""
import os
import re
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAGES = ('pre-release', 'release')


def load():
    with open(os.path.join(ROOT, 'release.toml'), 'rb') as f:
        cfg = tomllib.load(f)
    base = cfg.get('base')
    if not isinstance(base, str) or not re.fullmatch(r'\d+\.\d+', base):
        sys.exit(f'release.toml: base must be X.Y, got {base!r}')
    entry = cfg.get('bases', {}).get(base)
    if not isinstance(entry, dict):
        sys.exit(f'release.toml: no [bases."{base}"] entry')
    if entry.get('stage') not in STAGES:
        sys.exit(f'release.toml: bases."{base}".stage must be one of {STAGES}, got {entry.get("stage")!r}')
    with open(os.path.join(ROOT, 'Cargo.toml'), encoding='utf-8') as f:
        m = re.search(r'^\[workspace\.package\]\s*\nversion\s*=\s*"(\d+\.\d+)\.\d+"', f.read(), re.M)
    if not m or m.group(1) != base:
        sys.exit(f'release.toml base {base} differs from the major.minor of Cargo.toml [workspace.package] '
                 f'version ({m.group(1) if m else "missing"})')
    return base, entry


def main():
    args = sys.argv[1:]
    base, entry = load()
    run = os.environ.get('GITHUB_RUN_NUMBER', '0')
    if not run.isdigit():
        sys.exit(f'GITHUB_RUN_NUMBER is not a number: {run!r}')
    version = f'{base}.{int(run)}'
    if args == ['--check']:
        print(f'release.toml ok: base {base}, stage {entry["stage"]}')
        return
    if not args:
        sys.exit(__doc__)
    key = args[0]
    if key == 'version':
        print(version)
    elif key in ('stage', 'note'):
        print(entry.get(key, ''))
    elif key == 'tag':
        if len(args) != 2 or not re.fullmatch(r'[0-9a-f]{7,40}', args[1]):
            sys.exit('tag needs the commit sha')
        print(f'v{version}+{args[1][:7]}')
    else:
        sys.exit(f'unknown key {key!r}')


if __name__ == '__main__':
    main()
