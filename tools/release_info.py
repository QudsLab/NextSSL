#!/usr/bin/env python3
"""Release values for the CI release jobs (release.toml and Cargo.toml).

    python3 tools/release_info.py --check   exit 1 when release.toml or the Cargo.toml version is invalid (guard)
    python3 tools/release_info.py <key>     print one value:
        version   Cargo.toml [workspace.package] version, e.g. 0.0.1
        tag       v<version>
        stage     pre-release | release
        label     text for the release title (may be empty)
        note      free text for the release notes
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
    if cfg.get('stage') not in STAGES:
        sys.exit(f'release.toml: stage must be one of {STAGES}, got {cfg.get("stage")!r}')
    for k in ('label', 'note'):
        if not isinstance(cfg.get(k, ''), str):
            sys.exit(f'release.toml: {k} must be a string')
    with open(os.path.join(ROOT, 'Cargo.toml'), 'rb') as f:
        ws = tomllib.load(f).get('workspace', {}).get('package', {})
    version = ws.get('version')
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        sys.exit(f'Cargo.toml [workspace.package] version must be X.Y.Z, got {version!r}')
    return version, cfg


def main():
    args = sys.argv[1:]
    version, cfg = load()
    if args == ['--check']:
        print(f'release info ok: version {version}, stage {cfg["stage"]}, label {cfg.get("label", "")!r}')
        return
    if len(args) != 1:
        sys.exit(__doc__)
    key = args[0]
    if key == 'version':
        print(version)
    elif key == 'tag':
        print(f'v{version}')
    elif key in ('stage', 'label', 'note'):
        print(cfg.get(key, ''))
    else:
        sys.exit(f'unknown key {key!r}')


if __name__ == '__main__':
    main()
