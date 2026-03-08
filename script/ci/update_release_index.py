"""
script/ci/update_release_index.py
──────────────────────────────────
Append or update a tag entry in bin/releases/index.json.

Structure of index.json:
{
  "latest": "v0.2.0-beta",
  "versions": {
    "v0.2.0-beta": {
      "tag":         "v0.2.0-beta",
      "date":        "2026-03-07",
      "bins_url":    "https://raw.githubusercontent.com/.../bin/releases/v0.2.0-beta.json",
      "release_url": "https://github.com/.../releases/tag/v0.2.0-beta"
    }
  }
}
"""

import argparse
import json
import os
import sys
from datetime import date

RAW_BASE = 'https://raw.githubusercontent.com/{repo}/main'
GH_BASE  = 'https://github.com/{repo}'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--tag',   required=True)
    ap.add_argument('--index', required=True)
    ap.add_argument('--repo',  required=True)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.index)), exist_ok=True)

    if os.path.exists(args.index):
        with open(args.index, encoding='utf-8') as f:
            idx = json.load(f)
    else:
        idx = {'latest': '', 'versions': {}}

    raw_base = RAW_BASE.format(repo=args.repo)
    gh_base  = GH_BASE.format(repo=args.repo)

    idx['latest'] = args.tag
    idx['versions'][args.tag] = {
        'tag':         args.tag,
        'date':        str(date.today()),
        'bins_url':    f'{raw_base}/bin/releases/{args.tag}.json',
        'release_url': f'{gh_base}/releases/tag/{args.tag}',
    }

    with open(args.index, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(idx, f, indent=2, sort_keys=True)
        f.write('\n')

    print(f'[release-index] updated {args.index} → {args.tag}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
