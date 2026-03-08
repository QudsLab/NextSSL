"""
script/ci/commit_parser.py
──────────────────────────
Parse a Git commit message for NextSSL CI flags.

Recognised flags (anywhere in title or body):

  --gen [<platform>]    Build target: all | windows | linux | mac | web
  --genAll              Override load mode → genAll  (--fullTest)
  --genQuick            Override load mode → genQuick (--quickTest)
  --genRelease <tag>    Implies --gen all; triggers GitHub Release
  --skipTest            Skip runner.py --test step
  --noLog               Forward --noLog to runner.py

Output: key=value lines written to stdout.
        Pipe directly to $GITHUB_OUTPUT.

Exit code 0 always.
"""

import re
import sys

_PLATFORMS = {'windows', 'linux', 'mac', 'web', 'all'}
_TAG_RE    = re.compile(r'^v\d+\.\d+')   # v1.2.3 / v1.2.3-beta / v0.1.0-alpha.1


def parse(message: str) -> dict:
    flags = {
        'gen':           False,
        'gen_platforms': 'all',
        'gen_release':   '',
        'load_mode':     'gen',
        'skip_test':     False,
        'no_log':        False,
    }
    tokens = message.split()
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == '--gen':
            flags['gen'] = True
            if i + 1 < len(tokens) and tokens[i + 1].lower() in _PLATFORMS:
                flags['gen_platforms'] = tokens[i + 1].lower()
                i += 1
        elif t == '--genRelease':
            flags['gen']           = True
            flags['gen_platforms'] = 'all'
            if i + 1 < len(tokens) and _TAG_RE.match(tokens[i + 1]):
                flags['gen_release'] = tokens[i + 1]
                i += 1
            else:
                flags['gen_release'] = 'auto'  # resolved to dev-{8hex} by guard
        elif t == '--genAll':
            flags['load_mode'] = 'genAll'
        elif t == '--genQuick':
            flags['load_mode'] = 'genQuick'
        elif t == '--skipTest':
            flags['skip_test'] = True
        elif t == '--noLog':
            flags['no_log'] = True
        i += 1
    return flags


def main() -> int:
    msg = sys.argv[1] if len(sys.argv) > 1 else ''
    f = parse(msg)
    print(f"gen={'true' if f['gen'] else 'false'}")
    print(f"gen_platforms={f['gen_platforms']}")
    print(f"gen_release={f['gen_release']}")
    print(f"load_mode={f['load_mode']}")
    print(f"skip_test={'true' if f['skip_test'] else 'false'}")
    print(f"no_log={'true' if f['no_log'] else 'false'}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
