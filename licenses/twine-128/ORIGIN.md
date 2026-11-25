# twine-128: port from Python

- Original URL: https://github.com/amoallim15/xtwine
- Original commit: fa1e0706ef92afc2ef3031c16e16c3b6232cb5b3
- Original license: MIT (see LICENSE in this folder)
- Original language: Python 3
- Original file(s): src/algo.py (_key_schedule_128, _encrypt, _decrypt)
- Manifest row: 184 (collection/MANIFEST.csv)
- Algorithm: TWINE-128 (SAC 2012), 64-bit block, 128-bit key, 36 rounds. Identity checked against the source (structure, tables and constants follow the specification) before porting.
- Port: `port/twine.c`, `port/twine.h`. Line-by-line translation, no redesign. Deviations forced by the language: fixed-width C integers
  and byte arrays instead of Python integers/lists, tables built or copied literally, and (HITAG2 only) the returned big integer written as bytes.
- Tier: unverified. Reachable only through `nextssl_root_*`. Only an independent review can lift it (hard rule 1).
- Differential test (2026-11-09): original Python vs this C port, Docker image `nextssl-test`, `--network none`, a disposable copy under
  D:\Dev\kat_work\port_ws (the original was never run on the host). Published vectors: 0/0 pass.
  Random inputs: 2408/2408 identical to the original, mismatches 0. The C port was built with
  `-Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover`. Harness: D:\Dev\kat_work\port_ws\diff.py.
