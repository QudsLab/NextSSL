# feal: port from Python

- Original URL: https://github.com/Vozec/Feal-ALL
- Original commit: 9d01773dd69205eb24c3f541455356e6802c39f0
- Original license: NOASSERTION (see LICENSE in this folder)
- Original language: Python 3
- Original file(s): FEAL/feal_nx.py + FEAL/utils.py (F2, Fk, S0, S1)
- Manifest row: 180 (collection/MANIFEST.csv)
- Algorithm: FEAL-NX with N = 32 rounds (FEAL-32X), 64-bit block, 128-bit key. Identity checked against the source (structure, tables and constants follow the specification) before porting.
- Port: `port/feal.c`, `port/feal.h`. Line-by-line translation, no redesign. Deviations forced by the language: fixed-width C integers
  and byte arrays instead of Python integers/lists, tables built or copied literally, and (HITAG2 only) the returned big integer written as bytes.
- Tier: unverified. Reachable only through `nextssl_root_*`. Only an independent review can lift it (hard rule 1).
- Differential test (2026-11-09): original Python vs this C port, Docker image `nextssl-test`, `--network none`, a disposable copy under
  D:\Dev\kat_work\port_ws (the original was never run on the host). Published vectors: 8/8 pass.
  Random inputs: 4560/4560 identical to the original, mismatches 0. The C port was built with
  `-Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover`. Harness: D:\Dev\kat_work\port_ws\diff.py.
