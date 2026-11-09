# Known-answer vectors (feal)

- `kat.json`: 10 vectors sampled from 4560 random inputs on which the original source and the C port gave identical output
  (differential test, 2026-11-09, Docker `--network none`, disposable copy). Marked NOT independent: the expected values come from the original code
  the port was translated from. Tier stays `unverified`.
- Published vectors: `published.json` (1 vector(s)): test.py of the original repository: FEAL-NX spec (NTT, call-3e.pdf) example, 32 rounds.
- Published vectors checked in the differential run: 8/8.
