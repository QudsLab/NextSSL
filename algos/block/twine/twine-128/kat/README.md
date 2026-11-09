# Known-answer vectors (twine-128)

- `kat.json`: 10 vectors sampled from 2408 random inputs on which the original source and the C port gave identical output
  (differential test, 2026-11-09, Docker `--network none`, disposable copy). Marked NOT independent: the expected values come from the original code
  the port was translated from. Tier stays `unverified`.
- Published vectors: none: the original repository ships no vector from the designers for this variant.
- Published vectors checked in the differential run: 0/0.
