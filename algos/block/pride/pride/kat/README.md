# Known-answer vectors (pride)

- `kat.json`: 10 vectors sampled from 3120 random inputs on which the original source and the C port gave identical output
  (differential test, 2026-11-09, Docker `--network none`, disposable copy). Marked NOT independent: the expected values come from the original code
  the port was translated from. Tier stays `unverified`.
- Published vectors: `published.json` (5 vector(s)): pypride.py doctest (author lists them as PRIDE test vectors, https://eprint.iacr.org/2014/453.pdf); replayed against original and port.
- Published vectors checked in the differential run: 15/15.
