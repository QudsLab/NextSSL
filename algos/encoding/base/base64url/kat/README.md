# KAT provenance: base64url

- source: https://www.rfc-editor.org/rfc/rfc4648.txt (downloaded to kat_work/dl/rfc4648.txt, sha256 `84e14418f795d503be5f34bf23ce4ebaa119e9ec7c9f667d8caeb111385b178f`)
- invalid[] entries are hand-chosen rejections following RFC 4648 sections 3.3 (alphabet), 3.5 (canonical trailing bits), 4/6/7 (padding); they are ours, not from a published list.
- section 9 examples: the RFC gives the standard-alphabet text FPucA9l+ / FPucA9k= / FPucAw==; the URL-safe text is the RFC 5 alphabet substitution (+ -> -, / -> _), cross-checked with Python base64.urlsafe_b64encode.

- `vectors.json` sha256 `2336d996bb87ba3fdf13e102d26975657042ae543f90c0777c8336aa1907da1f`
