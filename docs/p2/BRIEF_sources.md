# P2 source-mapping brief (haiku)

Goal: for every KEEP row of your categories in `scope_classification.csv`, propose ONE trustworthy upstream
we can copy verbatim (we never hand-write crypto). You only research and write one CSV. Do not touch any other file.

Output: `docs/p2/sources_<GROUP>.csv` with header
`num,algorithm,category,proposed_path,kind,upstream_type,upstream,license,evidence_url,confidence,notes`

- proposed_path: `<category>/<family>/<id>` lowercase kebab, matching the existing style under `algos/`
  (e.g. `hash/sha2/sha512`, `aead/aes-gcm/aes-128-gcm`, `sign/slh-dsa/slh-dsa-sha2-128s`). One row per concrete
  parameter set when the catalog name implies several (e.g. "SHA-2" -> sha224,sha256,sha384,sha512,sha512-256 rows,
  reuse the same num).
- kind: one of Hash, Xof, Checksum, Encoding, Mac, Kdf, PwHash, Aead, BlockCipher, StreamCipher, Mode, Kem, Kex,
  Sign, EntropySource, Drbg. If none fits, write `none` and explain in notes.
- upstream_type: `crate` | `c` | `none`.
- upstream: crate -> `name=exact.version` (latest stable non-yanked, from `curl -s https://crates.io/api/v1/crates/<name>`);
  c -> `https://github.com/org/repo@<40-hex commit>` (from `curl -s https://api.github.com/repos/org/repo/commits/<branch>`).
- Preference order: RustCrypto / dalek / libcrux / other widely used crates (>100k downloads) > PQClean, liboqs,
  libsodium, authors' reference C > anything else. Never propose a crate with < 10k downloads unless it is the
  authors' own; say so in notes. `docs/reference/` lists known upstream repos.
- license: SPDX id from crates.io / the repo LICENSE.
- evidence_url: the crates.io or GitHub URL you actually fetched.
- confidence: high (fetched + name clearly matches) | medium | low.
- If no trustworthy upstream exists: upstream_type `none` and the reason in notes.
- Never invent versions or commits. If a fetch fails, write confidence low and say why.
Finish by printing: rows written, counts by upstream_type, and the list of `none` rows.
