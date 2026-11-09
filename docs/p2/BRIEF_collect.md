# Collection brief (owner: collect first, test and wire later)

Goal: get the source of every remaining algorithm onto disk and listed, fast and cheap. No tests, no KATs, no glue, no
builds, no deep review. Do not touch `algos/`, `crates/`, `xtask/` or `Cargo.*`.

Output, under `collection/` (outside the Cargo workspace):
- `collection/<category>/<family>/<id>/upstream/`: verbatim source files plus the LICENSE.
- `collection/<category>/<family>/<id>/ORIGIN.md`: URL, commit or sha256, SPDX license, language, download date.
- `collection/MANIFEST.csv`: `num,algorithm,proposed_path,upstream_type,upstream,license,language,state,notes`.
  state = `collected` | `crate-pinned` | `link-only` | `not-found`.

Method: write ONE script that reads the CSVs and does the work. Do not process rows by hand. Keep clones in
`D:\Dev\kat_work\clones`, one per repo. Copy only the directories an algorithm needs.

Rules:
- Include first, the owner decides later. Do not drop an algorithm because it is old, obscure, large (no 15-file limit
  here), C++, Java, Go or Python, or because it would not build on MSVC. Record language in the manifest.
- Crate upstream: no vendoring, one manifest row with the exact version, state `crate-pinned`.
- No license found: do not copy the code. Record URL and commit, state `link-only`, notes "no license".
- Copyleft (GPL/LGPL/AGPL): collect it, and put the SPDX id in the manifest.
- Never invent URLs, versions or commits. Use only what the CSVs give or what you fetched.
- If you notice an upstream bug in passing, add a row to `docs/UPSTREAM_ISSUES.md`. Do not investigate it.
- Do not commit. Keep the final report under 15 lines: counts by state and the not-found list.
