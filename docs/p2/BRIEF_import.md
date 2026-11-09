# P2 import brief (sonnet)

Read first: CLAUDE.md (hard rules), crates/nextssl-core/API.md, and two finished examples:
algos/hash/sha2/sha256 (crate upstream) and algos/hash/blake2/blake2b-512 (C upstream + build.rs).

For each row assigned to you (from docs/p2/sources_*.csv):
1. VERIFY the source first: crate exists at that exact version on crates.io (or the commit exists), the license
   matches, and the crate/file really implements that exact variant. If it fails, fix the row (better upstream) or
   mark it blocked; never guess.
2. `cargo xtask new <proposed_path> --kind <Kind> --upstream-crate name=ver` (or `--upstream-c repo@commit`), then
   fill algo.toml (tier: safe/standard/legacy/broken/research honestly; broken for MD4/MD5/SHA-0/SHA-1-collision class,
   legacy for old-but-unbroken), glue.rs (adapter only, zero crypto logic), and KATs.
3. KATs come from the official spec/RFC/NIST CAVP/authors' test vectors (cite the source in kat/README or algo.toml).
   Never generate expected outputs with the same upstream you are testing. Wycheproof where it exists.
4. C upstream: copy only the needed files verbatim into upstream/ with LICENSE, prefix every exported symbol
   (see blake2b-512 build.rs EXPORTED), no edits other than symbol-renaming patches recorded in upstream/PATCHES.md.
5. Copyleft (GPL/LGPL/AGPL) -> behind the `copyleft` cargo feature. No-license sources -> blocked, do not copy.
6. Owner rule: do NOT test after each algorithm. Import all assigned rows first, then run the full gate once at the end and fix failures.
   Never leave a half-made algo folder in the workspace (it breaks the whole workspace); delete it if you give up.

At the end (all must pass, paste exact output tails):
`cargo xtask gen --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`,
`cargo run -p xtask -- symbols` if C was added (or the symbol check command the xtask exposes).
Append your results to docs/p2/STATUS.md: one line per row `num | path | active|blocked | reason/KAT source`.
Do not commit. Do not touch files outside your algo folders, Cargo.lock, generated files, and docs/p2/STATUS.md.
Report: imported count, blocked list with reasons, anything that needs an owner decision.

Extra rules (from batch 1 review):
- Never type KAT vectors from memory. Download the published file (RFC text, NIST CAVP/ACVP zip, authors' page) and
  record its URL + sha256 in kat/README.md.
- Prefer raw NIST CAVP/ACVP vectors over vectors regenerated with hashlib/OpenSSL when NIST publishes them.
- Scratch work goes in D:\Dev\kat_work (outside the repo).

Owner rules on sourcing (2026-11-08):
- If the standard places (crates.io, PQClean, liboqs, authors' repo) have nothing, search wider (web search,
  GitHub code search, papers' artifact links, SUPERCOP, mailing-list archives) and find the actual code.
- Not found anywhere -> do not add; record `blocked: no source found` in STATUS.md.
- Found but not fully proven (no independent KAT, unclear provenance, single unofficial mirror) -> import with
  tier `unverified`. It is reachable only through root; record why in algo.toml `notes`.
- C++ source: copy verbatim, build with `cc` (`.cpp(true)`).
- Only Java/Go/Python/other source exists: port line by line to C in upstream/port/, tier `unverified`,
  upstream/ORIGIN.md with original URL+commit+license, differential test vs the original run in Docker
  (published KATs + >=1000 random inputs). Ports are done in the last batch, not mixed into normal batches.
- At the end of your batch, append a short entry to docs/PROGRESS.md (the site builder reads it): what was imported,
  blocked, verified numbers. Keep the existing format.
- Official source that is only a zip/tarball (NIST round packages, SUPERCOP, eSTREAM): allowed. Pin as
  `<download-url>#sha256=<hex>` in algo.toml, keep the zip's sha256 + download date in upstream/ORIGIN.md.
- libsignal is Rust (AGPL-3.0): import as a crate behind the `copyleft` feature, not as a port.
- The gate must pass on the Windows MSVC host too (cargo test --workspace on the host), not only in Docker.
  Windows is a required platform.
