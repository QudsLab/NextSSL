# Wire brief: turn collection/ rows into registered algorithms, cheaply

Owner: add all you can. Follow BRIEF_import.md for crypto rules, with these overrides.
Input: rows of `collection/MANIFEST.csv` in your batch, state `collected` or `crate-pinned`. Source files are already in
`collection/<path>/upstream/`.

Cost rules:
- Write ONE generator script per upstream family (PQClean, liboqs, NIST package, SUPERCOP, RustCrypto kind) in
  `D:\Dev\kat_work\wire`. It emits algo.toml, Cargo.toml, build.rs, shim and glue from a template. Do not hand-write folders.
- No interim builds. One gate at the end: `cargo xtask gen --check`, `cargo check --workspace`, and the registry KAT
  test only (`cargo test -p nextssl-registry`). No clippy, Docker or per-crate runs unless the check fails. Name what you skipped.
- Report under 15 lines.

Include first:
- No 15-file limit. A source needing a huge dependency tree: try once, then mark and move on.
- Fails on MSVC without editing algorithm code: gate that algo with `cfg(not(target_env = "msvc"))` and note it, do not drop it.
- Tier: `unverified` unless a published KAT independent of the copied code passes. A submission's own KAT files count as
  the designers' vectors: tier `research` for non-standard schemes when they pass.
- Secrets, lengths and params: glue still validates everything (hard rules 2, 5). Glue never contains crypto logic.
- Do not copy a row whose license is unknown. GPL family goes behind `copyleft`.
- A row that fails: delete its folder, write the reason in `docs/p2/STATUS.md`, continue. Never leave a broken folder.
- Do not commit. Append one entry to `docs/PROGRESS.md`.

Owner order, overrides every gate above: do NOT compile or test any batch. No cargo check, build or test. Generate, run only `cargo xtask gen`, mark rows `untested` in STATUS.md. One compile-and-fix pass happens after all batches.

Owner decision: this is an archive, so license does not block anything. Copy code with no license too, record license NOASSERTION. Still record every license found, and GPL family still goes behind `copyleft`.
