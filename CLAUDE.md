# CLAUDE.md — NextSSL

NextSSL aims to be the largest open, programmable cryptographic algorithm library: 776+ algorithms, PQC first, any language, any platform.
`REBUILD_PLAN.md` is the architecture. Read it before changing structure.

## Communication

- Talk to the owner in **Bangla**. Code, comments, commits, docs, and investigation notes are in **English**.
- Ask before decisions that are the owner's (license, scope, public claims). Give a recommendation, not a survey.

## Hard rules (crypto safety)

1. **Never hand-write a cryptographic primitive.** Copy verbatim from the upstream named in `algo.toml` (C or Rust), pinned to a commit, with its LICENSE kept in `upstream/`. Only `glue.rs`, `build.rs`, patches for symbol renaming, and tooling are ours.
   - C++ upstreams are used verbatim too (built with `cc` in C++ mode).
   - **Port exception (owner decision 2026-11-08):** when the only trustworthy source is in another language (Java, Go, Python, ...), it may be ported line by line to C. A port is always tier `unverified` (root only), keeps the original's license and URL+commit in `upstream/ORIGIN.md`, and must pass a differential test against the original (run in Docker) over published KATs plus random inputs. Only an independent review can lift it out of `unverified`.
2. **Rust is the safe shell.** All untrusted input (parsers, envelopes, params, lengths) is handled in Rust. `unsafe` is allowed only in `nextssl-ffi` and in per-algo C wrappers, and each block needs a `// SAFETY:` note plus Miri and fuzz coverage.
3. **Record every license, block none.** Put the SPDX id in `algo.toml`. GPL/LGPL algorithms go behind the `copyleft` cargo feature. The owner decides license policy later.
4. **Scope: everything deeply crypto-related.** See `scope_classification.csv`. KEEP = core algorithms. KEEP-PROTOCOL = protocols and PKI structures (later phase). KEEP-PLATFORM = OS RNG, CPU, HSM and TEE interfaces. DROP = only non-crypto items and other products' plumbing.
5. **No silent behaviour.** Validate every length and parameter and return an explicit error. Never ignore `key_len`, never truncate input, never fall back to another algorithm.
6. **One source of truth.** Edit `algo.toml`, then run `tools/gen`. Never hand-edit generated tables, cargo feature lists, `algo.json`, or docs.
7. **Tiers.** Only `safe`/`standard` algorithms are reachable from the safe API. `legacy`/`broken`/`research`/`unverified` algorithms go through `nextssl_root_*` only. `unverified` = source found but not fully proven.
8. **An algorithm is "done" only when** its KATs pass, sanitizer builds are clean, the symbol check passes (all exports `nextssl_`, upstream symbols prefixed), and the license file is present.
9. Secrets are zeroized on every exit path. Secret-dependent code runs under the constant-time checks.
10. Never claim "FIPS validated", or use NIST/CMVP logos, without a certificate. "Tested against NIST ACVP vectors" is the allowed claim.
11. The old C implementation was removed. It lives only in git history (commit `e526243`) and has known bugs, so never copy from it. Upstream source lists are in `docs/reference/`.

## Delegation (cost + accuracy)

Use the `nextssl-delegate` skill (`.claude/skills/nextssl-delegate/SKILL.md`). In short:

- **haiku:** find, list, run builds and tests in Docker, bug-hunt sweeps, mechanical edits from an exact pattern.
- **sonnet:** verify every haiku finding with evidence; import one algorithm per agent; bindings; tests.
- **opus (main session):** architecture, security boundaries, RNG/keys/constant-time, license decisions, release signing, and final review. Re-run the tests yourself. A subagent report is a claim, not proof.
- Parallel writers never touch the same files; use worktree isolation when they might.
- If a model fails the same piece twice, escalate one tier.

## Testing

- Everything runs in Docker on the owner's machine (Windows 11 + Docker Desktop), and the same images run in CI.
- Test layers: KAT, ACVP, Wycheproof, differential vs OpenSSL/PyCA/liboqs/libsodium, fuzzing, ASan/UBSan/MSan, dudect/ctgrind, QEMU cross-arch, WASM, and per-binding KAT runs. See REBUILD_PLAN.md §9.
- Report test results exactly. A skipped layer must be named.

## Git

- The remake happens directly on `main` (owner's decision). Commit only when the owner asks.
