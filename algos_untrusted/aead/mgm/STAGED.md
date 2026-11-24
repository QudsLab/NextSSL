# Staged, not wired

`mgm` 0.4.6 needs `subtle >=2, <2.5` (aead 0.4 / cipher 0.3 stack). The workspace already resolves `subtle 2.6.1` (bcrypt and others), and two 2.x versions cannot coexist, so `cargo metadata` fails with these folders under `algos/`. They are kept here as their own workspaces (`[workspace]` in each Cargo.toml), outside `cargo xtask gen`. Options: a Docker check with this older lock, or a C source for MGM (none collected). RFC 9058 vectors not replayed.

## Open (do not forget)

These two algorithms are not built, tested or shipped yet; they are not counted as done.
Committed on 2026-11-25 only so the work is not lost (it was never in git before).

To finish (owner rule: no algorithm reduction):
1. Move to the RustCrypto `mgm` release on the aead 0.5 / cipher 0.4 stack, which works with
   `subtle` 2.6, so both crates can live under `algos/aead/mgm/` in the main workspace.
2. Replay the RFC 9058 vectors (kat/*.json) and run the usual checks (KAT, ASan, symbols, licence).
3. `cargo xtask gen`, then delete this folder.
