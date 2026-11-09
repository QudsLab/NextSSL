# Patches

Source files are verbatim. Only the manifest differs: `Cargo.toml.orig` is the original; `Cargo.toml` drops dev-dependencies,
bench/example/test targets, [workspace] and [profile] tables and turns off target auto-discovery, so the crate resolves as a
path dependency of the nextssl workspace. Directories not copied: .cargo, .git, .github, benches, book, docs, examples, extra, fuzz, scripts, target, tests.

Manifest also carries `[lints.clippy] all = "allow"` so `cargo clippy -D warnings` reports only NextSSL-owned code.
