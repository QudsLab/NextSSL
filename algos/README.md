# algos/

One folder = one algorithm: `algos/<category>/<family>/<id>/`.

**How folders become code:** each algorithm is its own small crate `nextssl-algo-<id>`
(`Cargo.toml`, `glue.rs` as the lib root, optional `build.rs` + `upstream/`). The root
`Cargo.toml` picks them up with the glob member `algos/*/*/*`, and `cargo xtask gen` reads every
`algo.toml` to regenerate the registry table, the registry's dependency block, `docs/algo.generated.json`
and the C header.

- Add: create the folder (`algo.toml`, `Cargo.toml`, `glue.rs`, `kat/`, `upstream/` if C), run `cargo xtask gen`.
- Remove: delete the folder, run `cargo xtask gen`.
- Glue contract: `pub fn new(&Params) -> Result<Box<dyn Trait>>` where `Trait` is the kind trait (see `crates/nextssl-core/API.md`); validate every length. `[sizes]` and `copyleft` live in `algo.toml`.
- `cargo xtask gen --check` fails if generated files are stale (used by CI).
- Rust upstreams are pinned with `=x.y.z` in both `Cargo.toml` and `algo.toml` (xtask checks they agree).
  C upstreams are copied verbatim into `upstream/` with the commit sha and license file.
