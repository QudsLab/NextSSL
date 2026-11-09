# ml-dsa-65

Scaffolded by `cargo xtask new`; nothing has been imported yet.

- Upstream: Rust crate `ml-dsa` =0.1.2
- Status: `importing` (the glue stub returns `Error::Unimplemented`)

## To finish the import

1. Confirm the upstream license and put the real SPDX id in `algo.toml` (`upstream.license`).
2. Set `tier`, `standards`, `aliases`, `params` and the `[sizes]` the kind requires in `algo.toml` (owner decides the tier).
3. Write the adapter in `glue.rs` using the pinned crate (replace the `Error::Unimplemented` stub).
4. Add KAT vectors under `kat/` and list them in `[kat] files`.
5. Run `cargo xtask gen`, then the Docker suite (`NEXTSSL_ALL=1`).
