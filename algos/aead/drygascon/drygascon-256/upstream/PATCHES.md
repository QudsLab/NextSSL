# Patches

None. The files in this directory are byte-identical to the upstream named in
`../algo.toml`. Exported symbols are renamed with `-D` defines in `../build.rs`
(prefix `nextssl__drygascon_256__`), not by editing the sources.

MSVC build: on cl.exe build.rs force-includes `../msvc_compat.h`-style file `msvc_compat.h` (our file, outside upstream/) that defines `__attribute__(x)` as empty; the upstream only uses it for `aligned(16)` on a union. No source edit.
