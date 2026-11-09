# Patches

None. The files in this directory are byte-identical to the upstream commit named in
`../algo.toml`. Exported symbols are renamed with `-D` defines in `../build.rs`
(prefix `nextssl__md6__`), not by editing the sources.

inttypes.h / stdint.h (msinttypes shims shipped next to md6.h) are intentionally not copied: modern MSVC has its own <inttypes.h>, and the shim would shadow <stdint.h> under gcc/clang.
See ORIGIN.md for provenance.
