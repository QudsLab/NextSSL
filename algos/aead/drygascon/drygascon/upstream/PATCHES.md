# Patches

None. The files in this directory are byte-identical to the upstream named in
`../algo.toml`. Exported symbols are renamed with `-D` defines in `../build.rs`
(prefix `nextssl__drygascon__`), not by editing the sources.

MSVC build: the C is compiled with clang-cl (see `../build.rs`), which keeps the upstream's
`__attribute__((aligned(16)))` on the sponge state; the upstream refuses an unaligned state. No source edit.
