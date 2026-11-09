# Patches

None. The files in this directory are byte-identical to the upstream commit named in
`../algo.toml`. Exported symbols are renamed with `-D` defines in `../build.rs`
(prefix `nextssl__siphash_2_4__`), not by editing the sources.

Round counts are set with `-DcROUNDS=2 -DdROUNDS=4` in build.rs (upstream configuration macros).
Upstream licence file used: LICENSE_CC0 (the repo also offers MIT / A2LLVM variants), stored as LICENSE.
