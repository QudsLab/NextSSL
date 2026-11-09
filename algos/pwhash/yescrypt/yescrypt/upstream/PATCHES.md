# Patches

None. The files in this directory are byte-identical to the upstream commit named in
`../algo.toml`. Exported symbols are renamed with `-D` defines in `../build.rs`
(prefix `nextssl__yescrypt__`), not by editing the sources.

LICENSE is not an upstream file: the repository has no licence file, so the licence notice that heads every source file (yescrypt-common.c lines 1-17) is stored verbatim here.
Only the portable reference core yescrypt-ref.c is built (not the SSE2 yescrypt-opt.c, not yescrypt-platform.c / mmap).
