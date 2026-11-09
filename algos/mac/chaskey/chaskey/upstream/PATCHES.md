# Patches

None. The files in this directory are byte-identical to the upstream commit named in
`../algo.toml`. Exported symbols are renamed with `-D` defines in `../build.rs`
(prefix `nextssl__chaskey__`), not by editing the sources.

Origin: single file from the author's site, see ORIGIN.md. The licence file stored here is the CC0 dedication header of chaskey12.c itself.
`main` is renamed by a -D define so the archive defines no `main` symbol.
