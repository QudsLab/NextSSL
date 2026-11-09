# Patches

None. The files in this directory are byte-identical to the upstream commit named in
`../algo.toml`. Exported symbols are renamed with `-D` defines in `../build.rs`
(prefix `nextssl__xxhash32__`), not by editing the sources.

The whole API is namespaced with `-DXXH_NAMESPACE=nextssl__xxhash32__` (upstream feature); `XXH_NO_STREAM` drops the streaming API (no allocation).
