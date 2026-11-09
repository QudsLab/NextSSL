# Origin

Reference implementation of MD6 by Ronald L. Rivest (MIT licence, NIST SHA-3 submission, 2008-10-27), as repackaged
by nabijaczleweli in https://github.com/nabijaczleweli/md6-rs (v2.0.3, commit 02588c18df9f86f83169f51d4c1eab1217d62712, MIT).
Files md6.h, md6_compress.c, md6_mode.c are Rivest's; md6_compression_hook.c is a split-out of one
definition from md6.h by the repackager (Clang linking fix, see header). The official site
(groups.csail.mit.edu/cis/md6) returns 404, so no first-party copy could be fetched; the crates.io package
md6 2.0.3 carries the same files (identical apart from line endings).
