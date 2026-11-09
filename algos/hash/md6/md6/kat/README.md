# KAT provenance: md6 (UNVERIFIED)

Only two vectors, taken from the doc examples of md6-rs `src/lib.rs` @ 02588c18df9f86f83169f51d4c1eab1217d62712 (sha256 1c7be7e430f5fcbb9e1cb1bc9230533206f115e33c3dccfc6d379c011875eb0b): MD6-256 of
"The lazy fox jumps over the lazy dog" and MD6-512 of "Zażółć gęślą jaźń". They come from the same C code
that is tested here, so they only guard against regressions and wrong parameter plumbing (d = 8 * out_len),
not against an error in the code. The official MD6 KATs (NIST submission package) could not be fetched
(official site 404). Tier is therefore `unverified`: reachable through root only.
