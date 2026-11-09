# KAT provenance: xxhash32

Expected values: the xxHash author's sanity table `XSUM_XXH32_testdata` in `cli/xsum_sanity_check.c` @ 2ec67caeb18ec15ae60c0853174331089acddfc0 (sha256 9b310671a905988e1e8ed74202362ea2daf033bfc5ad3d62090b172c898ed4fc), seed-0 rows only. Inputs: the prefix of the author's pseudo-random test buffer (`XSUM_fillTestBuffer`: byteGen = PRIME32; byte = byteGen>>56; byteGen *= PRIME64), regenerated in Python. Values are the output as a big-endian integer.
