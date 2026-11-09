# KAT provenance: yescrypt

Expected values: `TESTS-OK` of openwall/yescrypt @ 86ea42c29d616b1376307b50f40dc56d57d909fe (sha256 66ccbc3b8ef15981579ec9993336aff09d5c55288df4261ff66855aa9b541e33), the author's reference output of `tests.c` `print_yescrypt()`. Rows used: flags = 182 (= YESCRYPT_DEFAULTS), g = 0, output length >= 16 bytes (N is a power of two; ln = log2 N). Rows with flags 0 / 1 (scrypt-compatible / WORM mode) and g != 0 (hash upgrade) are not exposed by this adapter.
