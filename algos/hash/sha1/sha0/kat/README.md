# KAT provenance: sha0

Vectors: `c/test_sha0.c` of sphlib @ 15b6b8d8f3e4 (sha256 61e94a22105bb35b84695e10a0037e1cfe770bd1f2775ecf37f89c07862becc1), `test_sha0_internal()` calls: "abc" and the 56-byte "abcdbcdecdef..." message, i.e. the two examples of the original FIPS 180 (1993) SHA. The one-million-"a" vector in the same file (3232affa48628a26653b5aaa44541fd90d690603) is not stored here (2 MB of hex); it was checked by running sphlib once.
Expected values were extracted by script from the test file.
