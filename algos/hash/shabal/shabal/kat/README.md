# KAT provenance: shabal

Vectors are the NIST SHA-3 competition known-answer digests as embedded in the sphlib author's own unit
test (`https://github.com/pornin/sphlib` @ `15b6b8d8f3e4a43c58ba102d712fa6b8a3317035`):

- digests: `c/test_shabal.c` (sha256 3ae1e2ebae99175bd5636aad6ea37446ed7e1698dcc4cf166275aadb075061de), tables `nist_vec<bits>[]`, index = message length in bits;
- messages: `c/utest.c` table `nist_data` (sha256 2f571ee8983f69e047ed844eb6ecdbc5947bfcbf1beb9c697bc576d1ab2a88f1), function `utest_nist_data()`; this is the NIST
  ShortMsgKAT message set (each message is the prefix pattern for its bit length).
- Only byte-aligned lengths are used here (the Hash trait is byte oriented). 96 vectors in total.

The expected values were extracted by script from the test file; nothing was generated with the code under test.
