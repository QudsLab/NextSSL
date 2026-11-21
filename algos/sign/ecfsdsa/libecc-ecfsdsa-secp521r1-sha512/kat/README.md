# KAT provenance: libecc-ecfsdsa-secp521r1-sha512

- Source: libecc `src/tests/ec_self_tests_core.h` at 059972c47c0c37b3a2557961210073b18d324ce6: private scalar, message and expected signature are the published self-test vector.
- The registry verify-only format needs a public key, which libecc's table does not list: `pk_hex` was derived by libecc itself (`keygen_from_seed` on the published private scalar, printed by the crate test as KATPK).
  Weaker than an independent vector, but the signature is the published one. Signing is not replayed (libecc fixes the nonce in its tests; nonce injection is not part of the Sign API).
- upstream: https://github.com/ANSSI-FR/libecc @ 059972c47c0c37b3a2557961210073b18d324ce6
