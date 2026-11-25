# ORIGIN: mayo-2-r2

- package: MAYO round 2 mayo_2
- source URL: https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/submission-pkg/mayo-submission-round2.tar.gz
- file: mayo-submission-round2.tar.gz
- sha256: 6f7e0680716ace69b06dd2dcff39ba0bce998229546b63ed6ab579a325159333
- subtree: MAYO/Reference_Implementation
- parameter set directory: src/mayo_2
- copied verbatim (whole subtree incl. shared include dirs) by wire batch 10
- license: NOASSERTION

## Support files restored (fix156)

The wire-10 copy dropped files of src/generic/ (echelon_form.h, ef_inner_loop.h). Restored verbatim from the same archive (mayo-submission-round2.tar.gz, sha256 6f7e0680...9333),
subtree MAYO/Reference_Implementation/src/generic/. Nothing edited. build.rs adds upstream/src/generic to the include path, as upstream's CMake does for the portable build.

## Export names (fix156)

upstream's api.h namespaces the NIST API as pqmayo_MAYO_2_ref_crypto_sign_*. build.rs' rename header maps that namespace to the plain crypto_sign_* name before adding the nextssl__ prefix, so the glue's link names resolve. No upstream file edited.

## AES sources (fix156)

src/common/aes_c.c and aes128ctr.c (portable AES-128-CTR, as upstream's CMake lists in SOURCE_FILES_COMMON_SYS) were dropped by the wire-10 copy; restored verbatim from the same archive
(mayo-submission-round2.tar.gz, sha256 6f7e0680...9333, MAYO/Reference_Implementation/src/common/) and added to SOURCES. aes_neon.c and the randombytes_* files are not used (randombytes comes from shim.c).
