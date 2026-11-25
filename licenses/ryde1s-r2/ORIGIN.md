# ORIGIN: ryde1s-r2

- package: RYDE round 2 ryde1s
- source URL: https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/submission-pkg/ryde-submission-round2.zip
- file: ryde-submission-round2.zip
- sha256: c40b9b01b3882a7da83a439a4c251a7dab67cd97c46d71f2b27b2af9978f02a9
- subtree: ryde/Reference_Implementation
- parameter set directory: ryde1s/src
- copied verbatim (whole subtree incl. shared include dirs) by wire batch 10
- license: NOASSERTION

## Support files restored (fix156)

The wire-10 copy dropped files of lib/XKCP. Restored verbatim from the same zip (sha256 c40b9b01...02a9),
subtree ryde/Reference_Implementation/ryde1s/lib/XKCP/ (opt64/ permutation + times4-on1, brg_endian.h, macros, Makefile, CMakeLists.txt). Nothing edited.
build.rs compiles opt64/KeccakP-1600-opt64.c and opt64/KeccakP-1600-times4-on1.c and adds lib/XKCP/opt64 to the include path, as upstream's CMakeLists does for the portable (non-avx) build.
