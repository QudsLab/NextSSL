# ORIGIN: qruov-5q31l3aes

- repository: https://github.com/open-quantum-safe/liboqs
- commit: 7bf154f197696f5bf04be2ea4c576db86bb6a238
- license: 0BSD
- copied verbatim from the pinned clone (files reachable from the build sources; liboqs common code only where the scheme needs it)
- liboqs common code (common.c, aes, sha2, sha3/XKCP plain) copied for the scheme's own hashing/AES needs; OQS_randombytes is provided by shim.c
