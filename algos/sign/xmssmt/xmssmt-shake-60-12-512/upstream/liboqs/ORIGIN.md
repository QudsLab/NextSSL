# ORIGIN: liboqs common code used by xmssmt-shake-60-12-512

- repository: https://github.com/open-quantum-safe/liboqs
- commit: 7bf154f197696f5bf04be2ea4c576db86bb6a238
- license: MIT
- files copied verbatim: src/common/common.c, src/common/common.h, src/common/ossl_functions.h, src/common/ossl_helpers.h, src/common/sha2/sha2.c, src/common/sha2/sha2.h, src/common/sha2/sha2_c.c, src/common/sha2/sha2_impl.c, src/common/sha2/sha2_local.h, src/common/sha2/sha2_ops.h, src/common/x86_64_helpers.h
- used only for SHA256()/SHA512() (hash.c's OpenSSL calls are provided by shim.c)
