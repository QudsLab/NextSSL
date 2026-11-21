/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP hash/sha256 code (hash.c) under the name crypto_hash_sha256. */
#define NS_SUP_NAME crypto_hash_sha256
#define NS_SUP_PFX(x) crypto_hash_sha256_##x
#include "crypto_hash_sha256.h"
#include "upstream/support/hash_sha256/hash.c"
