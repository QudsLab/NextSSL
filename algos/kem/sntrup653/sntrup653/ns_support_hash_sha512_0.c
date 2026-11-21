/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP hash/sha512 code (hash.c) under the name crypto_hash_sha512. */
#define NS_SUP_NAME crypto_hash_sha512
#define NS_SUP_PFX(x) crypto_hash_sha512_##x
#include "crypto_hash_sha512.h"
#include "upstream/support/hash_sha512/hash.c"
