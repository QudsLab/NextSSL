/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP hashblocks/sha256 code (blocks.c) under the name crypto_hashblocks_sha256. */
#define NS_SUP_NAME crypto_hashblocks_sha256
#define NS_SUP_PFX(x) crypto_hashblocks_sha256_##x
#include "crypto_hashblocks_sha256.h"
#include "upstream/support/hashblocks_sha256/blocks.c"
