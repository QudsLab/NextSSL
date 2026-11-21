/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP hashblocks/sha512 code (blocks.c) under the name crypto_hashblocks_sha512. */
#define NS_SUP_NAME crypto_hashblocks_sha512
#define NS_SUP_PFX(x) crypto_hashblocks_sha512_##x
#include "crypto_hashblocks_sha512.h"
#include "upstream/support/hashblocks_sha512/blocks.c"
