/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP core/aes128decrypt code (core.c) under the name crypto_core_aes128decrypt. */
#define NS_SUP_NAME crypto_core_aes128decrypt
#define NS_SUP_PFX(x) crypto_core_aes128decrypt_##x
#include "crypto_core_aes128decrypt.h"
#include "upstream/support/core_aes128decrypt/core.c"
