/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP core/aes128encrypt code (core.c) under the name crypto_core_aes128encrypt. */
#define NS_SUP_NAME crypto_core_aes128encrypt
#define NS_SUP_PFX(x) crypto_core_aes128encrypt_##x
#include "crypto_core_aes128encrypt.h"
#include "upstream/support/core_aes128encrypt/core.c"
