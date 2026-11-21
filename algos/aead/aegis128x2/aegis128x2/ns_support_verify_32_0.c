/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP verify/32 code (verify.c) under the name crypto_verify_32. */
#define NS_SUP_NAME crypto_verify_32
#define NS_SUP_PFX(x) crypto_verify_32_##x
#include "crypto_verify_32.h"
#include "upstream/support/verify_32/verify.c"
