/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP verify/16 code (verify.c) under the name crypto_verify_16. */
#define NS_SUP_NAME crypto_verify_16
#define NS_SUP_PFX(x) crypto_verify_16_##x
#include "crypto_verify_16.h"
#include "upstream/support/verify_16/verify.c"
