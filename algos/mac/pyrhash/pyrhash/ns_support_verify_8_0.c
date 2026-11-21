/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP verify/8 code (verify.c) under the name crypto_verify_8. */
#define NS_SUP_NAME crypto_verify_8
#define NS_SUP_PFX(x) crypto_verify_8_##x
#include "crypto_verify_8.h"
#include "upstream/support/verify_8/verify.c"
