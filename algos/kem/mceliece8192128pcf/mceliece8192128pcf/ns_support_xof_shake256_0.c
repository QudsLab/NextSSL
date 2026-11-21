/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP xof/shake256 code (fips202.c) under the name crypto_xof_shake256. */
#define NS_SUP_NAME crypto_xof_shake256
#define NS_SUP_PFX(x) crypto_xof_shake256_##x
#include "crypto_xof_shake256.h"
#include "upstream/support/xof_shake256/fips202.c"
