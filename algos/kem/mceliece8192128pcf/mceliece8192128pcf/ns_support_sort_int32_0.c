/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP sort/int32 code (sort.c) under the name crypto_sort_int32. */
#define NS_SUP_NAME crypto_sort_int32
#define NS_SUP_PFX(x) crypto_sort_int32_##x
#include "crypto_sort_int32.h"
#include "upstream/support/sort_int32/sort.c"
