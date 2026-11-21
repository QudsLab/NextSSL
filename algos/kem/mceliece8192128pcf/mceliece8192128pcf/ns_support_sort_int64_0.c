/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP sort/int64 code (sort.c) under the name crypto_sort_int64. */
#define NS_SUP_NAME crypto_sort_int64
#define NS_SUP_PFX(x) crypto_sort_int64_##x
#include "crypto_sort_int64.h"
#include "upstream/support/sort_int64/sort.c"
