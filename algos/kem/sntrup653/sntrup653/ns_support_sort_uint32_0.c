/* NextSSL wrapper (not upstream code): compiles the verbatim SUPERCOP sort/uint32 code (sort.c) under the name crypto_sort_uint32. */
#define NS_SUP_NAME crypto_sort_uint32
#define NS_SUP_PFX(x) crypto_sort_uint32_##x
#include "crypto_sort_uint32.h"
#include "upstream/support/sort_uint32/sort.c"
