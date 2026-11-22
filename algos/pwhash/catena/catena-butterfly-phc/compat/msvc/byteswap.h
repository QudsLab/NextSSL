/* NextSSL compat (not upstream), MSVC targets only: glibc <byteswap.h> names on the CRT byte swaps. */
#ifndef NEXTSSL_COMPAT_BYTESWAP_H
#define NEXTSSL_COMPAT_BYTESWAP_H
#include <stdlib.h>
#define bswap_16(x) _byteswap_ushort(x)
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)
#endif
