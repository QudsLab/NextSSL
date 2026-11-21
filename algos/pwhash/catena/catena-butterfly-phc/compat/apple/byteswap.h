/* NextSSL compat (not upstream), macOS only: glibc <byteswap.h> names for the Darwin byte swaps. */
#ifndef NEXTSSL_COMPAT_BYTESWAP_H
#define NEXTSSL_COMPAT_BYTESWAP_H
#include <libkern/OSByteOrder.h>
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)
#endif
