/* NextSSL compat (not upstream), macOS only: glibc <endian.h> names for the Darwin byte-order macros. */
#ifndef NEXTSSL_COMPAT_ENDIAN_H
#define NEXTSSL_COMPAT_ENDIAN_H
#include <machine/endian.h>
#define __BYTE_ORDER BYTE_ORDER
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
