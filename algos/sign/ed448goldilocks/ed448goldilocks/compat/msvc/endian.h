/* NextSSL compat (not upstream), MSVC targets only: glibc <endian.h> names. Every MSVC target
 * (x86, x64, ARM64) is little-endian. Newer clang-cl ships its own <endian.h> and older ones do not;
 * this stand-in comes first on the include path, so every clang-cl version compiles the same code. */
#ifndef NEXTSSL_COMPAT_ENDIAN_H
#define NEXTSSL_COMPAT_ENDIAN_H
#include <stdint.h>
#include <stdlib.h>
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __PDP_ENDIAN 3412
#define __BYTE_ORDER __LITTLE_ENDIAN
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#define BIG_ENDIAN __BIG_ENDIAN
#define PDP_ENDIAN __PDP_ENDIAN
#define BYTE_ORDER __BYTE_ORDER
#define htobe16(x) _byteswap_ushort((uint16_t)(x))
#define htobe32(x) _byteswap_ulong((uint32_t)(x))
#define htobe64(x) _byteswap_uint64((uint64_t)(x))
#define htole16(x) ((uint16_t)(x))
#define htole32(x) ((uint32_t)(x))
#define htole64(x) ((uint64_t)(x))
#define be16toh(x) _byteswap_ushort((uint16_t)(x))
#define be32toh(x) _byteswap_ulong((uint32_t)(x))
#define be64toh(x) _byteswap_uint64((uint64_t)(x))
#define le16toh(x) ((uint16_t)(x))
#define le32toh(x) ((uint32_t)(x))
#define le64toh(x) ((uint64_t)(x))
#endif
