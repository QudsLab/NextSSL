/* NextSSL compat header (not upstream code): endianness macros for MSVC. */
#ifdef _MSC_VER
#ifndef NS_COMPAT_PARAM
#define NS_COMPAT_PARAM
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#else
#include_next <sys/param.h>
#endif
