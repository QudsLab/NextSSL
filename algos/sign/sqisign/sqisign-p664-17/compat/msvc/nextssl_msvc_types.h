/* NextSSL compat (not upstream), MSVC targets only: POSIX ssize_t, which the CRT lacks. */
#ifndef NEXTSSL_MSVC_TYPES_H
#define NEXTSSL_MSVC_TYPES_H
#include <stdint.h>
typedef intptr_t ssize_t;
#endif
