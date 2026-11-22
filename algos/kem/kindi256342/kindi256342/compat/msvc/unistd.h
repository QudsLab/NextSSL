/* NextSSL compat (not upstream), MSVC targets only: POSIX <unistd.h> stand-in. The upstreams here
 * include it for read/write/close/getpid or nothing at all; the CRT has those in io.h/process.h. */
#ifndef NEXTSSL_COMPAT_UNISTD_H
#define NEXTSSL_COMPAT_UNISTD_H
#include <io.h>
#include <process.h>
#include <stdint.h>
typedef intptr_t ssize_t;
#endif
