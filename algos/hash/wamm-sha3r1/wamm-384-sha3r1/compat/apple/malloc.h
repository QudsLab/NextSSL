/* NextSSL compat (not upstream), macOS only: glibc <malloc.h> is absent there; the upstream
 * only needs the malloc/calloc/free prototypes, which <stdlib.h> declares. */
#ifndef NEXTSSL_COMPAT_MALLOC_H
#define NEXTSSL_COMPAT_MALLOC_H
#include <stdlib.h>
#endif
