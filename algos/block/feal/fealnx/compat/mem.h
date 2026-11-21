/* ours: Borland <mem.h>: memcpy/memset plus movmem(src, dst, n), which is memmove with swapped arguments */
#include <string.h>
#define movmem(src, dst, n) memmove((dst), (src), (n))
