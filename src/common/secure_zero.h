/* secure_zero.h — Portable secure memory wipe (Plan 204)
 *
 * secure_zero(buf, len) zeroes len bytes starting at buf.
 * Unlike plain memset(), this wipe is guaranteed not to be
 * removed by the compiler as a dead store.
 *
 * On Windows  : delegates to SecureZeroMemory() (WinAPI).
 * C11 Annex K : delegates to memset_s().
 * Fallback    : volatile-pointer loop + compiler memory barrier.
 *
 * No .c file is needed — the function is defined inline here.
 */
#ifndef NEXTSSL_SECURE_ZERO_H
#define NEXTSSL_SECURE_ZERO_H

#include <stddef.h>

#if defined(_WIN32)
#  include <windows.h>
   static inline void secure_zero(void *buf, size_t len) {
       SecureZeroMemory(buf, len);
   }
#elif defined(__STDC_LIB_EXT1__)
#  define __STDC_WANT_LIB_EXT1__ 1
#  include <string.h>
   static inline void secure_zero(void *buf, size_t len) {
       if (buf && len) memset_s(buf, len, 0, len);
   }
#else
   static inline void secure_zero(void *buf, size_t len) {
       if (!buf || !len) return;
   /* The volatile byte loop is the guaranteed portable wipe path.
    * The GNU/Clang compiler fence below is only a belt-and-suspenders
    * barrier to keep surrounding reordering conservative. */
       volatile unsigned char *p = (volatile unsigned char *)buf;
       while (len--) *p++ = 0;
#  ifdef __GNUC__
       __asm__ __volatile__("" ::: "memory");
#  endif
   }
#endif

#endif /* NEXTSSL_SECURE_ZERO_H */
