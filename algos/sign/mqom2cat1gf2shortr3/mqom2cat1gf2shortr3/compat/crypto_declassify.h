/* NextSSL compat header (not upstream code): valgrind-style declassify marker, a no-op. */
#ifndef NS_COMPAT_DECL
#define NS_COMPAT_DECL
#define crypto_declassify(x, y) ((void)(x), (void)(y))
#endif
