/* NextSSL compat header (not upstream code): randombytes is supplied by shim.c. */
#ifndef NS_COMPAT_RB
#define NS_COMPAT_RB
int randombytes(unsigned char *, unsigned long long);
#endif
