/* NextSSL compat header (not upstream code): cl.exe has no GNU __attribute__; the annotations (aligned(16)) carry no semantics for the portable C. */
#ifndef NS_PRE_H
#define NS_PRE_H
#ifdef _MSC_VER
#define __attribute__(x)
#endif
#endif
