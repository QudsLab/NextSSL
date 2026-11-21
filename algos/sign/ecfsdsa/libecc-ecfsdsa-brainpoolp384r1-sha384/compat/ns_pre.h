/* NextSSL compat header (not upstream code), force-included into every libecc source.
 * libecc's sig_algs_internal.h declares scheme callbacks that mention `struct ec_sign_context` inside prototype
 * scope. In the stock all-schemes build ecdsa.h introduces the tag first; with a single scheme enabled (EC-SDSA,
 * EC-OSDSA) the tag is born in prototype scope and the table initializers fail with incompatible pointer types.
 * A file-scope forward declaration of the two tags removes that without touching upstream. */
#ifndef NS_PRE_H
#define NS_PRE_H
/* libecc detects its word size only through GNU predefined macros; cl.exe has none of them, so pick 32-bit words there. */
#if defined(_MSC_VER) && !defined(WORDSIZE)
#define WORDSIZE 32
#endif
struct ec_sign_context;
struct ec_verify_context;
#endif
