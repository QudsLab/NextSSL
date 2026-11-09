/* NextSSL compat header (not upstream code): SUPERCOP builds define CRYPTO_NAMESPACE(x) per cipher; the upstream symbols get the nextssl__dragon__ prefix here, the shim symbols through build.rs. */
#ifndef NS_PRE_H
#define NS_PRE_H
#define CRYPTO_NAMESPACE(x) nextssl__dragon__##x
#endif
