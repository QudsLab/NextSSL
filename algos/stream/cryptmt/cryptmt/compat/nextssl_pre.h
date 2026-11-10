/* NextSSL compat header (not upstream code): SUPERCOP builds define CRYPTO_NAMESPACE(x) per cipher; the upstream symbols get the nextssl__cryptmt__ prefix here, the shim symbols through build.rs. */
#ifndef NS_PRE_H
#define NS_PRE_H
#define CRYPTO_NAMESPACE(x) nextssl__cryptmt__##x
#endif
