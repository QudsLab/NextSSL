/* NextSSL compat header (not upstream code): a fixed, portable-C liboqs configuration. No OpenSSL, no CPU-specific
 * code, no threads: AES, SHA-2 and SHA-3 use liboqs' own plain C implementations (XKCP plain-64bits, serial x4). */
#ifndef NS_OQSCONFIG_H
#define NS_OQSCONFIG_H
#define OQS_VERSION_TEXT "0.15.0"
#define OQS_VERSION_MAJOR 0
#define OQS_VERSION_MINOR 15
#define OQS_VERSION_PATCH 0
#define OQS_USE_PTHREADS 0
#define OQS_USE_CUPQC 0
#define OQS_USE_ICICLE 0
#endif
