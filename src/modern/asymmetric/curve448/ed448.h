#ifndef WOLF_CRYPT_ED448_H
#define WOLF_CRYPT_ED448_H

#include "wolf_shim.h"

#ifdef HAVE_ED448

#include "fe_448.h"
#include "ge_448.h"

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#define ED448_KEY_SIZE     57   /* private key only */
#define ED448_SIG_SIZE     114  /* two elements */

#define ED448_PUB_KEY_SIZE 57   /* compressed */
/* both private and public key */
#define ED448_PRV_KEY_SIZE (ED448_PUB_KEY_SIZE+ED448_KEY_SIZE)

#define ED448_PREHASH_SIZE 64

enum {
    Ed448    = 0,
    Ed448ph  = 1
};

/* An ED448 Key */
struct ed448_key {
    byte    p[ED448_PUB_KEY_SIZE]; /* compressed public key */
    byte    k[ED448_PRV_KEY_SIZE]; /* private key : 57 secret -- 57 public */

    WC_BITFIELD privKeySet:1;
    WC_BITFIELD pubKeySet:1;
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
#endif
#if defined(WOLF_CRYPTO_CB)
    void* devCtx;
    int devId;
#endif
    void *heap;
    wc_Shake sha;
    unsigned int sha_clean_flag : 1;
};

#ifndef WC_ED448KEY_TYPE_DEFINED
    typedef struct ed448_key ed448_key;
    #define WC_ED448KEY_TYPE_DEFINED
#endif

WOLFSSL_API
int wc_ed448_make_public(ed448_key* key, unsigned char* pubKey,
                         word32 pubKeySz);
WOLFSSL_API
int wc_ed448_make_key(WC_RNG* rng, int keysize, ed448_key* key);

WOLFSSL_API
int wc_ed448_sign_msg(const byte* in, word32 inLen, byte* out, word32 *outLen,
                      ed448_key* key, const byte* context, byte contextLen);
WOLFSSL_API
int wc_ed448ph_sign_hash(const byte* hash, word32 hashLen, byte* out,
                         word32 *outLen, ed448_key* key,
                         const byte* context, byte contextLen);
WOLFSSL_API
int wc_ed448_sign_msg_ex(const byte* in, word32 inLen, byte* out,
                         word32 *outLen, ed448_key* key, byte type,
                         const byte* context, byte contextLen);
WOLFSSL_API
int wc_ed448ph_sign_msg(const byte* in, word32 inLen, byte* out,
                        word32 *outLen, ed448_key* key, const byte* context,
                        byte contextLen);

WOLFSSL_API
int wc_ed448_verify_msg_ex(const byte* sig, word32 sigLen, const byte* msg,
                            word32 msgLen, int* res, ed448_key* key,
                            byte type, const byte* context, byte contextLen);

WOLFSSL_API
int wc_ed448_verify_msg_init(const byte* sig, word32 sigLen, ed448_key* key,
                        byte type, const byte* context, byte contextLen);
WOLFSSL_API
int wc_ed448_verify_msg_update(const byte* msgSegment, word32 msgSegmentLen,
                             ed448_key* key);
WOLFSSL_API
int wc_ed448_verify_msg_final(const byte* sig, word32 sigLen,
                              int* res, ed448_key* key);

WOLFSSL_API
int wc_ed448_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                        word32 msgLen, int* res, ed448_key* key,
                        const byte* context, byte contextLen);
WOLFSSL_API
int wc_ed448ph_verify_hash(const byte* sig, word32 sigLen, const byte* hash,
                           word32 hashLen, int* res, ed448_key* key,
                           const byte* context, byte contextLen);
WOLFSSL_API
int wc_ed448ph_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                          word32 msgLen, int* res, ed448_key* key,
                          const byte* context, byte contextLen);

WOLFSSL_API
int wc_ed448_init_ex(ed448_key* key, void *heap, int devId);
WOLFSSL_API
int wc_ed448_init(ed448_key* key);
WOLFSSL_API
void wc_ed448_free(ed448_key* key);

WOLFSSL_API
int wc_ed448_import_public(const byte* in, word32 inLen, ed448_key* key);
WOLFSSL_API
int wc_ed448_import_public_ex(const byte* in, word32 inLen, ed448_key* key,
                              int trusted);
WOLFSSL_API
int wc_ed448_import_private_only(const byte* priv, word32 privSz,
                                 ed448_key* key);
WOLFSSL_API
int wc_ed448_import_private_key(const byte* priv, word32 privSz,
                                const byte* pub, word32 pubSz, ed448_key* key);
WOLFSSL_API
int wc_ed448_import_private_key_ex(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, ed448_key* key, int trusted);

WOLFSSL_API
int wc_ed448_export_public(const ed448_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_ed448_export_private_only(const ed448_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_ed448_export_private(const ed448_key* key, byte* out, word32* outLen);
WOLFSSL_API
int wc_ed448_export_key(const ed448_key* key, byte* priv, word32 *privSz,
                        byte* pub, word32 *pubSz);

WOLFSSL_API
int wc_ed448_check_key(ed448_key* key);

/* size helper */
WOLFSSL_API
int wc_ed448_size(const ed448_key* key);
WOLFSSL_API
int wc_ed448_priv_size(const ed448_key* key);
WOLFSSL_API
int wc_ed448_pub_size(const ed448_key* key);
WOLFSSL_API
int wc_ed448_sig_size(const ed448_key* key);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_ED448 */
#endif /* WOLF_CRYPT_ED448_H */
