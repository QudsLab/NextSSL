#ifndef NEXTSSL_MLDSA87_API_H
#define NEXTSSL_MLDSA87_API_H

#include <stddef.h>
#include <stdint.h>

#define NEXTSSL_MLDSA87_CRYPTO_PUBLICKEYBYTES 2592
#define NEXTSSL_MLDSA87_CRYPTO_SECRETKEYBYTES 4896
#define NEXTSSL_MLDSA87_CRYPTO_BYTES 4627
#define NEXTSSL_MLDSA87_CRYPTO_ALGNAME "ML-DSA-87"

int NEXTSSL_MLDSA87_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int NEXTSSL_MLDSA87_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int NEXTSSL_MLDSA87_crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int NEXTSSL_MLDSA87_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int NEXTSSL_MLDSA87_crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int NEXTSSL_MLDSA87_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int NEXTSSL_MLDSA87_crypto_sign(uint8_t *sm, size_t *smlen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *sk);

int NEXTSSL_MLDSA87_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

int NEXTSSL_MLDSA87_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);

#endif
