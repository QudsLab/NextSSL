#ifndef NEXTSSL_MLKEM512_AVX2_API_H
#define NEXTSSL_MLKEM512_AVX2_API_H

#include <stdint.h>

#define NEXTSSL_MLKEM512_AVX2_CRYPTO_SECRETKEYBYTES  1632
#define NEXTSSL_MLKEM512_AVX2_CRYPTO_PUBLICKEYBYTES  800
#define NEXTSSL_MLKEM512_AVX2_CRYPTO_CIPHERTEXTBYTES 768
#define NEXTSSL_MLKEM512_AVX2_CRYPTO_BYTES           32
#define NEXTSSL_MLKEM512_AVX2_CRYPTO_ALGNAME "ML-KEM-512"

int NEXTSSL_MLKEM512_AVX2_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int NEXTSSL_MLKEM512_AVX2_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int NEXTSSL_MLKEM512_AVX2_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
