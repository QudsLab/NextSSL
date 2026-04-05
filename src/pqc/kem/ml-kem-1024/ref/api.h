#ifndef NEXTSSL_MLKEM1024_API_H
#define NEXTSSL_MLKEM1024_API_H

#include <stdint.h>

#define NEXTSSL_MLKEM1024_CRYPTO_SECRETKEYBYTES  3168
#define NEXTSSL_MLKEM1024_CRYPTO_PUBLICKEYBYTES  1568
#define NEXTSSL_MLKEM1024_CRYPTO_CIPHERTEXTBYTES 1568
#define NEXTSSL_MLKEM1024_CRYPTO_BYTES           32
#define NEXTSSL_MLKEM1024_CRYPTO_ALGNAME "ML-KEM-1024"

int NEXTSSL_MLKEM1024_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int NEXTSSL_MLKEM1024_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int NEXTSSL_MLKEM1024_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
