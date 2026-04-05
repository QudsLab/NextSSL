#ifndef NEXTSSL_MLKEM768_KEM_H
#define NEXTSSL_MLKEM768_KEM_H
#include "params.h"
#include <stdint.h>

#define NEXTSSL_MLKEM768_CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define NEXTSSL_MLKEM768_CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define NEXTSSL_MLKEM768_CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define NEXTSSL_MLKEM768_CRYPTO_BYTES           KYBER_SSBYTES

#define NEXTSSL_MLKEM768_CRYPTO_ALGNAME "ML-KEM-768"

int NEXTSSL_MLKEM768_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);

int NEXTSSL_MLKEM768_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int NEXTSSL_MLKEM768_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);

int NEXTSSL_MLKEM768_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

int NEXTSSL_MLKEM768_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
