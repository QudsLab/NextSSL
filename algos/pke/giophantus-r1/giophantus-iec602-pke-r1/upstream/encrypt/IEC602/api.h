//
//  api.h
//
//  Created by Bassham, Lawrence E (Fed) on 9/6/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
// modified by H. Shimizu on 2017/9/25

#ifndef api_h
#define api_h

#include "parameter.h"

//  Set these three values apropriately for your algorithm
#define CRYPTO_SECRETKEYBYTES SK_SIZE
#define CRYPTO_PUBLICKEYBYTES PK_SIZE
#define CRYPTO_BYTES C_SIZE

// Change the algorithm name
#define CRYPTO_ALGNAME "Giophantus"

int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk);
int crypto_encrypt(unsigned char *c, unsigned long long *clen, unsigned char *m, unsigned long long mlen, unsigned char *pk);
// add extra parameter pk
int crypto_encrypt_open(unsigned char *m, unsigned long long *mlen, unsigned char *c, unsigned long long clen, unsigned char *sk); // modify

#endif /* api_h */
