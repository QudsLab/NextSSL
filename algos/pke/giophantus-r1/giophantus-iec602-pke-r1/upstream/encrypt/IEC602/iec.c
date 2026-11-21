/*
	Giophantus public key cryptosystem

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#include <string.h>
#include "api.h"
#include "iec.h"
#include "genrand.h"


/**
	IECKG

	@param[out] ux secret key 1
	@param[out] uy secret key 2
	@param[out] X public key
*/
void iec_kg(Rq ux, Rq uy, Pq X)
{
	Rq a00;

	Rl_rand(ux);
	Rl_rand(uy);
	Pq_rand(X, DX);

	Pq_subst(a00, X, ux, uy, DX);
	Rq_sub(X[0][0], X[0][0], a00);
}


/**
	IECENC

	@param[out] c ciphertext in Pq(dX + dr)
	@param[in] m message in Rl
	@param[in] X public key in Pq(dX)
*/
void iec_enc(Pq c, Rq m, Pq X)
{
	Pq r, e;
	
	Pq_rand(r, DR);
	Pl_rand(e, DC);

	// c = m + X * r + l * e
	Pq_mul(c, X, r, DX, DR);
	Pq_smul(e, DC);
	Pq_add(c, c, e, DC);
	Rq_add(c[0][0], c[0][0], m);
}


/**
	IECDEC

	@param[out] m message in Rl
	@param[in] c ciphertext in Pq(dX + dr)
	@param[in] ux secret key 1 in Rl
	@param[in] uy secret key 2 in Rl
*/
void iec_dec(Rq m, Pq c, Rq ux, Rq uy)
{
	Pq_subst(m, c, ux, uy, DC);
	Rq_reduce(m);
}


/**
	generate key pair

	@param[out] pk
	@param[out] sk
	@return status
*/
int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk)
{
	Rq ux, uy;
	Pq X;

	set_randmode(RNG);

	iec_kg(ux, uy, X);

	Rl2OS(sk, ux);
	Rl2OS(&sk[RL_SIZE], uy); // modify
	Pq2OS(pk, X, DX);
	memcpy(&sk[2 * RL_SIZE], pk, PK_SIZE); // modify
	return IEC_OK;
}


/**
	encrypt with FO conversion

	@param[out] cip
	@param[out] ciplen
	@param[in] msg
	@param[in] msglen
	@param[in] pk
	@param[in] status
*/
int crypto_encrypt(unsigned char *cip, unsigned long long *ciplen, unsigned char *msg, unsigned long long msglen, unsigned char *pk)
{
	uint8_t M[PAYLOAD_SIZE];
	Rq m;
	Pq c, X;

	set_randmode(RNG);

	// pad with random string
	memcpy(M, msg, MLEN);
	genrand(&M[MLEN], PAYLOAD_SIZE - MLEN);

#if N % 4 == 1
	M[PAYLOAD_SIZE - 1] &= 0xc0;
#elif N % 4 == 2
	M[PAYLOAD_SIZE - 1] &= 0xf0;
#elif N % 4 == 3
	M[PAYLOAD_SIZE - 1] &= 0xfc;
#endif

	// initialize seed expand
	se_init(M, PAYLOAD_SIZE, SEED_SIZE);
	set_randmode(SE);

	// encrypt
	OS2Rl(m, M);
	OS2Pq(X, DX, pk);
	iec_enc(c, m, X);
	Pq2OS(cip, c, DC);
	*ciplen = C_SIZE;

	set_randmode(RNG);
	return IEC_OK;
}


/**
	decrypt with FO conversion

	@param[out] msg
	@param[out] msglen
	@param[in] cip
	@param[in] ciplen
	@param[in] sk
	@return status
*/
int crypto_encrypt_open(unsigned char *msg, unsigned long long *msglen, unsigned char *cip, unsigned long long ciplen, unsigned char *sk) // modify
{
	uint8_t M[PAYLOAD_SIZE];
	uint8_t w[C_SIZE];
	Rq m, ux, uy;
	Pq c, c2, X;

	// decrypt
	OS2Pq(c, DC, cip);
	OS2Rl(ux, sk);
	OS2Rl(uy, &sk[RL_SIZE]);
	iec_dec(m, c, ux, uy);

	// verify
	Rl2OS(M, m);

	// initialize seed expand
	se_init(M, PAYLOAD_SIZE, SEED_SIZE);
	set_randmode(SE);

	OS2Pq(X, DX, &sk[2 * RL_SIZE]); // modify
	iec_enc(c2, m, X);

	set_randmode(RNG);

	Pq2OS(w, c2, DC);
	if(memcmp(cip, w, C_SIZE) != 0) return IEC_NG;

	*msglen = MLEN;
	memcpy(msg, M, MLEN);
	return IEC_OK;
}
