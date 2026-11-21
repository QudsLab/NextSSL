/*
	Giophantus public key cryptosystem

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#include <string.h>
#include "api.h"
#include "iec.h"
#include "genrand.h"


#define PL_SIZE(d) (NTERM(d) * RL_SIZE)


void dump(uint8_t *x, int size, char *label);


typedef struct {
	int i, j;
} exp_pair;

static const exp_pair exp_table[] = {
	{0, 0},
	{0, 1},{1, 0},
	{0, 2},{1, 1},{2, 0},
	{0, 3},{1, 2},{2, 1},{3, 0},
	{0, 4},{1, 3},{2, 2},{3, 1},{4, 0},
};


/**
	Pl: convert Pl to octet string

	@param[out] os
	@param[in] f
	@param[in] d total degree of f
	@return byte size of result
*/
void Pl2OS(uint8_t *os, Pq f, int d)
{
	int i, j, index, p;

	p = 0;
	for(index = NTERM(d) - 1; index >= 0; index--){
		i = exp_table[index].i;
		j = exp_table[index].j;
		Rl2OS(&os[p], f[i][j]);
		p += RL_SIZE;
	}
}


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

	{
		uint8_t t[C_SIZE];

		printf("\n=============================================\n");
		printf("IECKG\n");
		Rl2OS(t, ux);
		dump(t, RL_SIZE, "(1) ux : Rl");
		Rl2OS(t, uy);
		dump(t, RL_SIZE, "(2) uy : Rl");
		Pq2OS(t, X, DX);
		dump(t, PQ_SIZE(DX), "(3) X : Pq(1)");
		Rq2OS(t, a00);
		dump(t, RQ_SIZE, "(4) a00 : Rq");
	}

	Rq_sub(X[0][0], X[0][0], a00);

	{
		uint8_t t[C_SIZE];

		Pq2OS(t, X, DX);
		dump(t, PQ_SIZE(DX), "(5) X : Pq(1)");
	}
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
	Pq w;

	Pq_rand(r, DR);
	Pl_rand(e, DC);

	// c = m + X * r + l * e
	Pq_mul(w, X, r, DX, DR);
	Pq_smul(e, DC);
	Pq_add(c, w, e, DC);
	Rq_add(c[0][0], c[0][0], m);

	{
		uint8_t t[C_SIZE];

		printf("\n=============================================\n");
		printf("IECENC\n");

		Rl2OS(t, m);
		dump(t, RL_SIZE, "m : Rl");
		Pq2OS(t, r, DR);
		dump(t, PQ_SIZE(DR), "(1) r : Pq(1)");
		Pl2OS(t, e, DC);
		dump(t, PL_SIZE(DC), "(2) e : Pl(2)");
		Pq2OS(t, w, DC);
		dump(t, PQ_SIZE(DC), "(3) X * r : Pq(2)");
		Pq2OS(t, c, DC);
		dump(t, PQ_SIZE(DC), "(3) c : Pq(2)");
	}
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

	{
		uint8_t t[C_SIZE];

		printf("\n=============================================\n");
		printf("IECDEC\n");

		Rq2OS(t, m);
		dump(t, RQ_SIZE, "(1) m : Rq");
	}

	Rq_reduce(m);

	{
		uint8_t t[C_SIZE];

		Rl2OS(t, m);
		dump(t, RL_SIZE, "(2) m : Rl");
	}
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

	{
		printf("\n=============================================\n");
		printf("crypto_encrypt_keypair\n");
	}

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

	{
		printf("\n=============================================\n");
		printf("crypto_encrypt\n");

		dump(msg, MLEN, "m ... plaintext");
		dump(M, RL_SIZE, "(2) M ... seed of SeedExpander");
	}

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

	{
		printf("\n=============================================\n");
		printf("crypto_encrypt_open\n");
	}

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
