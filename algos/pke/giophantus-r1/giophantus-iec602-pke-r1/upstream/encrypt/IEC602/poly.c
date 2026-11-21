/*
	Giophantus public key cryptosystem

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "iec.h"
#include "genrand.h"


typedef struct {
	int i, j;
} exp_pair;

static const exp_pair exp_table[] = {
	{0, 0},
	{0, 1}, {1, 0},
	{0, 2}, {1, 1}, {2, 0},
	{0, 3}, {1, 2}, {2, 1}, {3, 0},
	{0, 4}, {1, 3}, {2, 2}, {3, 1}, {4, 0},
};


/**
	Fq: a + b

	@param[in] a
	@param[in] b
	@return (a + b) % Q
*/
Fq Fq_add(Fq a, Fq b)
{
	Fq c = a + b;
	return c < Q ? c : c - Q;
}


/**
	Fq: a - b

	@param[in] a
	@param[in] b
	@return (a - b) % Q
*/
Fq Fq_sub(Fq a, Fq b)
{
	return a < b ? a - b + Q : a - b;
}


/**
	Fq: a * b

	@param[in] a
	@param[in] b
	@return (a * b) % Q
*/
Fq Fq_mul(Fq a, Fq b)
{
	return cast(uint64_t, a) * b % Q;
}


/**
	Rq: a = 0

	@param[out] a
*/
void Rq_clear(Rq a)
{
	int i;

	for(i = 0; i < N; i++) a[i] = 0;
}


/**
	Rq: c = a + b

	@param[out] c
	@param[in] a
	@param[in] b
*/
void Rq_add(Rq c, Rq a, Rq b)
{
	int i;

	for(i = 0; i < N; i++) c[i] = Fq_add(a[i], b[i]);
}


/**
	Rq: c = a - b

	@param[out] c
	@param[in] a
	@param[in] b
*/
void Rq_sub(Rq c, Rq a, Rq b)
{
	int i;

	for(i = 0; i < N; i++) c[i] = Fq_sub(a[i], b[i]);
}


/**
	Rq: c = a * b

	@param[out] c
	@param[in] a
	@param[in] b
*/
void Rq_mul(Rq c, Rq a, Rq b)
{
	int i, j, p;

	for(i = 0; i < N; i++) c[i] = 0;
	for(i = 0; i < N; i++){
		for(j = 0; j < N; j++){
			p = (i + j) % N;
			c[p] = Fq_add(c[p], Fq_mul(a[i], b[j]));
		}
	}
}


void Rq_reduce(Rq a)
{
	int i;

	for(i = 0; i < N; i++) a[i] %= L;
}


/**
	Pq: a = 0

	@param[out] a
	@param[in] d
*/
void Pq_clear(Pq a, int d)
{
	int i, j;

	POLYFOR(i, j, d){
		Rq_clear(a[i][j]);
	}
}


/**
	Pq: c = a + b

	@param[out] c
	@param[in] a
	@param[in] b
	@param[in] d total degree of a, b
*/
void Pq_add(Pq c, Pq a, Pq b, int d)
{
	int i, j;

	POLYFOR(i, j, d){
		Rq_add(c[i][j], a[i][j], b[i][j]);
	}
}


/**
	Pq: c = a * b

	@param[in] a
	@param[in] b
	@param[in] ad total degree of a
	@param[in] bd total degree of b
*/
void Pq_mul(Pq c, Pq a, Pq b, int ad, int bd)
{
	Rq t;
	int ai, aj, bi, bj;

	Pq_clear(c, ad + bd);
	POLYFOR(ai, aj, ad){
		POLYFOR(bi, bj, bd){
			Rq_mul(t, a[ai][aj], b[bi][bj]);
			Rq_add(c[ai + bi][aj + bj], c[ai + bi][aj + bj], t);
		}
	}
}


/**
	Pq: a *= L

	@param[inout] a
	@param[in] d total degree of a
	@param[in] s
*/
void Pq_smul(Pq a, int d)
{
	int i, j, k;

	POLYFOR(i, j, d){
		for(k = 0; k < N; k++) a[i][j][k] <<= L_BIT;
	}

}


/**
	Pq: substitute x = a, y = b for c = f(x, y)

	@param[out] c
	@param[in] f
	@param[in] a
	@param[in] b
	@param[in] d total degree of f
*/
void Pq_subst(Rq c, Pq f, Rq a, Rq b, int d)
{
	Rq w, t;
	int i;

	for(i = 0; i < N; i++) c[i] = f[0][0][i];

	// f10 * a
	Rq_mul(w, f[1][0], a);
	Rq_add(c, c, w);

	// f01 * b
	Rq_mul(w, f[0][1], b);
	Rq_add(c, c, w);

	if(d == 1) return;

	// f20 * a ^ 2
	Rq_mul(t, a, a);
	Rq_mul(w, f[2][0], t);
	Rq_add(c, c, w);

	// f11 * a * b
	Rq_mul(t, a, b);
	Rq_mul(w, f[1][1], t);
	Rq_add(c, c, w);

	// f02 * b ^ 2
	Rq_mul(t, b, b);
	Rq_mul(w, f[0][2], t);
	Rq_add(c, c, w);

	if(d == 2) return;

	fprintf(stderr, "Pq_subst(%d) not implemented\n", d);
	exit(EXIT_FAILURE);
}


/**
	Fq : generate random number in Fq

	@return random Fq
*/
Fq Fq_rand(void)
{
	Fq t = 0;

	genrand(cast(uint8_t *, &t), Q_SIZE);
	return t % Q;
}


/**
	Fl : generate random number in Fl

	@return random Fl
*/
Fq Fl_rand(void)
{
	Fq t = 0;

	genrand(cast(uint8_t *, &t), 1);
	return t % L;
}


/**
	Rq: generate random polynomial in Rq

	@param[out] f
*/
void Rq_rand(Rq f)
{
	int i;

	for(i = 0; i < N; i++) f[i] = Fq_rand();
}


/**
	Rl: generate random polynomial in Rl

	@param[out] x
*/
void Rl_rand(Rq f)
{
	int i;

	for(i = 0; i < N; i++) f[i] = Fl_rand();
}


/**
	Pq: generate random polynomial in Pq(d)

	@param[out] f
	@param[in] d
*/
void Pq_rand(Pq f, int d)
{
	int i, j;

	POLYFOR(i, j, d){
		Rq_rand(f[i][j]);
	}
}


/**
	Pl: generate random polynomial in Pl(d)

	@param[out] f
	@param[in] d
*/
void Pl_rand(Pq f, int d)
{
	int i, j;

	POLYFOR(i, j, d){
		Rl_rand(f[i][j]);
	}
}



/**
	Rq: convert Rq to octet string

	@param[out] os Q_SIZE * N bytes
	@param[in] f
	@return byte size of result
*/
void Rq2OS(uint8_t *os, Rq f)
{
	int i, p;

	p = 0;
	for(i = 0; i < N; i++){
		// this code assume little endian cpu.
		memcpy(&os[p], &f[i], Q_SIZE);
		p += Q_SIZE;
	}
}


/**
	Rl: convert Rl to octet string

	@param[out] os ceiling(N / 4) bytes
	@param[in] f
	@return byte size of result
*/
void Rl2OS(uint8_t *os, Rq f)
{
	int i;

	for(i = 0; i < N / 4; i++){
		os[i] = f[4 * i] << 6 | f[4 * i + 1] << 4 | f[4 * i + 2] << 2 | f[4 * i + 3];
	}

#if N % 4 == 1
	os[N / 4] = f[N - 1] << 6;
#elif N % 4 == 2
	os[N / 4] = f[N - 2] << 6 | f[N - 1] << 4;
#elif N % 4 == 3
	os[N / 4] = f[N - 3] << 6 | f[N - 2] << 4 | f[N - 1] << 2;
#endif
}


/**
	Pq: convert Pq to octet string

	@param[out] os
	@param[in] f
	@param[in] d total degree of f
	@return byte size of result
*/
void Pq2OS(uint8_t *os, Pq f, int d)
{
	int i, j, index, p;

	p = 0;
	for(index = NTERM(d) - 1; index >= 0; index--){
		i = exp_table[index].i;
		j = exp_table[index].j;
		Rq2OS(&os[p], f[i][j]);
		p += RQ_SIZE;
	}
}


/**
	Rl: convert octet string to Rl

	@param[out] f
	@param[in] os
*/
void OS2Rl(Rq f, uint8_t *os)
{
	int i;

	for(i = 0; i < N / 4; i++){
		f[4 * i + 0] = os[i] >> 6 & 3;
		f[4 * i + 1] = os[i] >> 4 & 3;
		f[4 * i + 2] = os[i] >> 2 & 3;
		f[4 * i + 3] = os[i] >> 0 & 3;
	}

#if N % 4 == 1
	f[N - 1] = os[N / 4] >> 6 & 3;
#elif N % 4 == 2
	f[N - 2] = os[N / 4] >> 6 & 3;
	f[N - 1] = os[N / 4] >> 4 & 3;
#elif N % 4 == 3
	f[N - 3] = os[N / 4] >> 6 & 3;
	f[N - 2] = os[N / 4] >> 4 & 3;
	f[N - 1] = os[N / 4] >> 2 & 3;
#endif
}


/**
	Rq: convert octet string to Rq

	@param[out] f
	@param[in] os
*/
void OS2Rq(Rq f, uint8_t *os)
{
	Fq t;
	int i, p;

	p = 0;
	for(i = 0; i < N; i++){
		t = 0;
		memcpy(&t, &os[p], Q_SIZE);
		f[i] = t;
		p += Q_SIZE;
	}
}


/**
	Pq: convert octet string to Pq

	@param[out] f
	@param[in] d
	@param[in] os
*/
void OS2Pq(Pq f, int d, uint8_t *os)
{
	int i, j, index, p;
	
	p = 0;
	for(index = NTERM(d) - 1; index >= 0; index--){
		i = exp_table[index].i;
		j = exp_table[index].j;
		OS2Rq(f[i][j], &os[p]);
		p += RQ_SIZE;
	}
}
