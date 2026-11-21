/*
	Giophantus public key cryptosystem

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#ifndef __IEC_H__

#include <stdint.h>
#include "parameter.h"

// constant

#define IEC_OK 0
#define IEC_NG 1

#define MAX_D (DX + DR)


// type

// Fq : Z/qZ
typedef uint32_t Fq;

// Rq: Fq[t] / (t^n - 1)
typedef Fq Rq[N];

// Pq(d): Rq[x, y] ... total degree d
typedef Rq Pq[MAX_D + 1][MAX_D + 1];


// macro
#define cast(type, value) ((type)(value))
#define POLYFOR(i, j, d) for(i = 0; i <= (d); i++) for(j = 0; j <= (d); j++) if(i + j <= (d))

// prototype

void iec_kg(Rq ux, Rq uy, Pq X);
void iec_enc(Pq c, Rq m, Pq X);
void iec_dec(Rq m, Pq c, Rq ux, Rq uy);

Fq Fq_add(Fq a, Fq b);
Fq Fq_sub(Fq a, Fq b);
Fq Fq_mul(Fq a, Fq b);

void Rq_clear(Rq a);
void Rq_add(Rq c, Rq a, Rq b);
void Rq_sub(Rq c, Rq a, Rq b);
void Rq_mul(Rq c, Rq a, Rq b);
void Rq_reduce(Rq a);

void Pq_add(Pq c, Pq a, Pq b, int d);
void Pq_mul(Pq c, Pq a, Pq b, int ad, int bd);
void Pq_smul(Pq a, int d);
void Pq_subst(Rq c, Pq f, Rq a, Rq b, int d);

Fq Fq_rand();
Fq Fl_rand();
void Rq_rand(Rq f);
void Rl_rand(Rq f);
void Pq_rand(Pq f, int d);
void Pl_rand(Pq f, int d);

void Rq2OS(uint8_t *os, Rq f);
void Rl2OS(uint8_t *os, Rq f);
void Pq2OS(uint8_t *os, Pq f, int d);
void Pl2OS(uint8_t *os, Pq f, int d);

void OS2Rq(Rq f, uint8_t *os);
void OS2Rl(Rq f, uint8_t *os);
void OS2Pq(Pq f, int d, uint8_t *os);
void OS2Pl(Pq f, int d, uint8_t *os);

#endif
