/*
	Giophantus public key cryptosystem

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#ifndef __PARAMETER_H__

// 128 bit security
#define N 1201
#define MLEN 16 // message length in bytes (same as security parameter)

// 192 bit security
//#define N 1733
//#define MLEN 24 // message length in bytes (same as security parameter)

// 256 bit security
//#define N 2267
//#define MLEN 32 // message length in bytes (same as security parameter)

#define Q 0x7fffffffu // 2^31 - 1
#define Q_SIZE 4

#define DX 1
#define DR 1
#define DC (DX + DR)

#define L 4
#define L_BIT 2

// size
#define NTERM(d) (((d) + 1) * ((d) + 2) / 2)
#define RQ_SIZE (N * Q_SIZE)
#define RL_SIZE ((N + 3) / 4) // Rl size in bytes (= ceiling(N / 4))
#define PQ_SIZE(d) (NTERM(d) * RQ_SIZE)

#define SK_SIZE (2 * RL_SIZE + PQ_SIZE(DX)) // modify
#define PK_SIZE PQ_SIZE(DX)
#define PAYLOAD_SIZE RL_SIZE
#define C_SIZE PQ_SIZE(DC)

#define SEED_SIZE (PQ_SIZE(DR) + NTERM(DC) * N) // random bytes using FO conversion

#endif
