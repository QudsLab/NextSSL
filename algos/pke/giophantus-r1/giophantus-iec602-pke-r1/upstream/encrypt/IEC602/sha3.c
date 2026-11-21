/*
	SHA3

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "sha3.h"

#define cast(type, value) ((type)(value))
#define rol64(x, n) ((x) << (n) | (x) >> (64 - (n)))


static void keccack_f1600(uint64_t a[25])
{
	static const uint64_t rc[24] = {
		0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull, 0x8000000080008000ull,
		0x000000000000808bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
		0x000000000000008aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
		0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull, 0x8000000000008003ull,
		0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800aull, 0x800000008000000aull,
		0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull,
	};
	uint64_t w[25], c[5], d[5];
	int round;

	for(round = 0; round < 24; round++){
		c[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
		c[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
		c[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
		c[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
		c[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

		d[0] = c[4] ^ rol64(c[1], 1);
		d[1] = c[0] ^ rol64(c[2], 1);
		d[2] = c[1] ^ rol64(c[3], 1);
		d[3] = c[2] ^ rol64(c[4], 1);
		d[4] = c[3] ^ rol64(c[0], 1);

		// pi(rho(theta()))
		w[0] = a[0] ^ d[0]; // rol64(a[0] ^ d[0], 0);
		w[10] = rol64(a[1] ^ d[1], 1);
		w[20] = rol64(a[2] ^ d[2], 62);
		w[5] = rol64(a[3] ^ d[3], 28);
		w[15] = rol64(a[4] ^ d[4], 27);
		w[16] = rol64(a[5] ^ d[0], 36);
		w[1] = rol64(a[6] ^ d[1], 44);
		w[11] = rol64(a[7] ^ d[2], 6);
		w[21] = rol64(a[8] ^ d[3], 55);
		w[6] = rol64(a[9] ^ d[4], 20);
		w[7] = rol64(a[10] ^ d[0], 3);
		w[17] = rol64(a[11] ^ d[1], 10);
		w[2] = rol64(a[12] ^ d[2], 43);
		w[12] = rol64(a[13] ^ d[3], 25);
		w[22] = rol64(a[14] ^ d[4], 39);
		w[23] = rol64(a[15] ^ d[0], 41);
		w[8] = rol64(a[16] ^ d[1], 45);
		w[18] = rol64(a[17] ^ d[2], 15);
		w[3] = rol64(a[18] ^ d[3], 21);
		w[13] = rol64(a[19] ^ d[4], 8);
		w[14] = rol64(a[20] ^ d[0], 18);
		w[24] = rol64(a[21] ^ d[1], 2);
		w[9] = rol64(a[22] ^ d[2], 61);
		w[19] = rol64(a[23] ^ d[3], 56);
		w[4] = rol64(a[24] ^ d[4], 14);

		// kai
		a[0] = w[0] ^ (~w[1] & w[2]);
		a[1] = w[1] ^ (~w[2] & w[3]);
		a[2] = w[2] ^ (~w[3] & w[4]);
		a[3] = w[3] ^ (~w[4] & w[0]);
		a[4] = w[4] ^ (~w[0] & w[1]);
		a[5] = w[5] ^ (~w[6] & w[7]);
		a[6] = w[6] ^ (~w[7] & w[8]);
		a[7] = w[7] ^ (~w[8] & w[9]);
		a[8] = w[8] ^ (~w[9] & w[5]);
		a[9] = w[9] ^ (~w[5] & w[6]);
		a[10] = w[10] ^ (~w[11] & w[12]);
		a[11] = w[11] ^ (~w[12] & w[13]);
		a[12] = w[12] ^ (~w[13] & w[14]);
		a[13] = w[13] ^ (~w[14] & w[10]);
		a[14] = w[14] ^ (~w[10] & w[11]);
		a[15] = w[15] ^ (~w[16] & w[17]);
		a[16] = w[16] ^ (~w[17] & w[18]);
		a[17] = w[17] ^ (~w[18] & w[19]);
		a[18] = w[18] ^ (~w[19] & w[15]);
		a[19] = w[19] ^ (~w[15] & w[16]);
		a[20] = w[20] ^ (~w[21] & w[22]);
		a[21] = w[21] ^ (~w[22] & w[23]);
		a[22] = w[22] ^ (~w[23] & w[24]);
		a[23] = w[23] ^ (~w[24] & w[20]);
		a[24] = w[24] ^ (~w[20] & w[21]);

		// iota
		a[0] ^= rc[round]; // iota
	}
}


void keccack(uint8_t *result, uint32_t resultlen, const uint8_t *data, uint32_t datalen, uint32_t rate, uint8_t padchar)
{
	uint64_t state[25];
	uint32_t i;

	// initialize
	memset(state, 0, sizeof(state));

	// absorbing
	while(datalen >= rate){
		for(i = 0; i < rate; i++) cast(uint8_t *, state)[i] ^= data[i];
		keccack_f1600(state);
		data += rate;
		datalen -= rate;
	}

	// absorbing : last block
	for(i = 0; i < datalen; i++) cast(uint8_t *, state)[i] ^= data[i];
	cast(uint8_t *, state)[datalen] ^= padchar;
	cast(uint8_t *, state)[rate - 1] ^= 0x80;
	keccack_f1600(state);

	// squeezing
	while(resultlen >= rate){
		memcpy(result, state, rate);
		result += rate;
		resultlen -= rate;
		keccack_f1600(state);
	}
	if(resultlen) memcpy(result, state, resultlen);
}
