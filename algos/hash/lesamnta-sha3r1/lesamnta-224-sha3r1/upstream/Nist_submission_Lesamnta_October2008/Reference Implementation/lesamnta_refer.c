/* 
 * lesamnta_refer.c
 *
 * Copyright (C) 2008 Hitachi, Ltd., All rights reserved.
 * Systems Development Laboratory, Hitachi, Ltd.
 */

#include <string.h>  /* for memset(), memcopy() */
#include "lesamnta_refer.h"

#define Nr_comp256 32    /* Number of rounds for Lesamnta-256 Compression function */
#define Nr_out256  32    /* Number of rounds for Lesamnta-256 Output function */
#define Nr_comp512 32    /* Number of rounds for Lesamnta-512 Compression function */
#define Nr_out512  32    /* Number of rounds for Lesamnta-512 Output function */

#define POLYNOMIAL 0x1B  /* Lower 8 bits value of the polynomial x^8 + x^4 + x^3 + x + 1 */

# define BYTES_SWAP32(x)\
	((x << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | (x >> 24))

# define BYTES_SWAP64(x)\
	(((u64)(BYTES_SWAP32((u32)(x))) << 32) | (u64)(BYTES_SWAP32((u32)((x) >> 32))))

/* BYTES_SWAP256(x) stores each 32-bit word of 256 bits data in little-endian convention */
#define BYTES_SWAP256(x) { \
	int _i = 8; while(_i--){x[_i] = BYTES_SWAP32(x[_i]);} \
}

/* BYTES_SWAP512(x) stores each 64-bit word of 512 bits data in little-endian convention */
#define BYTES_SWAP512(x) { \
	int _i = 8; while(_i--){x[_i] = BYTES_SWAP64(x[_i]);} \
}

#define ST224(x) (x->state.state256)
#define ST256(x) (x->state.state256)
#define ST384(x) (x->state.state512)
#define ST512(x) (x->state.state512)

HashReturn Init256(hashState *state);
HashReturn Update256(hashState *state, const BitSequence *data, Datalength databitlen);
HashReturn Final256(hashState *state, BitSequence *hashval);

HashReturn Init512(hashState *state);
HashReturn Update512(hashState *state, const BitSequence *data, Datalength databitlen);
HashReturn Final512(hashState *state, BitSequence *hashval);

HashReturn Init224(hashState *state);
HashReturn Update224(hashState *state, const BitSequence *data, Datalength databitlen);
HashReturn Final224(hashState *state, BitSequence *hashval);

HashReturn Init384(hashState *state);
HashReturn Update384(hashState *state, const BitSequence *data, Datalength databitlen);
HashReturn Final384(hashState *state, BitSequence *hashval);

static void Output256(u32 *chain, const u32 *mb);
static void Compression256(u32 *chain, const u32 *mb);
static void AddRoundKey256(u32 *substate256, u32 *K);
static void SubBytes256(u8 *substate256);
static void ShiftRows256(u8 *substate256);
static void MixColumns256(u8 *substate256);
static void WordRotation256(u32 *state);
static void KeyExpComp256(u32 *chain, u32 K[][2]);
static void KeyExpOut256(u32 *chain, u32 K[][2]);
static void SubWords256(u8 *s);
static void KeyLinear256(u8 *s);
static void ByteTranspos256(u8 *s);

static void Output512(u64 *chain, const u64 *mb);
static void Compression512(u64 *chain, const u64 *mb);
static void AddRoundKey512(u64 *substate512, u64 *K);
static void SubBytes512(u8 *substate512);
static void ShiftRows512(u8 *substate512);
static void MixColumns512(u8 *substate512);
static void WordRotation512(u64 *state);
static void KeyExpComp512(u64 *chain, u64 K[][2]);
static void KeyExpOut512(u64 *chain, u64 K[][2]);
static void SubWords512(u8 *s);
static void KeyLinear512(u8 *s);
static void ByteTranspos512(u8 *s);

static u8 mul(u8 x, u8 y);
static u8 mul2(u8 s);


/* Initial hash velue of Lesamnta-224 */
static const u32 H_init224[8] = {
	0x00000224, 0x00000224, 0x00000224, 0x00000224, 
	0x00000224, 0x00000224, 0x00000224, 0x00000224
};

/* Initial hash velue of Lesamnta-256 */
static const u32 H_init256[8] = {
	0x00000256, 0x00000256, 0x00000256, 0x00000256, 
	0x00000256, 0x00000256, 0x00000256, 0x00000256
};

/* Initial hash velue of Lesamnta-384 */
static const u64 H_init384[8] = {
	0x0000000000000384LL, 0x0000000000000384LL, 0x0000000000000384LL, 0x0000000000000384LL, 
	0x0000000000000384LL, 0x0000000000000384LL, 0x0000000000000384LL, 0x0000000000000384LL
};

/* Initial hash velue of Lesamnta-512 */
static const u64 H_init512[8] = {
	0x0000000000000512LL, 0x0000000000000512LL, 0x0000000000000512LL, 0x0000000000000512LL, 
	0x0000000000000512LL, 0x0000000000000512LL, 0x0000000000000512LL, 0x0000000000000512LL
};

static const u8 Sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const u32 C256[32][2] = {
    {0x00000001, 0x00000000}, {0x00000003, 0x00000002}, {0x00000005, 0x00000004}, {0x00000007, 0x00000006},
    {0x00000009, 0x00000008}, {0x0000000b, 0x0000000a}, {0x0000000d, 0x0000000c}, {0x0000000f, 0x0000000e},
    {0x00000011, 0x00000010}, {0x00000013, 0x00000012}, {0x00000015, 0x00000014}, {0x00000017, 0x00000016},
    {0x00000019, 0x00000018}, {0x0000001b, 0x0000001a}, {0x0000001d, 0x0000001c}, {0x0000001f, 0x0000001e},
    {0x00000021, 0x00000020}, {0x00000023, 0x00000022}, {0x00000025, 0x00000024}, {0x00000027, 0x00000026},
    {0x00000029, 0x00000028}, {0x0000002b, 0x0000002a}, {0x0000002d, 0x0000002c}, {0x0000002f, 0x0000002e},
    {0x00000031, 0x00000030}, {0x00000033, 0x00000032}, {0x00000035, 0x00000034}, {0x00000037, 0x00000036},
    {0x00000039, 0x00000038}, {0x0000003b, 0x0000003a}, {0x0000003d, 0x0000003c}, {0x0000003f, 0x0000003e}
};

static const u64 C512[32][2] = {
    {0x0000000000000001LL, 0x0000000000000000LL}, {0x0000000000000003LL, 0x0000000000000002LL},
    {0x0000000000000005LL, 0x0000000000000004LL}, {0x0000000000000007LL, 0x0000000000000006LL},
    {0x0000000000000009LL, 0x0000000000000008LL}, {0x000000000000000bLL, 0x000000000000000aLL},
    {0x000000000000000dLL, 0x000000000000000cLL}, {0x000000000000000fLL, 0x000000000000000eLL},
    {0x0000000000000011LL, 0x0000000000000010LL}, {0x0000000000000013LL, 0x0000000000000012LL},
    {0x0000000000000015LL, 0x0000000000000014LL}, {0x0000000000000017LL, 0x0000000000000016LL},
    {0x0000000000000019LL, 0x0000000000000018LL}, {0x000000000000001bLL, 0x000000000000001aLL},
    {0x000000000000001dLL, 0x000000000000001cLL}, {0x000000000000001fLL, 0x000000000000001eLL},
    {0x0000000000000021LL, 0x0000000000000020LL}, {0x0000000000000023LL, 0x0000000000000022LL},
    {0x0000000000000025LL, 0x0000000000000024LL}, {0x0000000000000027LL, 0x0000000000000026LL},
    {0x0000000000000029LL, 0x0000000000000028LL}, {0x000000000000002bLL, 0x000000000000002aLL},
    {0x000000000000002dLL, 0x000000000000002cLL}, {0x000000000000002fLL, 0x000000000000002eLL},
    {0x0000000000000031LL, 0x0000000000000030LL}, {0x0000000000000033LL, 0x0000000000000032LL},
    {0x0000000000000035LL, 0x0000000000000034LL}, {0x0000000000000037LL, 0x0000000000000036LL},
    {0x0000000000000039LL, 0x0000000000000038LL}, {0x000000000000003bLL, 0x000000000000003aLL},
    {0x000000000000003dLL, 0x000000000000003cLL}, {0x000000000000003fLL, 0x000000000000003eLL}
};

HashReturn Init256(hashState *state)
{
	ST256(state).bitlen[0] = 0;
	ST256(state).bitlen[1] = 0;

	ST256(state).rembitlen = 0;

	memset(ST256(state).buffer, 0, sizeof(ST256(state).buffer));
	memcpy(ST256(state).hash, H_init256, sizeof(ST256(state).hash));

	return SUCCESS;
}

HashReturn Update256(hashState *state, const BitSequence *data, Datalength databitlen)
{
	u8 *p = (u8*)ST256(state).buffer;
	u32 cpylen;
	u32 len;

	if ((ST256(state).bitlen[1] += (u32)databitlen) < (u32)databitlen) {
		ST256(state).bitlen[0] +=1;
	}
	ST256(state).bitlen[0] += (u32)(databitlen >> 32);

	if (ST256(state).rembitlen + databitlen >= LESAMNTA256_BLOCK_BIT_LEN) {
		cpylen = LESAMNTA256_BLOCK_LEN - (ST256(state).rembitlen >> 3);

		memcpy(p + (ST256(state).rembitlen >> 3), data, cpylen);

		BYTES_SWAP256(ST256(state).buffer);

		Compression256(ST256(state).hash, ST256(state).buffer);

		databitlen -= (cpylen << 3);
		data += cpylen;
		ST256(state).rembitlen = 0;

		while (databitlen >= LESAMNTA256_BLOCK_BIT_LEN) {
			memcpy(p, data, LESAMNTA256_BLOCK_LEN);

			BYTES_SWAP256(ST256(state).buffer);

			Compression256(ST256(state).hash, ST256(state).buffer);

			databitlen -= LESAMNTA256_BLOCK_BIT_LEN;
			data += LESAMNTA256_BLOCK_LEN;
		}
	}

	/* All remaining data copy to buffer */
	if (databitlen) {
		len = databitlen >> 3;
		if (databitlen % 8 != 0) {
			len += 1;
		}

		memcpy(p + (ST256(state).rembitlen >> 3), data, len);
		ST256(state).rembitlen += databitlen;
	}

	return SUCCESS;
}

HashReturn Final256(hashState *state, BitSequence *hashval)
{
	u8 *p = (u8*)ST256(state).buffer;
	int bytePos;
	int bitPos;

	/* Get the byte position in which padding is needed */
	bytePos = ST256(state).rembitlen >> 3;

	/* Get the bit position in which last 1-bit data is stored */
	bitPos = (ST256(state).rembitlen % 8);

	if (bitPos == 0) {
		/* Concatenate with a single 1 bit and zero bits */
		p[bytePos] = 0x80;
	} else {
		/* Mask for the upper n bits (n = bitPos) */
		p[bytePos] &= (0xff << (8 - bitPos));

		/* Concatenate with a single 1 bit and zero bits */
		p[bytePos] |= (0x80 >> bitPos);
	}

	/* Concatenate with zero bits */
	memset(&p[bytePos + 1], 0, LESAMNTA256_BLOCK_LEN - (bytePos + 1));

	/* If data bit length is not a multiple of 256 bits */
	if (ST256(state).rembitlen != 0) {
		BYTES_SWAP256(ST256(state).buffer);

		Compression256(ST256(state).hash, ST256(state).buffer);

		memset(p, 0, LESAMNTA256_BLOCK_LEN);
	}

	BYTES_SWAP256(ST256(state).buffer);

	/* Store the data bit length in lower 64 bits of a 256-bit data block */
	ST256(state).buffer[6] = ST256(state).bitlen[0];
	ST256(state).buffer[7] = ST256(state).bitlen[1];

	Output256(ST256(state).hash, ST256(state).buffer);

	BYTES_SWAP256(ST256(state).hash);

	memcpy(hashval, &ST256(state).hash, state->hashbitlen >> 3);

	return SUCCESS;
}

HashReturn Init512(hashState *state)
{
	ST512(state).bitlen[0] = 0;
	ST512(state).bitlen[1] = 0;

	ST512(state).rembitlen = 0;

	memset(ST512(state).buffer, 0, sizeof(ST512(state).buffer));
	memcpy(ST512(state).hash, H_init512, sizeof(ST512(state).hash));

	return SUCCESS;
}

HashReturn Update512(hashState *state, const BitSequence *data, Datalength databitlen)
{
	u8 *p =(u8*) ST512(state).buffer;
	u32 cpylen;
	u64 len;

	if ((ST512(state).bitlen[1] += databitlen) < databitlen) {
		ST512(state).bitlen[0] += 1;
	}

	if ( ST512(state).rembitlen + databitlen >= LESAMNTA512_BLOCK_BIT_LEN) {
		cpylen = LESAMNTA512_BLOCK_LEN - (ST512(state).rembitlen >> 3);

		memcpy(p + (ST512(state).rembitlen >> 3), data, cpylen);

		BYTES_SWAP512(ST512(state).buffer);

		Compression512(ST512(state).hash, ST512(state).buffer);

		databitlen -= (cpylen << 3);
		data += cpylen;
		ST512(state).rembitlen = 0;

		while (databitlen >= LESAMNTA512_BLOCK_BIT_LEN) {
			memcpy(p, data, LESAMNTA512_BLOCK_LEN);

			BYTES_SWAP512(ST512(state).buffer);

			Compression512(ST512(state).hash, ST512(state).buffer);

			databitlen -= LESAMNTA512_BLOCK_BIT_LEN;
			data += LESAMNTA512_BLOCK_LEN;
		}
	}

	/* All remaining data copy to buffer */
	if (databitlen) {
		len = databitlen >> 3;
		if (databitlen % 8 != 0) {
			len += 1;
		}

		memcpy(p + (ST512(state).rembitlen >> 3), data, len);
		ST512(state).rembitlen += databitlen;
	}

	return SUCCESS;
}

HashReturn Final512(hashState *state, BitSequence *hashval)
{
	u8 *p = (u8*)ST512(state).buffer;
	int bytePos;
	int bitPos;

	/* Get the byte position in which padding is needed */
	bytePos = (ST512(state).rembitlen) >> 3;

	/* Get the bit position in which last 1-bit data is stored */
	bitPos = ST512(state).rembitlen % 8;

	if (bitPos == 0) {
		/* Concatenate with a single 1 bit and zero bits */
		p[bytePos] = 0x80;
	} else {
		/* Mask for the upper n bits (n = bitPos) */
		p[bytePos] &= (0xff << (8 - bitPos));

		/* Concatenate with a single 1 bit and zero bits */
		p[bytePos] |= (0x80 >> bitPos);
	}

	/* Concatenate with zero bits */
	memset(&p[bytePos + 1], 0, LESAMNTA512_BLOCK_LEN - (bytePos + 1));

	/* If data bit length is not a multiple of 512 bits */
	if (ST512(state).rembitlen != 0) {
		BYTES_SWAP512(ST512(state).buffer);

		Compression512(ST512(state).hash, ST512(state).buffer);

		memset(p, 0, LESAMNTA512_BLOCK_LEN);
	} 		

	BYTES_SWAP512(ST512(state).buffer);

	/* Store the data bit length in lower 128 bits of a 512-bit data block */
	ST512(state).buffer[6] = ST512(state).bitlen[0];
	ST512(state).buffer[7] = ST512(state).bitlen[1];

	Output512(ST512(state).hash, ST512(state).buffer);

	BYTES_SWAP512(ST512(state).hash);

	memcpy(hashval, &ST512(state).hash, state->hashbitlen >> 3);

	return SUCCESS;
}

HashReturn Init224(hashState *state)
{
	ST224(state).bitlen[0] = 0;
	ST224(state).bitlen[1] = 0;

	ST224(state).rembitlen = 0;

	memset(ST224(state).buffer, 0, sizeof(ST224(state).buffer));
	memcpy(ST224(state).hash, H_init224, sizeof(ST224(state).hash));

	return SUCCESS;
}

HashReturn Update224(hashState *state, const BitSequence *data, Datalength databitlen)
{
	return  Update256(state, data, databitlen);
}

HashReturn Final224(hashState *state, BitSequence *hashval)
{
	return  Final256(state, hashval);
}

HashReturn Init384(hashState *state)
{
	ST384(state).bitlen[0] = 0;
	ST384(state).bitlen[1] = 0;

	ST384(state).rembitlen = 0;

	memset(ST384(state).buffer, 0, sizeof(ST384(state).buffer));
	memcpy(ST384(state).hash, H_init384, sizeof(ST384(state).hash));

	return SUCCESS;
}

HashReturn Update384(hashState *state, const BitSequence *data, Datalength databitlen)
{
	return  Update512(state, data, databitlen); 
}

HashReturn Final384(hashState *state, BitSequence *hashval) 
{
	return  Final512(state, hashval); 
}

HashReturn Hash(int hashbitlen, const BitSequence *data, Datalength databitlen, BitSequence *hashval) 
{
	hashState state;
	HashReturn ret;

	ret = Init(&state, hashbitlen);
	if (ret != SUCCESS) {
		return ret;
	}

	ret = Update(&state, data, databitlen);
	if (ret != SUCCESS) {
		return ret;
	}

	ret = Final(&state, hashval);
	if (ret != SUCCESS) {
		return ret;
	}
	return SUCCESS;
}

HashReturn Init(hashState *state, int hashbitlen) 
{
	HashReturn ret = FAIL;

	state->hashbitlen = hashbitlen;

	switch(hashbitlen) {
		case LESAMNTA224_DIGEST_BIT_LEN:
			ret = Init224(state);
			break;
		case LESAMNTA256_DIGEST_BIT_LEN:
			ret = Init256(state);
			break;
		case LESAMNTA384_DIGEST_BIT_LEN:
			ret = Init384(state);
			break;
		case LESAMNTA512_DIGEST_BIT_LEN:
			ret = Init512(state);
			break;
		default:
			ret = BAD_HASHBITLEN;
			break;
	}

	return ret;
}

HashReturn Update(hashState *state, const BitSequence *data, Datalength databitlen) 
{
	HashReturn ret = FAIL;

	switch(state->hashbitlen) {
		case LESAMNTA224_DIGEST_BIT_LEN:
			ret = Update224(state, data, databitlen);
			break;
		case LESAMNTA256_DIGEST_BIT_LEN:
			ret = Update256(state, data, databitlen);
			break;
		case LESAMNTA384_DIGEST_BIT_LEN:
			ret = Update384(state, data, databitlen);
			break;
		case LESAMNTA512_DIGEST_BIT_LEN:
			ret = Update512(state, data, databitlen);
			break;
		default:
			ret = BAD_HASHBITLEN;
			break;
	}

	return ret;
}

HashReturn Final(hashState *state, BitSequence *hashval) 
{
	HashReturn ret = FAIL;

	switch(state->hashbitlen) {
		case LESAMNTA224_DIGEST_BIT_LEN:
			ret = Final224(state, hashval);
			break;
		case LESAMNTA256_DIGEST_BIT_LEN:
			ret = Final256(state, hashval);
			break;
		case LESAMNTA384_DIGEST_BIT_LEN:
			ret = Final384(state, hashval);
			break;
		case LESAMNTA512_DIGEST_BIT_LEN:
			ret = Final512(state, hashval);
			break;
		default:
			ret = BAD_HASHBITLEN;
			break;
	}

	return ret;
}

static void Compression256(u32 *chain, const u32 *mb)
{
	u32 K[Nr_comp256][2];
	u32 x[8];
	u32 substate256[2];
	int j, round, iteration;

	KeyExpComp256(chain, K);

	for (j = 0; j < 8; j++) {
		x[j] = mb[j];
	}

	for (round = 0; round < Nr_comp256; round++) {
		substate256[0] = x[4];
		substate256[1] = x[5];

		AddRoundKey256(substate256, K[round]);

		substate256[0] = BYTES_SWAP32(substate256[0]);
		substate256[1] = BYTES_SWAP32(substate256[1]);

		for (iteration = 0; iteration < 4; iteration++) {
			SubBytes256((u8*)substate256);
			ShiftRows256((u8*)substate256);
			MixColumns256((u8*)substate256);
		}

		substate256[0] = BYTES_SWAP32(substate256[0]);
		substate256[1] = BYTES_SWAP32(substate256[1]);

		x[6] ^= substate256[0];
		x[7] ^= substate256[1];

		WordRotation256(x);
	}

	for (j = 0; j < 8; j++) {
		chain[j] = x[j] ^ mb[j];
	}
}

static void Output256(u32 *chain, const u32 *mb)
{
	u32 K[Nr_out256][2];
	u32 x[8];
	u32 substate256[2];
	int j, round, iteration;

	KeyExpOut256(chain, K);

	for (j = 0; j < 8; j++) {
		x[j] = mb[j];
	}

	for (round = 0; round < Nr_out256; round++) {
		substate256[0] = x[4];
		substate256[1] = x[5];

		AddRoundKey256(substate256, K[round]);

		substate256[0] = BYTES_SWAP32(substate256[0]);
		substate256[1] = BYTES_SWAP32(substate256[1]);

		for (iteration = 0; iteration < 4; iteration++) {
			SubBytes256((u8*)substate256);
			ShiftRows256((u8*)substate256);
			MixColumns256((u8*)substate256);
		}

		substate256[0] = BYTES_SWAP32(substate256[0]);
		substate256[1] = BYTES_SWAP32(substate256[1]);

		x[6] ^= substate256[0];
		x[7] ^= substate256[1];

		WordRotation256(x);
	}

	for (j = 0; j < 8; j++) {
		chain[j] = x[j] ^ mb[j];
	}
}

static void WordRotation256(u32 *state)
{
	u32 tmp[2];

	tmp[0] = state[6];
	tmp[1] = state[7];
	state[7] = state[5];
	state[6] = state[4];
	state[5] = state[3];
	state[4] = state[2];
	state[3] = state[1];
	state[2] = state[0];
	state[1] = tmp[1];
	state[0] = tmp[0];
}

static void AddRoundKey256(u32 *substate256, u32 *K)
{
	substate256[0] ^= K[0];
	substate256[1] ^= K[1];
}

static void SubBytes256(u8 *substate256)
{
	int i;

	for (i = 0; i < 8; i++) {
		substate256[i] = Sbox[substate256[i]];
	}
}

static void ShiftRows256(u8 *substate256)
{
	int i;
	u8 tmp[8];
	u8 indx[8] = { 0, 3, 2, 5, 4, 7, 6, 1 };

	for (i = 0; i < 8; i++) {
		tmp[i] = substate256[indx[i]];
	}

	for (i = 0; i < 8; i++) {
		substate256[i] = tmp[i];
	}
}

static void MixColumns256(u8* substate256) 
{
	u8 tmp[2]; 
	u8 *p; 
	int i;

	p = substate256;

	for (i = 0; i < 4; i++) {
		tmp[0] = mul(p[0], 0x02) ^ mul(p[1], 0x01);
		tmp[1] = mul(p[0], 0x01) ^ mul(p[1], 0x02);

		p[0] = tmp[0];
		p[1] = tmp[1];
		p += 2;
	}
}

static void KeyExpComp256(u32 *chain, u32 K[][2])
{
	u32 t[2];
	int round;

	for (round = 0; round < Nr_comp256; round++) {
		t[0] = chain[4] ^ C256[round][0];
		t[1] = chain[5] ^ C256[round][1];

		t[0] = BYTES_SWAP32(t[0]);
		t[1] = BYTES_SWAP32(t[1]);

		SubWords256((u8*)t);
		KeyLinear256((u8*)t);
		ByteTranspos256((u8*)t);

		t[0] = BYTES_SWAP32(t[0]);
		t[1] = BYTES_SWAP32(t[1]);

		chain[6] ^= t[0];
		chain[7] ^= t[1];

		WordRotation256(chain);

		K[round][0] = chain[2];
		K[round][1] = chain[3];
	}
}

static void KeyExpOut256(u32 *chain, u32 K[][2])
{
	u32 substate256[2];
	int round, iteration;

	for (round = 0; round < Nr_out256; round++) {
		substate256[0] = chain[4] ^ C256[round][0];
		substate256[1] = chain[5] ^ C256[round][1];

		substate256[0] = BYTES_SWAP32(substate256[0]);
		substate256[1] = BYTES_SWAP32(substate256[1]);

		for (iteration = 0; iteration < 4; iteration++) {
			SubBytes256((u8*)substate256);
			ShiftRows256((u8*)substate256);
			MixColumns256((u8*)substate256);
		}

		substate256[0] = BYTES_SWAP32(substate256[0]);
		substate256[1] = BYTES_SWAP32(substate256[1]);

		chain[6] ^= substate256[0];
		chain[7] ^= substate256[1];

		WordRotation256(chain);

		K[round][0] = chain[2];
		K[round][1] = chain[3];
	}
}

static void SubWords256(u8 *s)
{
	int i;

	for (i = 0; i < 8; i++) {
		s[i] = Sbox[s[i]];
	}
}

static void KeyLinear256(u8 *s) 
{
	u8 tmp[4]; 
	u8 *p; 
	int i;

	p = s;

	for (i = 0; i < 2; i++) {
		tmp[0] = mul(p[0], 0x02) ^ mul(p[1], 0x03) ^ mul(p[2], 0x01) ^ mul(p[3], 0x01);
		tmp[1] = mul(p[0], 0x01) ^ mul(p[1], 0x02) ^ mul(p[2], 0x03) ^ mul(p[3], 0x01);
		tmp[2] = mul(p[0], 0x01) ^ mul(p[1], 0x01) ^ mul(p[2], 0x02) ^ mul(p[3], 0x03);
		tmp[3] = mul(p[0], 0x03) ^ mul(p[1], 0x01) ^ mul(p[2], 0x01) ^ mul(p[3], 0x02);

		p[0] = tmp[0];
		p[1] = tmp[1];
		p[2] = tmp[2];
		p[3] = tmp[3];
		p += 4;
	}
}

static void ByteTranspos256(u8 *s)
{
	u8 tmp[8];
	u8 indx[8] = { 4, 5, 2, 3, 0, 1, 6, 7 };
	int i;

	for (i = 0; i < 8; i++) {
		tmp[i] = s[indx[i]];
	}

	for (i = 0; i < 8; i++) {
		s[i] = tmp[i];
	}
}

static void Compression512(u64 *chain, const u64 *mb)
{
	u64 K[Nr_comp512][2];
	u64 x[8];
	u64 substate512[2];
	int j, round, iteration;

	KeyExpComp512(chain, K);

	for (j = 0; j < 8; j++) {
		x[j] = mb[j];
	}

	for (round = 0; round < Nr_comp512; round++) {
		substate512[0] = x[4];
		substate512[1] = x[5];

		AddRoundKey512(substate512, K[round]);

		substate512[0] = BYTES_SWAP64(substate512[0]);
		substate512[1] = BYTES_SWAP64(substate512[1]);

		for (iteration = 0; iteration < 4; iteration++) {
			SubBytes512((u8*)substate512);
			ShiftRows512((u8*)substate512);
			MixColumns512((u8*)substate512);
		}

		substate512[0] = BYTES_SWAP64(substate512[0]);
		substate512[1] = BYTES_SWAP64(substate512[1]);

		x[6] ^= substate512[0];
		x[7] ^= substate512[1];

		WordRotation512(x);
	}

	for (j = 0; j < 8; j++) {
		chain[j] = x[j] ^ mb[j];
	}
}

static void Output512(u64 *chain, const u64 *mb)
{
	u64 K[Nr_out512][2];
	u64 x[8];
	u64 substate512[2];
	int j, round, iteration;

	KeyExpOut512(chain, K);

	for (j = 0; j < 8; j++) {
		x[j] = mb[j];
	}

	for (round = 0; round < Nr_out512; round++) {
		substate512[0] = x[4];
		substate512[1] = x[5];

		AddRoundKey512(substate512, K[round]);

		substate512[0] = BYTES_SWAP64(substate512[0]);
		substate512[1] = BYTES_SWAP64(substate512[1]);

		for (iteration = 0; iteration < 4; iteration++) {
			SubBytes512((u8*)substate512);
			ShiftRows512((u8*)substate512);
			MixColumns512((u8*)substate512);
		}

		substate512[0] = BYTES_SWAP64(substate512[0]);
		substate512[1] = BYTES_SWAP64(substate512[1]);

		x[6] ^= substate512[0];
		x[7] ^= substate512[1];

		WordRotation512(x);
	}

	for (j = 0; j < 8; j++) {
		chain[j] = x[j] ^ mb[j];
	}
}

static void WordRotation512(u64 *state)
{
	u64 tmp[2];

	tmp[0] = state[6];
	tmp[1] = state[7];
	state[7] = state[5];
	state[6] = state[4];
	state[5] = state[3];
	state[4] = state[2];
	state[3] = state[1];
	state[2] = state[0];
	state[1] = tmp[1];
	state[0] = tmp[0];
}

static void AddRoundKey512(u64 *substate512, u64 *K)
{
	substate512[0] ^= K[0];
	substate512[1] ^= K[1];
}

static void SubBytes512(u8 *substate512)
{
	int i;

	for (i = 0; i < 16; i++) {
		substate512[i] = Sbox[substate512[i]];
	}
}

static void ShiftRows512(u8 *substate512)
{
	u8 tmp[16];
	u8 indx[16] = { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 };
	int i;

	for (i = 0; i < 16; i++) {
		tmp[i] = substate512[indx[i]];
	}

	for (i = 0; i < 16; i++) {
		substate512[i] = tmp[i];
	}
}

static void MixColumns512(u8 *substate512)
{
	u8 tmp[4];
	u8 *p;
	int i;

	p = substate512;

	for (i = 0; i < 4; i++) {
		tmp[0] = mul(p[0], 0x02) ^ mul(p[1], 0x03) ^ mul(p[2], 0x01) ^ mul(p[3], 0x01);
		tmp[1] = mul(p[0], 0x01) ^ mul(p[1], 0x02) ^ mul(p[2], 0x03) ^ mul(p[3], 0x01);
		tmp[2] = mul(p[0], 0x01) ^ mul(p[1], 0x01) ^ mul(p[2], 0x02) ^ mul(p[3], 0x03);
		tmp[3] = mul(p[0], 0x03) ^ mul(p[1], 0x01) ^ mul(p[2], 0x01) ^ mul(p[3], 0x02);

		p[0] = tmp[0];
		p[1] = tmp[1];
		p[2] = tmp[2];
		p[3] = tmp[3];
		p += 4;
	}
}

static void KeyExpComp512(u64 *chain, u64 K[][2])
{
	u64 t[2];
	int round;

	for (round = 0; round < Nr_comp512; round++) {
		t[0] = chain[4] ^ C512[round][0];
		t[1] = chain[5] ^ C512[round][1];

		t[0] = BYTES_SWAP64(t[0]);
		t[1] = BYTES_SWAP64(t[1]);

		SubWords512((u8*)t);
		KeyLinear512((u8*)t);
		ByteTranspos512((u8*)t);

		t[0] = BYTES_SWAP64(t[0]);
		t[1] = BYTES_SWAP64(t[1]);

		chain[6] ^= t[0];
		chain[7] ^= t[1];

		WordRotation512(chain);

		K[round][0] = chain[2];
		K[round][1] = chain[3];
	}
}

static void KeyExpOut512(u64 *chain, u64 K[][2])
{
	u64 substate512[2];
	int round, iteration;

	for (round = 0; round < Nr_out512; round++) {
		substate512[0] = chain[4] ^ C512[round][0];
		substate512[1] = chain[5] ^ C512[round][1];

		substate512[0] = BYTES_SWAP64(substate512[0]);
		substate512[1] = BYTES_SWAP64(substate512[1]);

		for (iteration = 0; iteration < 4; iteration++) {
			SubBytes512((u8*)substate512);
			ShiftRows512((u8*)substate512);
			MixColumns512((u8*)substate512);
		}

		substate512[0] = BYTES_SWAP64(substate512[0]);
		substate512[1] = BYTES_SWAP64(substate512[1]);

		chain[6] ^= substate512[0];
		chain[7] ^= substate512[1];

		WordRotation512(chain);

		K[round][0] = chain[2];
		K[round][1] = chain[3];
	}
}

static void SubWords512(u8 *s)
{
	int i;

	for (i = 0; i < 16; i++) {
		s[i] = Sbox[s[i]];
	}
}

static void KeyLinear512(u8* s)
{
	u8 tmp[8];
	u8 *p;
	int i;

	p = s;

	for (i = 0; i < 2; i++) {
		tmp[0] = mul(p[0], 0x01) ^ mul(p[1], 0x01) ^ mul(p[2], 0x02) ^ mul(p[3], 0x0a) 
		       ^ mul(p[4], 0x09) ^ mul(p[5], 0x08) ^ mul(p[6], 0x01) ^ mul(p[7], 0x04);
		tmp[1] = mul(p[0], 0x04) ^ mul(p[1], 0x01) ^ mul(p[2], 0x01) ^ mul(p[3], 0x02) 
		       ^ mul(p[4], 0x0a) ^ mul(p[5], 0x09) ^ mul(p[6], 0x08) ^ mul(p[7], 0x01);
		tmp[2] = mul(p[0], 0x01) ^ mul(p[1], 0x04) ^ mul(p[2], 0x01) ^ mul(p[3], 0x01) 
		       ^ mul(p[4], 0x02) ^ mul(p[5], 0x0a) ^ mul(p[6], 0x09) ^ mul(p[7], 0x08);
		tmp[3] = mul(p[0], 0x08) ^ mul(p[1], 0x01) ^ mul(p[2], 0x04) ^ mul(p[3], 0x01) 
		       ^ mul(p[4], 0x01) ^ mul(p[5], 0x02) ^ mul(p[6], 0x0a) ^ mul(p[7], 0x09);
		tmp[4] = mul(p[0], 0x09) ^ mul(p[1], 0x08) ^ mul(p[2], 0x01) ^ mul(p[3], 0x04) 
		       ^ mul(p[4], 0x01) ^ mul(p[5], 0x01) ^ mul(p[6], 0x02) ^ mul(p[7], 0x0a);
		tmp[5] = mul(p[0], 0x0a) ^ mul(p[1], 0x09) ^ mul(p[2], 0x08) ^ mul(p[3], 0x01) 
		       ^ mul(p[4], 0x04) ^ mul(p[5], 0x01) ^ mul(p[6], 0x01) ^ mul(p[7], 0x02);
		tmp[6] = mul(p[0], 0x02) ^ mul(p[1], 0x0a) ^ mul(p[2], 0x09) ^ mul(p[3], 0x08) 
		       ^ mul(p[4], 0x01) ^ mul(p[5], 0x04) ^ mul(p[6], 0x01) ^ mul(p[7], 0x01);
		tmp[7] = mul(p[0], 0x01) ^ mul(p[1], 0x02) ^ mul(p[2], 0x0a) ^ mul(p[3], 0x09) 
		       ^ mul(p[4], 0x08) ^ mul(p[5], 0x01) ^ mul(p[6], 0x04) ^ mul(p[7], 0x01);

		p[0] = tmp[0];
		p[1] = tmp[1];
		p[2] = tmp[2];
		p[3] = tmp[3];
		p[4] = tmp[4];
		p[5] = tmp[5];
		p[6] = tmp[6];
		p[7] = tmp[7];
		p += 8;
	}
}

static void ByteTranspos512(u8 *s)
{
	u8 tmp[16];
	u8 indx[16] = { 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15 };
	int i;

	for (i = 0; i < 16; i++) {
		tmp[i] = s[indx[i]];
	}

	for (i = 0; i < 16; i++) {
		s[i] = tmp[i];
	}
}

/* 
 * Multiplication of parameters a and b.
 * Parameters a and b are binary polynomials of degree less than 8. 
 */
static u8 mul(u8 a, u8 b)
{
	u8 result = 0;

	while (b != 0) {
		if (b & 0x01) {
			result ^= a;
		}
		a = mul2(a);
		b >>= 1;
	}
	return result;
}

/*
 * Multiplication by the polynomial x (i.e. 0x02). 
 */
static u8 mul2(u8 s)
{
	if (s & 0x80) {
		s = s << 1;
		s ^= POLYNOMIAL;
	}
	else {
		s = s << 1;
	}
	return s;
}

