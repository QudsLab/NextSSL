/* 
 * lesamnta_refer.h
 *
 * Copyright (C) 2008 Hitachi, Ltd., All rights reserved.
 * Systems Development Laboratory, Hitachi, Ltd.
 */

#ifndef _LESAMNTA_REFER_H_
#define _LESAMNTA_REFER_H_

/* LESAMNTA specific definitions. */
#define LESAMNTA256_BLOCK_BIT_LEN 256
#define LESAMNTA512_BLOCK_BIT_LEN 512
#define LESAMNTA256_BLOCK_LEN (LESAMNTA256_BLOCK_BIT_LEN >> 3) /* 32 bytes */
#define LESAMNTA512_BLOCK_LEN (LESAMNTA512_BLOCK_BIT_LEN >> 3) /* 64 bytes */

#define LESAMNTA224_DIGEST_BIT_LEN 224
#define LESAMNTA256_DIGEST_BIT_LEN 256
#define LESAMNTA384_DIGEST_BIT_LEN 384
#define LESAMNTA512_DIGEST_BIT_LEN 512

typedef unsigned char BitSequence;
typedef unsigned long long Datalength;

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;


typedef struct {
	u32 bitlen[2]; /* Message length in bits */
	u32 rembitlen; /* Length of buffer data to be hashed */
	u32 buffer[8]; /* Buffer to be hashed */
	u32 hash[8];   /* Hash state */
} hashState256;

typedef struct {
	u64 bitlen[2]; /* Message length in bits */
	u32 rembitlen; /* Length of buffer data to be hashed */
	u64 buffer[8]; /* Buffer to be hashed */
	u64 hash[8];   /* Hash state */
} hashState512;

typedef struct {
	int hashbitlen;
	union {
		hashState256 state256;
		hashState512 state512;
	} state;
} hashState;


HashReturn Init(hashState *state, int hashbitlen);
HashReturn Update(hashState *state, const BitSequence *data, Datalength databitlen);
HashReturn Final(hashState *state, BitSequence *hashval);
HashReturn Hash(int hashbitlen, const BitSequence *data, Datalength databitlen, BitSequence *hashval);


#endif /* _LESAMNTA_REFER_H_ */
