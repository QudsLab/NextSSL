#include "sarmal.h"
#include "sarmal-tables.h"

#include <string.h>

/* BSWAP: swaps bytes of 64-bit argument */
#define BSWAP(x) \
        (x) = (((x)&0xFF00FF00FF00FF00ull)>>8)|(((x)&0x00FF00FF00FF00FFull)<<8); \
        (x) = (((x)&0xFFFF0000FFFF0000ull)>>16)|(((x)&0x0000FFFF0000FFFFull)<<16); \
	(x) = ((x)>>32)|((x)<<32)

/* get byte macro: returns specified byte of 64-bit argument */
#define GET_BYTE(x,y) (unsigned char)((x)>>(8*(y)))

/* prototypes for G, g, Galois Field Multiplication functions */
int GFMultiply(int a, int b);
Bit64 g(const Bit64 in);
void G(const Bit64 *in1, const Bit64 in20, const Bit64 in21, const Bit64 in22, const Bit64 in23, Bit64 *out);

/* prototypes for helper functions */
void HashBlock(hashState *state);
void HashPad(hashState *state);

/* initialization function */
HashReturn Init(hashState *state, int hashbitlen)
{
	/* constants for Sarmal-224 */
	static Bit64 SARMAL_224_h[8] = { 0xBB67AE8584CAA73Bull, 0x25742D7078B83B89ull, 0x25D834CC53DA4798ull, 0xC720A6486E45A6E2ull, 0x490BCFD95EF15DBDull, 0xA9930AAE12228F87ull, 0xCC4CF24DA3A1EC68ull, 0xD0CD33A01AD9A383ull };
	static Bit64 SARMAL_224_c[2] = { 0xB9E122E6138C3AE6ull, 0xDE5EDE3BD42DB730ull };
	static Bit64 SARMAL_224_s[4] = { 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull };

	/* constants for Sarmal-256 */
	static Bit64 SARMAL_256_h[8] = { 0x9E3779B97F4A7C15ull, 0xF39CC0605CEDC834ull, 0x1082276BF3A27251ull, 0xF86C6A11D0C18E95ull, 0x2767F0B153D27B7Full, 0x0347045B5BF1827Full, 0x01886F0928403002ull, 0xC1D64BA40F335E36ull };
	static Bit64 SARMAL_256_c[2] = { 0xF06AD7AE9717877Eull, 0x85839D6EFFBD7DC6ull };
	static Bit64 SARMAL_256_s[4] = { 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull };

	/* constants for Sarmal-384 */
	static Bit64 SARMAL_384_h[8] = { 0x3C6EF372FE94F82Bull, 0xE73980C0B9DB9068ull, 0x21044ED7E744E4A3ull, 0xF0D8D423A1831D2Aull, 0x4ECFE162A7A4F6FEull, 0x068E08B6B7E304FEull, 0x0310DE1250806005ull, 0x83AC97481E66BC6Dull };
	static Bit64 SARMAL_384_c[2] = { 0xE0D5AF5D2E2F0EFDull, 0x0B073ADDFF7AFB8Cull };
	static Bit64 SARMAL_384_s[4] = { 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull };

	/* constants for Sarmal-512 */
	static Bit64 SARMAL_512_h[8] = { 0x243F6A8885A308D3ull, 0x13198A2E03707344ull, 0xA4093822299F31D0ull, 0x082EFA98EC4E6C89ull, 0x452821E638D01377ull, 0xBE5466CF34E90C6Cull, 0xC0AC29B7C97C50DDull, 0x3F84D5B5B5470917ull };
	static Bit64 SARMAL_512_c[2] = { 0x9216D5D98979FB1Bull,	0xD1310BA698DFB5ACull };
	static Bit64 SARMAL_512_s[4] = { 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull, 0x0000000000000000ull };

	/* check hashbitlen and initialize accordingly */
	switch(hashbitlen)
	{
		case 224:
			memcpy(state->h, SARMAL_224_h, sizeof(SARMAL_224_h));
			memcpy(state->c, SARMAL_224_c, sizeof(SARMAL_224_c));
			memcpy(state->s, SARMAL_224_s, sizeof(SARMAL_224_s));
			
			break;

		case 256:
			memcpy(state->h, SARMAL_256_h, sizeof(SARMAL_256_h));
			memcpy(state->c, SARMAL_256_c, sizeof(SARMAL_256_c));
			memcpy(state->s, SARMAL_256_s, sizeof(SARMAL_256_s));
			
			break;

		case 384:
			memcpy(state->h, SARMAL_384_h, sizeof(SARMAL_384_h));
			memcpy(state->c, SARMAL_384_c, sizeof(SARMAL_384_c));
			memcpy(state->s, SARMAL_384_s, sizeof(SARMAL_384_s));
			
			break;

		case 512:
			memcpy(state->h, SARMAL_512_h, sizeof(SARMAL_512_h));
			memcpy(state->c, SARMAL_512_c, sizeof(SARMAL_512_c));
			memcpy(state->s, SARMAL_512_s, sizeof(SARMAL_512_s));
			
			break;

		default:
			return BAD_HASHBITLEN;
	}

	state->t = 0;
	state->hashbitlen = hashbitlen;

	state->remainingbitlen = 0;
	
	return SUCCESS;
}

/* update function */
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
	int reqbitlen; /* number of bits required to obtain 1024-bit message block */
	int copybitlen; /* number of bits available for copying */ 

	if(state->remainingbitlen != 0)
	{	/* we have remaining data */
		reqbitlen = 1024 - state->remainingbitlen;
		copybitlen = (databitlen>=reqbitlen?reqbitlen:databitlen);
		
		/* append available bits to message block */
		memcpy(state->messageblock+(state->remainingbitlen/8), data, copybitlen/8 + (copybitlen%8?1:0));
		
		databitlen -= copybitlen;
		
		if(reqbitlen == copybitlen)
		{	/* we have 1024-bit message block, so hash it */
			HashBlock(state);
			state->remainingbitlen = 0;
			/* update data pointer */
			data += copybitlen/8 + (copybitlen%8?1:0);
		}
		else	/* update remaining bit count */
			state->remainingbitlen += copybitlen;
	}

	/* hash available data blocks */
	while(databitlen >= 1024)
	{
		memcpy(state->messageblock, data, 128);
		HashBlock(state);
		databitlen -= 1024;
		data += 128;
	}

	if(databitlen>0)
	{	/* we have remaining data, put it into message block for future processing */
		memcpy(state->messageblock, data, databitlen/8 + (databitlen%8?1:0));
		state->remainingbitlen = databitlen;
	}	

	return SUCCESS;
}

/* finalize and return hash value */
HashReturn Final(hashState *state, BitSequence *hashval)
{
	Bit64 h[8];	/* temporary space used for byte swapping */
	int i;

	/* perform padding operation */
	HashPad(state);

	/* swap bytes of chaining values */
	memcpy(h, state->h, 64);
	for(i=0; i<8; i++)
	{
		BSWAP(h[i]);
	}

	/* check hashbitlen and update return value accordingly */
	switch(state->hashbitlen)
	{
		case 224:
			/* rightmost 224 bits of chaining value */
			hashval[0] = (BitSequence)(state->h[4] >> 24);
			hashval[1] = (BitSequence)(state->h[4] >> 16);
			hashval[2] = (BitSequence)(state->h[4] >> 8);
			hashval[3] = (BitSequence)(state->h[4]);
			
			memcpy(hashval+4, h+5, 24);

			break;
		case 256:
			/* leftmost 256 bits of chaining value */
			memcpy(hashval, h, 32);

			break;
		case 384:
			/* leftmost 384 bits of chaining value */
			memcpy(hashval, h, 48);

			break;
		case 512:
			/* all 512 bits of chaining value */
			memcpy(hashval, h, 64);

			break;
	}

	return SUCCESS;
}

/* all-at-once processing */
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	hashState state;
	HashReturn res;
	res = Init(&state, hashbitlen); /* initialize */
	if(res != SUCCESS)
		return res;	/* init failed, return */
	res = Update(&state, data, databitlen); /* update */
	if(res != SUCCESS)
		return res;	/* update failed, return */
	return Final(&state, hashval); /* finalize and return result */
}

/* Galois Field Multiplication function 
   multiplies a and b in GF(2^8) */
int GFMultiply(int a, int b)
{
        if((a == 0)||(b == 0))
		return 0;
        else
		return (GFALOG[(GFLOG[a] + GFLOG[b]) % 255]);
}

/* hashes 1024-bit block of message */
void HashBlock(hashState *state)
{
	Bit64 leftTemp1[8], leftTemp2[8];	/* 512-bit temporary storage for left branch */
	Bit64 rightTemp1[8], rightTemp2[8];	/* 512-bit temporary storage for right branch */
	Bit64 m[16];				/* 1024-bit temporary storage for message block */

	int i;

	/* get 1024-bit message and swap its bytes */
	memcpy(m, state->messageblock, 128);
	for(i=0; i<16; i++)
	{
		BSWAP(m[i]);
	}
	
	/* initialize left branch */
	leftTemp1[0] = state->h[0];
	leftTemp1[1] = state->h[1];
	leftTemp1[2] = state->h[2];
	leftTemp1[3] = state->h[3];
	leftTemp1[4] = state->s[0];
	leftTemp1[5] = state->s[1];
	leftTemp1[6] = state->c[0];
	leftTemp1[7] = state->t;

	/* initialize right branch */
	rightTemp1[0] = state->h[4];
	rightTemp1[1] = state->h[5];
	rightTemp1[2] = state->h[6];
	rightTemp1[3] = state->h[7];
	rightTemp1[4] = state->s[2];
	rightTemp1[5] = state->s[3];
	rightTemp1[6] = state->c[1];
	rightTemp1[7] = state->t;

	/* left branch operations, same for all hash sizes */
	G(leftTemp1, m[SIGMA0[0]], m[SIGMA0[1]], m[SIGMA0[2]], m[SIGMA0[3]], leftTemp2);
	G(leftTemp2, m[SIGMA0[4]], m[SIGMA0[5]], m[SIGMA0[6]], m[SIGMA0[7]], leftTemp1);
	G(leftTemp1, m[SIGMA0[8]], m[SIGMA0[9]], m[SIGMA0[10]], m[SIGMA0[11]], leftTemp2);
	G(leftTemp2, m[SIGMA0[12]], m[SIGMA0[13]], m[SIGMA0[14]], m[SIGMA0[15]], leftTemp1);
	
	G(leftTemp1, m[SIGMA1[0]], m[SIGMA1[1]], m[SIGMA1[2]], m[SIGMA1[3]], leftTemp2);
	G(leftTemp2, m[SIGMA1[4]], m[SIGMA1[5]], m[SIGMA1[6]], m[SIGMA1[7]], leftTemp1);
	G(leftTemp1, m[SIGMA1[8]], m[SIGMA1[9]], m[SIGMA1[10]], m[SIGMA1[11]], leftTemp2);
	G(leftTemp2, m[SIGMA1[12]], m[SIGMA1[13]], m[SIGMA1[14]], m[SIGMA1[15]], leftTemp1);
	
	G(leftTemp1, m[SIGMA2[0]], m[SIGMA2[1]], m[SIGMA2[2]], m[SIGMA2[3]], leftTemp2);
	G(leftTemp2, m[SIGMA2[4]], m[SIGMA2[5]], m[SIGMA2[6]], m[SIGMA2[7]], leftTemp1);
	G(leftTemp1, m[SIGMA2[8]], m[SIGMA2[9]], m[SIGMA2[10]], m[SIGMA2[11]], leftTemp2);
	G(leftTemp2, m[SIGMA2[12]], m[SIGMA2[13]], m[SIGMA2[14]], m[SIGMA2[15]], leftTemp1);
	
	G(leftTemp1, m[SIGMA3[0]], m[SIGMA3[1]], m[SIGMA3[2]], m[SIGMA3[3]], leftTemp2);
	G(leftTemp2, m[SIGMA3[4]], m[SIGMA3[5]], m[SIGMA3[6]], m[SIGMA3[7]], leftTemp1);
	G(leftTemp1, m[SIGMA3[8]], m[SIGMA3[9]], m[SIGMA3[10]], m[SIGMA3[11]], leftTemp2);
	G(leftTemp2, m[SIGMA3[12]], m[SIGMA3[13]], m[SIGMA3[14]], m[SIGMA3[15]], leftTemp1);

	/* left branch operations applied only for Sarmal-384 and Sarmal-512 */
	if(state->hashbitlen == 384 || state->hashbitlen == 512)
	{	
		G(leftTemp1, m[SIGMA3_5[0]], m[SIGMA3_5[1]], m[SIGMA3_5[2]], m[SIGMA3_5[3]], leftTemp2);
		G(leftTemp2, m[SIGMA3_5[4]], m[SIGMA3_5[5]], m[SIGMA3_5[6]], m[SIGMA3_5[7]], leftTemp1);
		G(leftTemp1, m[SIGMA3_5[8]], m[SIGMA3_5[9]], m[SIGMA3_5[10]], m[SIGMA3_5[11]], leftTemp2);
		G(leftTemp2, m[SIGMA3_5[12]], m[SIGMA3_5[13]], m[SIGMA3_5[14]], m[SIGMA3_5[15]], leftTemp1);
	}

	/* right branch operations, same for all hash sizes */
	G(rightTemp1, m[SIGMA4[0]], m[SIGMA4[1]], m[SIGMA4[2]], m[SIGMA4[3]], rightTemp2);
	G(rightTemp2, m[SIGMA4[4]], m[SIGMA4[5]], m[SIGMA4[6]], m[SIGMA4[7]], rightTemp1);
	G(rightTemp1, m[SIGMA4[8]], m[SIGMA4[9]], m[SIGMA4[10]], m[SIGMA4[11]], rightTemp2);
	G(rightTemp2, m[SIGMA4[12]], m[SIGMA4[13]], m[SIGMA4[14]], m[SIGMA4[15]], rightTemp1);
	
	G(rightTemp1, m[SIGMA5[0]], m[SIGMA5[1]], m[SIGMA5[2]], m[SIGMA5[3]], rightTemp2);
	G(rightTemp2, m[SIGMA5[4]], m[SIGMA5[5]], m[SIGMA5[6]], m[SIGMA5[7]], rightTemp1);
	G(rightTemp1, m[SIGMA5[8]], m[SIGMA5[9]], m[SIGMA5[10]], m[SIGMA5[11]], rightTemp2);
	G(rightTemp2, m[SIGMA5[12]], m[SIGMA5[13]], m[SIGMA5[14]], m[SIGMA5[15]], rightTemp1);
	
	G(rightTemp1, m[SIGMA6[0]], m[SIGMA6[1]], m[SIGMA6[2]], m[SIGMA6[3]], rightTemp2);
	G(rightTemp2, m[SIGMA6[4]], m[SIGMA6[5]], m[SIGMA6[6]], m[SIGMA6[7]], rightTemp1);
	G(rightTemp1, m[SIGMA6[8]], m[SIGMA6[9]], m[SIGMA6[10]], m[SIGMA6[11]], rightTemp2);
	G(rightTemp2, m[SIGMA6[12]], m[SIGMA6[13]], m[SIGMA6[14]], m[SIGMA6[15]], rightTemp1);
	
	G(rightTemp1, m[SIGMA7[0]], m[SIGMA7[1]], m[SIGMA7[2]], m[SIGMA7[3]], rightTemp2);
	G(rightTemp2, m[SIGMA7[4]], m[SIGMA7[5]], m[SIGMA7[6]], m[SIGMA7[7]], rightTemp1);
	G(rightTemp1, m[SIGMA7[8]], m[SIGMA7[9]], m[SIGMA7[10]], m[SIGMA7[11]], rightTemp2);
	G(rightTemp2, m[SIGMA7[12]], m[SIGMA7[13]], m[SIGMA7[14]], m[SIGMA7[15]], rightTemp1);
	
	/* right branch operations applied only for Sarmal-384 and Sarmal-512 */
	if(state->hashbitlen == 384 || state->hashbitlen == 512)
	{	
		G(rightTemp1, m[SIGMA7_5[0]], m[SIGMA7_5[1]], m[SIGMA7_5[2]], m[SIGMA7_5[3]], rightTemp2);
		G(rightTemp2, m[SIGMA7_5[4]], m[SIGMA7_5[5]], m[SIGMA7_5[6]], m[SIGMA7_5[7]], rightTemp1);
		G(rightTemp1, m[SIGMA7_5[8]], m[SIGMA7_5[9]], m[SIGMA7_5[10]], m[SIGMA7_5[11]], rightTemp2);
		G(rightTemp2, m[SIGMA7_5[12]], m[SIGMA7_5[13]], m[SIGMA7_5[14]], m[SIGMA7_5[15]], rightTemp1);
	}
	
	/* XOR left and right branches */
	for(i=0; i<8; i++)
		rightTemp1[i] ^= leftTemp1[i];

	/* and XOR the result with previous chaining values */
	for(i=0; i<8; i++)
		state->h[i] ^= rightTemp1[i];
	
	/* update # of bits hashed so far */
	state->t += 1024;
}

/* G function
   in -> state values (X0-X7)
   A, B, C, D -> 64-bit message blocks
   out -> resulting state values */   
void G(const Bit64 *in, const Bit64 A, const Bit64 B, const Bit64 C, const Bit64 D, Bit64 *out)
{
	Bit64 temp1, temp2; /* temporary variables */
	
	out[1] = in[0] ^ A;
	temp1  = g(out[1]);

	out[2] = temp1 ^ in[1];

	temp2  = in[2] ^ B;
	out[3] = temp1 + temp2;

	out[4] = in[3] - temp1;

	out[5] = in[4] ^ C;
	temp2  = g(out[5]);

	out[6] = temp2 ^ in[5];

	temp1  = in[6] ^ D;
	out[7] = temp2 + temp1;

	out[0] = in[7] - temp2;
}

/* g function
   in -> 64-bit argument */
Bit64 g(const Bit64 in)
{
	int i;
	Bit64 retVal;			/* return value */
	BitSequence inBytes[8];		/* bytes of input value */
	BitSequence outBytes[8];	/* bytes of return value */
		
	/* get bytes of input value */
	for(i=0; i<8; i++)
		inBytes[i] = GET_BYTE(in,7-i); 

	/* s-box look-up for each byte */
	for(i=0; i<8; i++)
		inBytes[i] = S[inBytes[i]];
	
	/* MDS matrix multiplication in GF(2^8) */
	for(i=0; i<8; i++)
	{
		outBytes[i] =	GFMultiply(inBytes[0], MDS[i][0]) ^  
				GFMultiply(inBytes[1], MDS[i][1]) ^
				GFMultiply(inBytes[2], MDS[i][2]) ^
				GFMultiply(inBytes[3], MDS[i][3]) ^
				GFMultiply(inBytes[4], MDS[i][4]) ^
				GFMultiply(inBytes[5], MDS[i][5]) ^
				GFMultiply(inBytes[6], MDS[i][6]) ^
				GFMultiply(inBytes[7], MDS[i][7]);
	}
	
	/* construct 64-bit return value using bytes resulting from MDS multiplication */
	retVal = (((Bit64)outBytes[0])<<56) |
		 (((Bit64)outBytes[1])<<48) |
		 (((Bit64)outBytes[2])<<40) |
		 (((Bit64)outBytes[3])<<32) |
		 (((Bit64)outBytes[4])<<24) |
		 (((Bit64)outBytes[5])<<16) |
		 (((Bit64)outBytes[6])<< 8) |
		 (((Bit64)outBytes[7])    );
	
	return retVal;
}

/* perform padding operation */
void HashPad(hashState *state)
{
	/* total message length */
	Bit64 messagebitlen = state->t + state->remainingbitlen;

	int byteind = state->remainingbitlen/8; /* byte index of remaining byte */
	int bitpos = state->remainingbitlen%8; /* bit position in last byte */

	/* make unoccupied bits 0 */
	if(bitpos)
		state->messageblock[byteind] &= 0xFF<<(8-bitpos);

	if(state->remainingbitlen < 950)
	{
		/* add single 1-bit */
		if(bitpos)
		{		
			state->messageblock[byteind] |= 0x80>>(bitpos);
		}
		else
		{
			state->messageblock[byteind] = 0x80;
		}
		/* add 0-bits until we have 950 bits */
		while(byteind!=118)
		{
			byteind++;
			state->messageblock[byteind] = 0;
		}
	}
	else if(state->remainingbitlen > 950)
	{
		/* add single 1-bit */
		if(bitpos)
		{
			state->messageblock[byteind] |= 0x80>>(bitpos);
		}
		else
		{
			state->messageblock[byteind] = 0x80;
		}
		/* add 0-bits until we have 1024 bits */
		while(byteind!=127)
		{
			byteind++;
			state->messageblock[byteind] = 0;
		}
		/* hash once */
		HashBlock(state);
		/* then, start adding 0-bits until we have 950 bits */
		for(byteind=0; byteind<119; byteind++)
			state->messageblock[byteind] = 0;
	}
		
	/* append 10-bit hashbitlen to message block */
	switch(state->hashbitlen)
	{
		case 224:
			state->messageblock[119] = 0xE0;
			break;
		case 256:
			state->messageblock[118] |= 0x01;
			state->messageblock[119] = 0;
			break;
		case 384:
			state->messageblock[118] |= 0x01;
			state->messageblock[119] = 0x80;
			break;
		case 512:
			state->messageblock[118] |= 0x02;
			state->messageblock[119] = 0;
			break;
	}
	
	/* add 64-bit message length */
	BSWAP(messagebitlen);
	memcpy(state->messageblock+120, &messagebitlen, 8);
	
	/* then hash 1024-bit message block */
	HashBlock(state);
}

