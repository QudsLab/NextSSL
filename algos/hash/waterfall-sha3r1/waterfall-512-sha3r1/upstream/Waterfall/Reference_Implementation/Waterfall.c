/*
Waterfall Hash Algorithm version 1.7 Reference version A

Generates a fixed length message digest of up to 512 bits in 32-bit increments from an 
unlimited-length message, with resistance to a range of cryptographic attacks.

See "Waterfall Specification 1.0" for details.

Bob Hattersley 12Oct08
*/

#include <stddef.h>
#include "Waterfall.h"

#define FINALUPDATES 16 // Number of Update Steps in Final with fixed input
#define FINALSTEPS 4	// Number of Final Steps in Final after combining with Pools
#define DEBUG 0			// 0: no output, 1: API calls, 2: main step results, 3: full processing breakdown

#if DEBUG>0
#include <stdio.h>
#endif

// Rijndael S-box - with limited program memory this could be calculated
static const unsigned char sbox[256] = {
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

// Derived X-box - with limited data memory this could be calculated on the fly as needed; note that
// this should not be in global scope if it is implemented in a DLL or called by multithreaded code;
// this is only done here to make the set-up of the X-box explicit in Init
static unsigned int xbox[256];

// -------------------------------------------------------------------------------------------------

// API routine to initialise hash algorithm state and check required message digest length

HashReturn Init ( hashState *state, int hashbitlen ) {
	int i;
	unsigned char work1, work2;

// Check message digest length is valid (whole 32-bit words, at most 16 of them)
	if (hashbitlen<=0 || hashbitlen>32*STREAM1 || hashbitlen%32) return BAD_HASHBITLEN;
	state->hashbitlen = hashbitlen;

// Initialise input buffer to empty
	state->inputbits = 0;
	state->inputblocks = 0;
	state->inputslabs = 0;

// Put the digest length into the first word of Stream 2 (Stream 1 may be used for a key)
	state->stream2[0] = hashbitlen;

// Initialise remaining Stream entries to zeros
	for (i=0; i<STREAM1; i++) state->stream1[i] = 0;
	state->istream1 = STREAM1-1;
	for (i=1; i<STREAM2; i++) state->stream2[i] = 0;
	state->istream2 = STREAM2-1;
	for (i=0; i<STREAM3; i++) state->stream3[i] = 0;
	state->istream3 = STREAM3-1;

// Initialise Pools to zeros
	for (i=0; i<POOL; i++) state->pool2[i] = 0;
	for (i=0; i<POOL; i++) state->pool3[i] = 0;
	state->ipool = POOL-1;

// Fill X-box: each byte is an affine transform of the Rijndael S-box, except the low-order byte which 
// is the Rijndael S-box exclusive-or the index; the linear operators are simple rotations and shifts
// to save processing in the case that X-box entries are calculated on the fly
	for (i=0; i<256; i++) {
		work1 = sbox[i];
		xbox[i] = work1 ^ i;

		work2 = work1 ^ (work1<<2) ^ (work1>>6) ^ (work1<<3);
		work2 = (work2<<7) | (work2>>1) ^ 0x3b;
		xbox[i] |= (work2<<8);

		work2 = work1 ^ (work1<<5) ^ (work1>>3) ^ (work1>>7) ^ 0x95;
		xbox[i] |= (work2<<16);

		work2 = work1 ^ (work1<<7) ^ (work1>>1) ^ (work1>>5) ^ 0x6a;
		xbox[i] |= (work2<<24);
	}

#if DEBUG>0
	printf("Waterfall initialised: hashbitlen %d\n", hashbitlen);
#endif
	return SUCCESS;
}

// -------------------------------------------------------------------------------------------------

// Perform the X-box 32-bit to 32-bit substitution making sure that each byte (almost certainly)
// depends on every byte

static void Xbox ( unsigned int *pword ) {

#if DEBUG>2
	printf("  X-box steps: %8.8x ", *pword);
#endif
	*pword ^= xbox[*pword & 0xFF];
	*pword = (*pword<<24) | (*pword>>8);
#if DEBUG>2
	printf("%8.8x ", *pword);
#endif
	*pword ^= xbox[*pword & 0xFF];
	*pword = (*pword<<24) | (*pword>>8);
#if DEBUG>2
	printf("%8.8x ", *pword);
#endif
	*pword ^= xbox[*pword & 0xFF];
	*pword = (*pword<<24) | (*pword>>8);
#if DEBUG>2
	printf("%8.8x ", *pword);
#endif
	*pword ^= xbox[*pword & 0xFF];
	*pword = (*pword<<24) | (*pword>>8);
#if DEBUG>2
	printf("%8.8x\n", *pword);
#endif
}

// -------------------------------------------------------------------------------------------------

// Perform a single update step given an input word

static void UpdateStep ( hashState *state, unsigned int input ) {
	unsigned int word1, word2, word3;

#if DEBUG>1
	printf(" Update step input %8.8x\n", input);
#endif

// Extract previous entries from Streams
	word1 = state->stream1[state->istream1];
	word2 = state->stream2[state->istream2];
	word3 = state->stream3[state->istream3];

#if DEBUG>2
	printf("  Previous stream values %8.8x %8.8x %8.8x\n", word1, word2, word3);
#endif

// Advance Stream positions rotationally
	state->istream1++;
	if(state->istream1==STREAM1) state->istream1 = 0;
	state->istream2++;
	if(state->istream2==STREAM2) state->istream2 = 0;
	state->istream3++;
	if(state->istream3==STREAM3) state->istream3 = 0;

#if DEBUG>2
	printf("  Current stream positions %d %d %d\n", state->istream1, state->istream2, state->istream3);
	printf("  Current stream values  %8.8x %8.8x %8.8x\n", 
		state->stream1[state->istream1], state->stream2[state->istream2], state->stream3[state->istream3]);
#endif

// Update the current position in each Stream using the input word and the previous entry, using the X-box
// for non-linearity and mixing in the word 
	word1 ^= state->stream1[state->istream1] ^ input; 
	Xbox(&word1);
	state->stream1[state->istream1] = word1;

	word2 ^= state->stream2[state->istream2] ^ input ^ 1; 
	Xbox(&word2);
	state->stream2[state->istream2] = word2;

	word3 ^= state->stream3[state->istream3] ^ input ^ 2; 
	Xbox(&word3);
	state->stream3[state->istream3] = word3;

#if DEBUG>2
	printf("  New stream values      %8.8x %8.8x %8.8x\n", word1, word2, word3);
#endif

// Update Pools 2 and 3 from the current words in Stream 2 and 3 with simple exclusive-or
	state->ipool++;
	if(state->ipool==POOL) state->ipool = 0;
	state->pool2[state->ipool] ^= word2;
	state->pool3[state->ipool] ^= word3;

#if DEBUG>2
	printf("  New pool values at %d: %8.8x %8.8x\n", 
			state->ipool, state->pool2[state->ipool], state->pool3[state->ipool]);
#endif
}

// -------------------------------------------------------------------------------------------------

// API routine to process some passed data into the hash state

HashReturn Update ( hashState *state, const BitSequence *data, DataLength databitlen ) {
	int i, j;
	unsigned int input;
	unsigned char last;

#if DEBUG>0
	printf("Update: databitlen %d\n", databitlen);
#endif

// Number of bytes currently in the buffer
	i = state->inputbits / 8;

// Loop over whole bytes of input, filling the buffer
	while (databitlen>=8) {

	// Next byte into buffer
		state->inputbits += 8;
		state->inputbuffer[i] = *data;
		i++;
		data++;
		databitlen -= 8;

	// The buffer may be full now, in which case do some real work - 17 steps
		if(i==64) {

		// Process the buffer - 16 words (little-endian)
			for(j=0; j<16; j++) {
				input = state->inputbuffer[4*j]
					+ (state->inputbuffer[4*j+1] << 8)
					+ (state->inputbuffer[4*j+2] << 16)
					+ (state->inputbuffer[4*j+3] << 24);
				UpdateStep(state, input);
			}

		// Increment the block count and possibly the slab count, then process the block count
			state->inputblocks++;
			if(!state->inputblocks) state->inputslabs++;
			UpdateStep(state, state->inputblocks);

		// Buffer is now empty again
			i = 0;
			state->inputbits = 0;
		}
	}

// Handle a part of a byte (only in the last update) - zero least significant bits before storing
	if (databitlen>0) {
		last = *data;
		last >>= 8-databitlen;
		last <<= 8-databitlen;
		state->inputbits += (int) databitlen;
		state->inputbuffer[i] = last;
	}

#if DEBUG>1
	printf(" Stream 1:\n");
	for(i=0; i<STREAM1; i++) {
		if((i&7)==0) printf(" ");
		printf(" %8.8x", state->stream1[i]);
		if((i&7)==7) printf("\n");
	}
	printf(" Stream 2:\n ");
	for(i=0; i<STREAM2; i++) printf(" %8.8x", state->stream2[i]);
	printf("\n");
	printf(" Stream 3:\n ");
	for(i=0; i<STREAM3; i++) printf(" %8.8x", state->stream3[i]);
	printf("\n");
	printf(" Pool 2:\n");
	for(i=0; i<POOL; i++) {
		if((i&7)==0) printf(" ");
		printf(" %8.8x", state->pool2[i]);
		if((i&7)==7) printf("\n");
	}
	printf(" Pool 3:\n");
	for(i=0; i<POOL; i++) {
		if((i&7)==0) printf(" ");
		printf(" %8.8x", state->pool3[i]);
		if((i&7)==7) printf("\n");
	}
#endif

	return SUCCESS;
}

// -------------------------------------------------------------------------------------------------

// Mangle the copy of Stream 1, optionally mixing with a section of one of the Pools

static void FinalStep ( unsigned int *pworkin, unsigned int *ppool, unsigned int *pworkout ) {
	unsigned int i;

// Swap bits rotationally between elements of the array
	for (i=0; i<STREAM1; i++) {
		pworkout[i] = (pworkin[i] & 0x14141414) | (pworkin[(i+3)%STREAM1] & 0x28282828) | 
					(pworkin[(i+7)%STREAM1] & 0x42424242) | (pworkin[(i+12)%STREAM1] & 0x81818181);
	}

#if DEBUG>2
	printf("  Bits swapped:\n");
	for(i=0; i<STREAM1; i++) {
		if((i&7)==0) printf("  ");
		printf(" %8.8x", pworkout[i]);
		if((i&7)==7) printf("\n");
	}
#endif

// Apply the X-box to each member of the copy array
	for(i=0; i<STREAM1; i++) Xbox(pworkout+i);

#if DEBUG>2
	printf("  X-box applied:\n");
	for(i=0; i<STREAM1; i++) {
		if((i&7)==0) printf("  ");
		printf(" %8.8x", pworkout[i]);
		if((i&7)==7) printf("\n");
	}
#endif

// If it is passed, exclusive-or a section of a Pool into the copy of Stream 1
	if (ppool!=NULL) for(i=0; i<STREAM1; i++) pworkout[i] ^= ppool[i];

#if DEBUG>2
	printf("  Masked:\n");
	for(i=0; i<STREAM1; i++) {
		if((i&7)==0) printf("  ");
		printf(" %8.8x", pworkout[i]);
		if((i&7)==7) printf("\n");
	}
#endif

}

// -------------------------------------------------------------------------------------------------

// API routine to complete the algorithm and return the message digest

HashReturn Final ( hashState *state, BitSequence *hashval ) {
	unsigned int i, pass, input, *ppool;
	unsigned int work1[STREAM1], work2[STREAM1], *pworkin, *pworkout, *pwork;

#if DEBUG>0
	printf("Final\n");
#endif

// May need to process the contents of the input buffer
	if (state->inputbits) {

	// Zero the end of the buffer (we don't want data going in twice)
		i = (state->inputbits+7) / 8;
		for(; i<64; i++) state->inputbuffer[i] = 0;

	// Process the buffer
		state->inputblocks++;
		if(!state->inputblocks) state->inputslabs++;

		for(i=0; i<16; i++) {
			input = state->inputbuffer[4*i]
				+ (state->inputbuffer[4*i+1] << 8)
				+ (state->inputbuffer[4*i+2] << 16)
				+ (state->inputbuffer[4*i+3] << 24);
			UpdateStep(state, input);
		}
		UpdateStep(state, state->inputblocks);
	}

// Always process the bit count and slab count
	UpdateStep(state, state->inputbits);
	UpdateStep(state, state->inputslabs);

// Perform multiple steps with fixed input to mix the last entries in
	for(i=0; i<FINALUPDATES; i++) UpdateStep(state, i);

#if DEBUG>1
	printf(" Stream 1 after input:\n");
	for(i=0; i<STREAM1; i++) {
		if((i&7)==0) printf(" ");
		printf(" %8.8x", state->stream1[i]);
		if((i&7)==7) printf("\n");
	}
	printf(" Stream 2 after input:\n ");
	for(i=0; i<STREAM2; i++) printf(" %8.8x", state->stream2[i]);
	printf("\n");
	printf(" Stream 3 after input:\n ");
	for(i=0; i<STREAM3; i++) printf(" %8.8x", state->stream3[i]);
	printf("\n");
	printf(" Pool 2 after input:\n");
	for(i=0; i<POOL; i++) {
		if((i&7)==0) printf(" ");
		printf(" %8.8x", state->pool2[i]);
		if((i&7)==7) printf("\n");
	}
	printf(" Pool 3 after input:\n");
	for(i=0; i<POOL; i++) {
		if((i&7)==0) printf(" ");
		printf(" %8.8x", state->pool3[i]);
		if((i&7)==7) printf("\n");
	}
#endif

// Take a copy of Stream 1
	for(i=0; i<STREAM1; i++) work1[i] = state->stream1[i];

// Work arrays are used alternately as input and output
	pworkin = work1;
	pworkout = work2;

// Perform mangling steps, combining with Pool 2
	ppool = state->pool2;
	for(pass=0; pass<POOLFACTOR; pass++) {
#if DEBUG>1
		printf(" Combining with Pool 2 pass %d\n", pass);
#endif
		FinalStep(pworkin, ppool, pworkout);
		pwork = pworkin;
		pworkin = pworkout;
		pworkout = pwork;
		ppool += STREAM1;
	}

// Same with Pool 3
	ppool = state->pool3;
	for(pass=0; pass<POOLFACTOR; pass++) {
#if DEBUG>1
		printf(" Combining with Pool 3 pass %d\n", pass);
#endif
		FinalStep(pworkin, ppool, pworkout);
		pwork = pworkin;
		pworkin = pworkout;
		pworkout = pwork;
		ppool += STREAM1;
	}

// Same steps but with no Pool data
	for(pass=0; pass<FINALSTEPS; pass++) {
#if DEBUG>1
		printf(" Mixing without Pools pass %d\n", pass);
#endif
		FinalStep(pworkin, NULL, pworkout);
		pwork = pworkin;
		pworkin = pworkout;
		pworkout = pwork;
	}

#if DEBUG>1
	printf(" Mangled copy of Stream 1:\n");
	for(i=0; i<STREAM1; i++) {
		if((i&7)==0) printf(" ");
		printf(" %8.8x", pworkin[i]);
		if((i&7)==7) printf("\n");
	}
#endif

// Exclusive-or the mangled copy of Stream 1 with Stream 1
	for(i=0; i<STREAM1; i++) pworkin[i] ^= state->stream1[i];

// And with each section of each Pool to make Final one-way with respect to each of these
	ppool = state->pool2;
	for(pass=0; pass<POOLFACTOR; pass++) {
		for(i=0; i<STREAM1; i++) pworkin[i] ^= ppool[i];
		ppool += STREAM1;
	}

	ppool = state->pool3;
	for(pass=0; pass<POOLFACTOR; pass++) {
		for(i=0; i<STREAM1; i++) pworkin[i] ^= ppool[i];
		ppool += STREAM1;
	}
	
#if DEBUG>1
	printf(" Final digest:\n");
	for(i=0; i<STREAM1; i++) {
		if((i&7)==0) printf(" ");
		printf(" %8.8x", pworkin[i]);
		if((i&7)==7) printf("\n");
	}
#endif

// Return all the bytes required (little-endian transfer)
	for(i=0; i<(state->hashbitlen/32); i++) {
		hashval[4*i] = (unsigned char) pworkin[i];
		hashval[4*i+1] = (unsigned char) (pworkin[i]>>8);
		hashval[4*i+2] = (unsigned char) (pworkin[i]>>16);
		hashval[4*i+3] = (unsigned char) (pworkin[i]>>24);
	}
	return SUCCESS;
}

// -------------------------------------------------------------------------------------------------

// Perform the complete hash process in one call

HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen,
				BitSequence *hashval) {
	HashReturn ret;
	hashState state;

	ret = Init(&state, hashbitlen);
	if (ret != SUCCESS) return ret;

	ret = Update(&state, data, databitlen);
	if (ret != SUCCESS) return ret;

	ret = Final(&state, hashval);
	return ret;
}