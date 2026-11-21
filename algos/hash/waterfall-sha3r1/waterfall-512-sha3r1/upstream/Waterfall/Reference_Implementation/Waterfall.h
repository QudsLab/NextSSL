/*
Waterfall Hash Algorithm 1.7 Reference version A

Include file to define data types and function prototypes.  See Waterfall.c for details.

Bob Hattersley 03Oct08
*/

#ifndef __WATERFALL_H__
#define __WATERFALL_H__

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef unsigned char BitSequence;		// Data type of input data
typedef unsigned long long DataLength;	// Data type for input data length in bits
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;	// Returns from functions

#define STREAM1 16					// Stream lengths (32-bit words)
#define STREAM2 7
#define STREAM3 6
#define POOLFACTOR 2				// Length of each Pool as a multiple of Stream 1
#define POOL (STREAM1*POOLFACTOR)	// Pool lengths (32-bit words)

// Structure to hold Waterfall Hash state data
typedef struct {
	unsigned int hashbitlen;		// Requested number of bits in message digest

	unsigned char inputbuffer[64];	// Input buffer of 512 bits
	unsigned int inputbits;			// Number of bits currently in input buffer
	unsigned int inputblocks;		// Number of blocks of input (512 bits) currently processed
	unsigned int inputslabs;		// Number of slabs of input (2^41 bits) currently processed

	unsigned int istream1;			// Current word in Stream 1
	unsigned int stream1[STREAM1];	// Stream 1
	unsigned int istream2;			// Current word in Stream 2
	unsigned int stream2[STREAM2];	// Stream 2
	unsigned int istream3;			// Current word in Stream 3
	unsigned int stream3[STREAM3];	// Stream 3

	unsigned int ipool;				// Current word in each Pool
	unsigned int pool2[POOL];		// Pool 2 - NB there is no Pool 1
	unsigned int pool3[POOL];		// Pool 3
} hashState;

// Function prototypes
HashReturn Init(hashState *state, int hashbitlen);										// Initialisation
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen);	// Update state data with input
HashReturn Final(hashState *state, BitSequence *hashval);								// Return message digest
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen,
				BitSequence *hashval);													// Do it all at once

#ifdef __cplusplus
}
#endif

#endif // __WATERFALL_H__
