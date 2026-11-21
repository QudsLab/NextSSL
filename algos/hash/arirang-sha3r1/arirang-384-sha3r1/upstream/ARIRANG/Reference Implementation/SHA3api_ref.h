///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PROJECT : Arirang family
//
// DATE    : 2008.10.23
//
///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FILE  : SHA3api_Ref.h
//
// NOTES : Reference code of Arirang family
// 
//         Based on 64-bit platform
//
///////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __SHA3API_REF_H__
#define __SHA3API_REF_H__ 100


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Definition

#define ARIRANG224_BLOCK_LEN	64
#define ARIRANG224_DIGEST_LEN	28

#define ARIRANG256_BLOCK_LEN	64
#define ARIRANG256_DIGEST_LEN	32

#define ARIRANG384_BLOCK_LEN	128
#define ARIRANG384_DIGEST_LEN	48

#define ARIRANG512_BLOCK_LEN	128
#define ARIRANG512_DIGEST_LEN	64


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Datatype

typedef unsigned char BYTE;				//  8-bit data type

typedef unsigned char BitSequence;		//  8-bit data type

typedef unsigned short int WORD;		// 16-bit data type

typedef unsigned int DWORD;				// 32-bit data type

typedef unsigned long long QWORD;		// 64-bit data type

typedef unsigned long long DataLength;	// 64-bit data type


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Error

typedef enum {SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2} HashReturn;


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Structure

typedef struct {

	// Hash length
	int hashbitlen;
	
	// Counter
	QWORD counter[2];

	// Count
	QWORD count[2];

	// Message block
	BYTE block[ARIRANG512_BLOCK_LEN];

	// Working variables
	QWORD workingvar[8];

	// hash block length
	DWORD blocklen;

	// bit_length % 7
	DWORD remainderbit;


} hashState;


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Function

HashReturn Init(hashState *state, int hashbitlen);
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Final(hashState *state, BYTE *hashval);
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

#endif