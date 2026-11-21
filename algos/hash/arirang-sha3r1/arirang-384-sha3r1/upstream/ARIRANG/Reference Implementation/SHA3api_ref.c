///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PROJECT : ARIRANG family(ARIRANG-224,ARIRANG-256,ARIRANG-384,ARIRANG-512)
//
// DATE    : 2008.10.23
//
///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FILE  : SHA3_Ref.c
//
// NOTES : Reference code of ARIRANG family
// 
//         Based on 64-bit platform
//
///////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <memory.h>
#include "Arirang_ref64.h"
#include "SHA3api_ref.h"


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Init
//
// DESCRIPTION    : Initialize a hashState with the intended hash length of particular instantiation.
//
// PARAMETERS     : state - a structure that holds the hashState information
//                  hashbitlen - an integer value that indicates the length of the hash output in bits
//
// RETURNS        : SUCCESS - on success
//                  BAD_HASHLEN - hashbitlen is invalid
//
///////////////////////////////////////////////////////////////////////////////////////////////////

HashReturn Init(hashState *state, int hashbitlen)
{
	if ((hashbitlen != 224) && (hashbitlen != 256) && (hashbitlen != 384) && (hashbitlen != 512))
		return BAD_HASHLEN;

	gen_tabs();
	// Setting the Hash Length
	state->hashbitlen = hashbitlen;
	
	// Setting the Counter Values
	state->counter[0] = state->counter[1] = 0;	
	
	// Initialize the Data Length
	state->count[0] = state->count[1] = 0;

	// Setting the Initial Value
	if(state->hashbitlen == 224){
		state->workingvar[0] = 0xcbbb9d5d;
		state->workingvar[1] = 0x629a292a;
		state->workingvar[2] = 0x9159015a;
		state->workingvar[3] = 0x152fecd8;
		state->workingvar[4] = 0x67332667;
		state->workingvar[5] = 0x8eb44a87;
		state->workingvar[6] = 0xdb0c2e0d;
		state->workingvar[7] = 0x47b5481d;
		state->blocklen=ARIRANG256_BLOCK_LEN;
	}
		
	else if(state->hashbitlen == 256){
		state->workingvar[0] = 0x6a09e667;
		state->workingvar[1] = 0xbb67ae85;
		state->workingvar[2] = 0x3c6ef372;
		state->workingvar[3] = 0xa54ff53a;
		state->workingvar[4] = 0x510e527f;
		state->workingvar[5] = 0x9b05688c;
		state->workingvar[6] = 0x1f83d9ab;
		state->workingvar[7] = 0x5be0cd19;
		state->blocklen=ARIRANG256_BLOCK_LEN;
	
	}
	else if(hashbitlen == 384){	
		state->workingvar[0]=0xcbbb9d5dc1059ed8ULL;
		state->workingvar[1]=0x629a292a367cd507ULL;
		state->workingvar[2]=0x9159015a3070dd17ULL;	
		state->workingvar[3]=0x152fecd8f70e5939ULL;
		state->workingvar[4]=0x67332667ffc00b31ULL;
		state->workingvar[5]=0x8eb44a8768581511ULL;
		state->workingvar[6]=0xdb0c2e0d64f98fa7ULL;
		state->workingvar[7]=0x47b5481dbefa4fa4ULL;
		state->blocklen=ARIRANG512_BLOCK_LEN;
	
	}													
	else if(hashbitlen == 512){									
		state->workingvar[0]=0x6a09e667f3bcc908ULL;
		state->workingvar[1]=0xbb67ae8584caa73bULL;
		state->workingvar[2]=0x3c6ef372fe94f82bULL;
		state->workingvar[3]=0xa54ff53a5f1d36f1ULL;
		state->workingvar[4]=0x510e527fade682d1ULL;
		state->workingvar[5]=0x9b05688c2b3e6c1fULL;
		state->workingvar[6]=0x1f83d9abfb41bd6bULL;
		state->workingvar[7]=0x5be0cd19137e2179ULL;
		state->blocklen=ARIRANG512_BLOCK_LEN;		
	}
	return SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Update
//
// DESCRIPTION    : Process the supplied data.
//
// PARAMETERS     : state - a structure that holds the hashState information
//                  data - the data to be hashed
//                  Databitlen - the length, in bits, of the data to be hashed
//
// RETURNS        : SUCCESS - on success
//
///////////////////////////////////////////////////////////////////////////////////////////////////

HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
	DWORD RemainedLen, PartLen;
	QWORD databytelen, temp;

	state->remainderbit = databitlen & 7;

	// If length of data is not multiple of 8, databytelen = databitlen / 8 + 1;
	databytelen = ( databitlen >> 3) + (state->remainderbit != 0); 
	
	// Compute the number of hashed bytes mod ARIRANG_BLOCK_LEN
	RemainedLen = (state->count[0] >> 3) % state->blocklen;

	// Compute the number of bytes that can be filled up
	PartLen = state->blocklen - RemainedLen;

	// Update count (number of toatl data bits)
	temp = state->count[0] + (databytelen << 3);
	if( temp  < state->count[0] )	state->count[1]++;		
	state->count[0]=temp;
	
	if ((databytelen > PartLen) || ((databytelen == PartLen) && (state->remainderbit == 0)) ) {
		memcpy(state->block + RemainedLen, data, (int)PartLen);
		if(state->hashbitlen <257) Arirang_Compression256(state);
		else Arirang_Compression512(state);

		data += PartLen;
		databytelen -= PartLen;
		RemainedLen = 0;

		while( (databytelen > state->blocklen) || ((databytelen == state->blocklen) && (state->remainderbit == 0)) ) {
			memcpy((BYTE *)state->block, data, (int)state->blocklen);
			if(state->hashbitlen <257) Arirang_Compression256(state);
			else Arirang_Compression512(state);

			data += state->blocklen;
			databytelen -= state->blocklen;
		}
	}

	//	Buffer remaining input
	memcpy((BYTE *)state->block + RemainedLen, data, (int)databytelen);

	return SUCCESS;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Final
//
// DESCRIPTION    : Perform any post processing and ouput filtering required and return the final 
//                  hash value.
//
// PARAMETERS     : state - a structure that holds the hashState information
//                  hashval - the storage for the final hash value to be returned
//
// RETURNS        : SUCCESS - on success
//
///////////////////////////////////////////////////////////////////////////////////////////////////

HashReturn Final(hashState *state, BYTE *hashval)
{
	DWORD i, dwIndex;
	DWORD temp=(state->blocklen >> 3);
	QWORD count[2];

	// Padding the message
	if(state->remainderbit){
		// Length of data isn't multiple of 8
		count[0] = state->count[0] + state->remainderbit - 8;
		count[1] = state->count[1];
		dwIndex = ((count[0] + (state->blocklen<<3) ) >> 3) % state->blocklen;
		state->block[dwIndex] &= 0xff-(1<<(8-state->remainderbit))+1;		
		state->block[dwIndex++] ^= 0x80>>(state->remainderbit);
	}
	else{
		// Length of data is multiple of 8
		count[0] = state->count[0];
		count[1] = state->count[1];		
		dwIndex = (count[0] >> 3) % state->blocklen;		
		state->block[dwIndex++] = 0x80;	
	}
		
	if (dwIndex > (state->blocklen - temp)){
		memset((BYTE *)state->block + dwIndex, 0, (int)(state->blocklen - dwIndex));
		if(state->hashbitlen <257) Arirang_Compression256(state);
		else Arirang_Compression512(state);

		memset((BYTE *)state->block, 0, (int)state->blocklen - temp);
	}
	else
		memset((BYTE *)state->block + dwIndex, 0, (int)(state->blocklen - dwIndex - temp));

	#if defined(LITTLE_ENDIAN)
		count[0] = ENDIAN_REVERSE_DWORD(((DWORD*)count)[1])| ((QWORD)(ENDIAN_REVERSE_DWORD(((DWORD*)count)[0])) << 32);
		count[1] = ENDIAN_REVERSE_DWORD(((DWORD*)count)[3])| ((QWORD)(ENDIAN_REVERSE_DWORD(((DWORD*)count)[2])) << 32);
	#endif
	
	// Fixed counter value for the last message block
	if(state->hashbitlen > 257){
		((QWORD *)state->block)[state->blocklen/8-2] = count[1];
		((QWORD *)state->block)[state->blocklen/8-1] = count[0];
		state->counter[1]=0xb7e151628aed2a6aULL;
		state->counter[0]=0xbf7158809cf4f3c7ULL;
	}
	else{
		((QWORD *)state->block)[state->blocklen/8-1] = count[0];
		state->counter[0]=0xb7e151628aed2a6aULL;	
	}
	
	if(state->hashbitlen <257) Arirang_Compression256(state);
	else Arirang_Compression512(state);


	if(state->hashbitlen <257)
		for (i = 0; i < (state->hashbitlen >> 3); i += 4)	BIG_D2B((state->workingvar)[(i*2) / 8], &(hashval[i]));
	else
		for (i = 0; i < (state->hashbitlen >> 3); i += 8)	BIG_Q2B((state->workingvar)[i / 8], &(hashval[i]));

	return SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Hash
//
// DESCRIPTION    : Hash the supplied data and provide the resulting hash value. 
//                  
//
// PARAMETERS     : state      - a structure that holds the hashState information
//                  data       - the data to be hashed
//                  databitlen - the length, in bits, of the data to be hashed
//                  hashval    - the storage for the final hash value to be returned
//
// RETURNS        : SUCCESS - on success
//
///////////////////////////////////////////////////////////////////////////////////////////////////
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval){

	hashState State;
	HashReturn hash_return;
	int i,j;
	
	if ( (hash_return = Init(&State, hashbitlen)) != SUCCESS )
		return hash_return;	
	
	if ( (hash_return = Update(&State, data, databitlen)) != SUCCESS)
		return hash_return;	

	if ( (hash_return = Final(&State, hashval)) !=SUCCESS)
		hash_return;

	return SUCCESS;	
}