/*
 * inupfin.c
 *
 *		Implements the API functions Init(), Update(), Final() and Hash()
 *		Calls the appropriate functions for each hash length
 *		Authors: Penazzi - Montes
 */


#include "inupfin.h"


/* Initializes a hashState with the intended hash length of this particular instantiation,
 * and calls the right initializacion function for that length.
 * Parameters:
 *	state: a structure that holds the hashState information
 *	hashbitlen: an integer value that indicates the length of the hash output in bits.
 * Returns:
 *	SUCCESS - on success
 *	BAD_HASHBITLEN - hashbitlen is invalid (e.g. is not one of 224, 256, 384, 512)
 */
HashReturn Init(hashState *state, int hashbitlen){
	switch (hashbitlen){
	case 256: 	state->hashbitlen = 256;
				return Init256(state->uu->state256);
	case 224: 	state->hashbitlen = 224;
				return Init224(state->uu->state256);
	case 512: 	state->hashbitlen = 512;
				return Init512(state->uu->state512);
	case 384: 	state->hashbitlen = 384;
				return Init384(state->uu->state512);
	default: return BAD_HASHBITLEN;
	}
}

/* Process the supplied data. 
 * Parameters:
 *	state: a structure that holds the hashState information
 *	data: the data to be hashed
 *	databitlen: the length, in bits, of the data to be hashed. 
 *	It must be a multiple of 8, except, possibly, in the last call
 * Returns:
 *	SUCCESS - on success
 */
HashReturn Update (hashState *state ,const BitSequence *data, DataLength databitlen){
	switch (state->hashbitlen){
	case 224:
	case 256: return Update256(state->uu->state256, data, databitlen);
	case 384:
	case 512: return Update512(state->uu->state512, data, databitlen);
	default: return BAD_HASHBITLEN;
	}
}

/* Perform post processing and output filtering and return the final hash value.
 * Parameters:
 *	state: a structure that holds the hashState information
 *	hashval: the storage for the final hash value to be returned
 * Returns:
 *	SUCCESS - on success
 */
HashReturn Final (hashState *state, BitSequence *hashval){
	switch (state->hashbitlen){
	case 256: return Final256(state->uu->state256, hashval);
	case 224: return Final224(state->uu->state256, hashval);
	case 512: return Final512(state->uu->state512, hashval);
	case 384: return Final384(state->uu->state512, hashval);
	default: return BAD_HASHBITLEN;
	}
}

/* Hash the supplied data and provide the resulting hash value. Set return code as
 * appropriate.
 * Parameters:
 *	hashbitlen: the length in bits of the desired hash value
 *	data: the data to be hashed
 *	databitlen: the length, in bits, of the data to be hashed
 *	hashval: the resulting hash value of the provided data
 * Returns:
 *	SUCCESS - on success
 *	BAD_HASHBITLEN – unknown hashbitlen requested
*/
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval){
	hashState state;
	HashReturn status;
	status = Init(&state, hashbitlen);
	if (status != SUCCESS) return status;
	status = Update(&state, data, databitlen);
	if (status != SUCCESS) return status;
	return Final(&state, hashval);
}






