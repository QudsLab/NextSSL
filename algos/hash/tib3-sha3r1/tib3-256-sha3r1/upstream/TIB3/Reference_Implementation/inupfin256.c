/*
 * inupfin256.c
 *
 *		Implements the 224 and 256 bit versions of Init(), Update(), Final() and Hash()
 *		Authors: Penazzi - Montes
 */


#include <string.h>
#include "inupfin.h"


/* Sizes used across all the functions */
#define STATE_DWORDS STATE_DWORDS_256
#define STATE_BYTES STATE_BYTES_256
#define BLOCK_DWORDS BLOCK_DWORDS_256
#define BLOCK_BYTES BLOCK_BYTES_256
#define HASH_BYTES HASH_BYTES_256
#define BLOCK_BITS 512

/* Updates the bits processed before calling Transform. 
 * The increment is BLOCK_BITS in all the blocks except the last.
 */
#define UPDATEBITS   state->bits_processed += BLOCK_BITS;



void Encrypt256(uint64_t hsh[STATE_DWORDS], uint64_t k[BLOCK_DWORDS],uint64_t pk[BLOCK_DWORDS],uint64_t bits);
void Transform256(hashState256* state);

/* Bitmask for zeroing the unused bits of the last byte of the message */
const static unsigned char BITMASK[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe};
/* Bitmask for adding a 1 after the last bit of the message */
const static unsigned char BITPADDING[] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

/* IV for the 256 bit version */
const uint64_t i256[STATE_DWORDS] =
{
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
    0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull
};

/* IV for the 224 bit version */
const uint64_t  i224[STATE_DWORDS] =
{
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
    0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};



/* Initializes a hashState256 with the appropriate values for the 256 bit hash.
 * Parameters:
 *	state: a structure that holds the hashState256 information
 * Returns:
 *	SUCCESS - on success
 */
HashReturn Init256(hashState256 *state){
	state->previous_block = state->buffer; /* previous_block points to the first half of the buffer */
	state->data_block = state->buffer+BLOCK_DWORDS; /* data_block points to the second half of the buffer */
	state->bits_processed = 0; /* No bits, yet */
	state->bits_waiting_for_process = 0; /* No bits waiting */
	memcpy(state->state, i256, STATE_BYTES); /* Copying the IV */
	memcpy(state->previous_block, i224, STATE_BYTES); /* Initial state of the previous block. We copy the 224 bit IV, twice */
	memcpy(state->previous_block+STATE_DWORDS, i224, STATE_BYTES);
	return SUCCESS;
}

/* Initializes a hashState224 with the appropriate values for the 224 bit hash.
 * Parameters:
 *	state: a structure that holds the hashState224 information
 * Returns:
 *	SUCCESS - on success
 */
HashReturn Init224(hashState256 *state){
	state->previous_block = state->buffer; /* previous_block points to the first half of the buffer */
	state->data_block = state->buffer+BLOCK_DWORDS; /* data_block points to the second half of the buffer */
	state->bits_processed = 0; /* No bits, yet */
	state->bits_waiting_for_process = 0;  /* No bits waiting */
	memcpy(state->state, i224, STATE_BYTES); /* Copying the IV */
	memcpy(state->previous_block, i256, STATE_BYTES);/* Initial state of the previous block. We copy the 256 bit IV, twice */
	memcpy(state->previous_block+STATE_DWORDS, i256, STATE_BYTES);
	return SUCCESS;
}


/* Process the supplied data.
 * Parameters:
 *	state: a structure that holds the hashState256 information
 *	data: the data to be hashed
 *	databitlen: the length, in bits, of the data to be hashed. 
 *	It must be a multiple of 8, except, possibly, in the last call
 * Returns:
 *	SUCCESS - on success
 */
HashReturn Update256(hashState256 *state, const BitSequence *data,
		DataLength databitlen) {
	DataLength offset, databytes;
	unsigned int remaining, index;
	BitSequence* byte_buffer;
	databytes = (databitlen >> 3); /* number of bytes to process */

	/*bytes waiting to be processed
	 * According to specifications, except for the last time, update will never be called with
	 * a number of bits not multiple of 8. Therefore, the number of bits that have been
	 * fed into the buffer but not processed after the last call of update must be
	 * a multiple of 8. Also, this number should be less than BLOCK_BYTES
	 */
	index = (state->bits_waiting_for_process >> 3);

	remaining = BLOCK_BYTES - index; /* space available in the buffer */
	offset = 0;

	/* If we have bytes waiting from a previous call, and there are enough
	 * to fill a block, we copy them and call to Transform
	 */
	if ((index != 0) && (databytes >= remaining)) {
		byte_buffer = (BitSequence*) state->data_block; /* buffer as an array of char */
		memcpy(byte_buffer + index, data, remaining); /* We fill the buffer */
		UPDATEBITS;
		Transform256(state);
		offset += remaining; /* We consumed 'remaining' bytes from data */
		index = 0; /* There are not bytes waiting for process */
		state->bits_waiting_for_process = 0; /* Therefore, no bits */
	}

	/* We process as many blocks as we can */
	while (offset + BLOCK_BYTES <= databytes) {
		memcpy(state->data_block, data + offset, BLOCK_BYTES);
		UPDATEBITS;
		Transform256(state);
		offset += BLOCK_BYTES;
	}
	if (databitlen & 7)
		databytes++; /* The number of bits is not a multiple of 8. This can only happen in the last call to update */
	byte_buffer = (BitSequence*) state->data_block;

	/* If there are still bytes in data, we copy them to the buffer */
	memcpy(byte_buffer + index, data + offset,(size_t) (databytes - offset));
	state->bits_waiting_for_process += (uint32_t) (databitlen - 8 * offset);;
	return SUCCESS;
}


/* Process the block stored in the buffer. 
 * Parameters:
 *	state: a structure that holds the hashState256 information
 */
void Transform256(hashState256* state){
	uint64_t temp[STATE_DWORDS];  /* Temporal state, so we can apply the final xor */
	uint64_t* swap_aux;
	int i;
	/* We copy the state to the temp state, and call Encrypt256 */
	memcpy(temp,state->state,STATE_BYTES);
	Encrypt256(temp, state->data_block, state->previous_block,state->bits_processed);

	/* Now we perform the xor between the words of the original state,
	 * and the output of Encrypt256
	 */
	for (i = 0; i < STATE_DWORDS; i++)
		state->state[i] ^= temp[i];

	/* We swap the pointers, so the current data_block becomes the previous_block */
	swap_aux = state->data_block;
	state->data_block = state->previous_block;
	state->previous_block = swap_aux; /* now previous_block points to the block just processed */
}



/* Perform post processing and output filtering and return the final hash value.
 * This function is called from Final256() or Final224()
 * Parameters:
 *	state: a structure that holds the hashState256 information
 *	hashval: the storage for the final hash value to be returned
 *	hashbytes: the number of bytes to store in hashval
 *		(28 for the 224 bit hash, 32 for the 256 bit hash)
 * Returns:
 *	SUCCESS - on success
 */

HashReturn _Final256 (hashState256 *state, BitSequence *hashval, int hashbytes){
	int j;
	BitSequence* byte_buffer;
	unsigned int index, bits;

	/* if there is any data to be processed, we need to pad and process, 
	 * otherwise we	go to the last block*/
	if(state->bits_waiting_for_process){
		/* If bits_waiting_for_process is not a multiple of 8, index will be the last byte,
		 * and bits will be the number of valid bits in that byte.
		 */
		index = state->bits_waiting_for_process >> 3;
		bits =  state->bits_waiting_for_process & 7;
		byte_buffer = (BitSequence*) state->data_block;

		/* We zero the unused bits of the last byte, and set the fist unused bit to 1 */
		byte_buffer[index] = (byte_buffer[index] & BITMASK[bits]) | BITPADDING[bits];
		index++;
		memset(byte_buffer+index, 0, BLOCK_BYTES - index); /* We fill the rest of the block with zeros */

		/*the usual update of bits processed cannot be used here, since
		 *less than a full block of DATA has been processed
		 */
		state->bits_processed += state->bits_waiting_for_process; 

		Transform256(state);
	}/*endif(bits_waiting_for_process)*/
   
	/* All data (plus any padding) has been processed. A last call, so that the last block
	 * of data is treated like all the others (i.e., twice) is made. The new block is simply the number of
	 * bits processed, xor the last state. 
	 */
	state->data_block[0]=state->bits_processed;
	for(j=1;j < STATE_DWORDS;j++) state->data_block[j]=0; /* The size of the block is twice the size of the state */
	memcpy(state->data_block + STATE_DWORDS, state->state, STATE_BYTES);
	state->bits_processed = 0; /* This ensures that the final transform is the same regardless of the bits processed */
	
	Transform256(state);
	
	/* We output the appropriate number of bytes, truncating the state if necessary */
	for (j = 0; j < hashbytes; j++)
		hashval[j] = ((BitSequence*)state->state)[j];
	return SUCCESS;
}

/* Perform post processing and output filtering and return the final 256 bit hash value.
 * Parameters:
 *	state: a structure that holds the hashState256 information
 *	hashval: the storage for the final hash value to be returned
 * Returns:
 *	SUCCESS - on success
 */
HashReturn Final256(hashState256 *state, BitSequence *hashval){
	return _Final256(state,hashval,HASH_BYTES_256);
}

/* Perform post processing and output filtering and return the final 224 bit hash value.
 * Parameters:
 *	state: a structure that holds the hashState256 information
 *	hashval: the storage for the final hash value to be returned
 * Returns:
 *	SUCCESS - on success
 */
HashReturn Final224(hashState256 *state, BitSequence *hashval){
	return _Final256(state,hashval,HASH_BYTES_224);
}





/* Hash the supplied data and provide the resulting hash value. 256 bit version.
 * Parameters:
 *	data: the data to be hashed
 *	databitlen: the length, in bits, of the data to be hashed
 *	hashval: the resulting hash value of the provided data
 * Returns:
 *	SUCCESS - on success
*/

HashReturn Hash256(const BitSequence *data, DataLength databitlen, BitSequence *hashval){
	hashState256 state;
	HashReturn status;
	status = Init256(&state);
	if (status != SUCCESS) return status;
	status = Update256(&state, data, databitlen);
	if (status != SUCCESS) return status;
	return _Final256(&state, hashval,HASH_BYTES_256);
}

/* Hash the supplied data and provide the resulting hash value. 224 bit version
 * Parameters:
 *	data: the data to be hashed
 *	databitlen: the length, in bits, of the data to be hashed
 *	hashval: the resulting hash value of the provided data
 * Returns:
 *	SUCCESS - on success
*/
HashReturn Hash224(const BitSequence *data, DataLength databitlen, BitSequence *hashval){
	hashState256 state;
	HashReturn status;
	status = Init224(&state);
	if (status != SUCCESS) return status;
	status = Update256(&state, data, databitlen);
	if (status != SUCCESS) return status;
	return _Final256(&state, hashval,HASH_BYTES_224);
}






