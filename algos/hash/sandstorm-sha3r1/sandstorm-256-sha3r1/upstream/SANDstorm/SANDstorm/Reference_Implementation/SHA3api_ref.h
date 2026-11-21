/*
 *	Name:  SHA3api_ref.h
 *
 *  Date:  10/30/08
 *
 *  Version:
 *
 *  Abstract:
 *		This file includes user definitions to perform the SANDstorm Hash Algorithm
 *
 *  History:
 *
 *  Authors: Sandia National Laboratories
 *		Rich Schroeppel
 *		Tim Draelos
 *		Sean Malone
 *		Andrea Walker
 *		Nathan Dauhtenhan
 *		Sammy Smith
 *		Mark Torgerson
 */

/* Type definitions */
typedef unsigned char BitSequence;
typedef unsigned long long DataLength; //typical 64 bit value
typedef unsigned long long ULL;
typedef unsigned int UI;

/* 512 bit hash Type defintions */
typedef unsigned int u32;
typedef unsigned long long u64;
typedef struct { u64 hi; u64 lo;} u128;

typedef enum { 
	SUCCESS = 0, 
	FAIL = 1, 
	BAD_HASHBITLEN = 2 
} HashReturn;

typedef struct {
	/********* 256 bit hash vars *************/
	DataLength blockIters[3];			// iterators to manage which level we are at in the algorithm
	int hashbitlen;						// length of the resultant hash
	int pipedBits;						// current number of bits in the pipe to be processed
	int initCompressFlag;				// lets program know if we have accomplished the first compress
	BitSequence queuedData[64];			// data that are left over from last call to update
	DataLength prevBlock[3][5][4];		// data to feed into the next compression round

	/********* 512 bit hash vars *************/
	unsigned char msgbytes[128];  // data bytes of the message
	int mbcnt;                    // number of message bytes in the buffer
	u128 msg[8];                  // message repacked into 8 words of 128 bits
	u128 msglen;                  // message length in bits
	u128 blkn1, blkn2;            // superblock numbers for level 1 and 2
	int lvl0flag;                 // level 0 has been processed;
	int lvl1cnt, lvl2cnt;         // number of blocks in current level 1 & 2 superblocks
	int lvl3flag;                 // level 3 has been used
	u128 prev[5*5*4];             // result of hash round function at each level
								  // 5 levels, 5 rounds, 4 128-bit words
	int outsize;                  // output size in bits; must be 384 or 512.
	u128 *lvlc;                   // pointer to level starting constants
} hashState;

/*===== SHA3api_ref Function Prototypes =====*/

/*
 * Initializes a hashState with the intended hash length of this particular 
 * instantiation. Additionally, any data independent setup is performed.
 * Parameters:
 * 		state: a structure that holds the hashState information
 * 		hashbitlen: an integer value that indicates the length of the hash output in bits.
 * Returns:
 * 		SUCCESS - on success
 * 		BAD_HASHBITLEN - hashbitlen is invalid (e.g., unknown Value)
 */
HashReturn Init(hashState *state, int hashbitlen);

/*
 * Process the supplied data.
 * Parameters:
 *		state: a structure that holds the hashState information
 *		data: the data to be hashed
 *		databitlen: the length, in bits, of the data to be hashed
 * Returns:
 *		SUCCESS - on success
 *		HashReturn Update(hashState *state, const BitSequence *data, 
 *			DataLength databitlen);
 */
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen);

/*
 * Perform any post processing and output filtering required and return the final hash value.
 * Parameters:
 *		state: a structure that holds the hashState information
 *		hashval: the storage for the final hash value to be returned
 * Returns:
 *		SUCCESS - on success
 *		HashReturn Final(hashState *state, BitSequence *hashval);
 */
HashReturn Final(hashState *state, BitSequence *hashval);

/*
 * Hash the supplied data and provide the resulting hash value. Set return code as
 * appropriate.
 * Parameters:
 *		hashbitlen: the length in bits of the desired hash value
 *		data: the data to be hashed
 *		databitlen: the length, in bits, of the data to be hashed
 *		hashval: the resulting hash value of the provided data
 * Returns:
 *		SUCCESS - on success
 *		FAIL – arbitrary failure
 *		BAD_HASHBITLEN – unknown hashbitlen requested
 *		...
 */
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);
