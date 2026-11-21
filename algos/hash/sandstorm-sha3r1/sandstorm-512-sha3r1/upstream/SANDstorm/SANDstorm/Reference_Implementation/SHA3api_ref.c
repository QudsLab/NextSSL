/*
 *	Name:  SHA3api_ref.c
 *
 *  Date:  10/30/08
 *
 *  Version:
 *
 *  Abstract:
 *		This file includes reference functions to perform the SANDstorm Hash Algorithm
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

#include <stdio.h>
#include <stdlib.h>
#include "SHA3api_ref.h"
#include "SHA3_ref.h"

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
HashReturn Init(hashState *state, int hashBitLen){
	state->hashbitlen = hashBitLen;
	if(hashBitLen <=256){
		int i,j;
		state->pipedBits = 0;
		state->initCompressFlag = 0;
		state->blockIters[0] = 0;
		state->blockIters[1] = 0;
		state->blockIters[2] = 0;
		// set the constants depending upon the hash length desired
		switch(hashBitLen){
			case 224:
				for(i=0;i<5;i++){
					for(j=0;j<4;j++){
						initialVectorTempWords[i][j] = constants_224[i][j];
						mainConstantInputWords[i][j] = constants_224[i][j];
					}
				}
				break;
			case 256:
				for(i=0;i<5;i++){
					for(j=0;j<4;j++){
						initialVectorTempWords[i][j] = constants_256[i][j];
						mainConstantInputWords[i][j] = constants_256[i][j];
					}
				}
				break;
			default: 
				printf("\n\nWe do not have any of these hash bit lengths\n\n");
				return BAD_HASHBITLEN;
				break;
		}
	}else{
		int i;
		state->mbcnt = 0;
		state->msglen = k128(0,0);
		state->blkn1 = k128(0,1); state->blkn2 = k128(0,1);
		state->lvl0flag = 0;
		state->lvl1cnt = 0; state->lvl2cnt = 0;
		state->lvl3flag = 0;
		state->outsize = hashBitLen;
		if (hashBitLen==384) state->lvlc = sandwlvlc384; else state->lvlc = sandwlvlc512;
		// setup level 0 constants
		for (i=0;i<20;i++) state->prev[i] = (state->lvlc)[i];
									#if INTERMEDIATE_VALUES == 1
										GLOBAL_512_L1_BNUM = 0;
										GLOBAL_512_L2_BNUM = 0;
										GLOBAL_512_L3_BNUM = 0;
									#endif
	}
	return SUCCESS;
}

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
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen){
	UI neededBits, qDataIndex, bytesToCpy;
	ULL dataBitsLeft, dataIndex;

	/*check to see if we have a larger hash and use alternate 512 bit update*/
	if(state->hashbitlen > 256){
		sandwupdate( state, databitlen, data );
		return SUCCESS;
	}

	dataIndex = 0;
	dataBitsLeft = databitlen;
	qDataIndex = state->pipedBits / BYTELENGTH;

	// byteOffset = state->pipedBits >> 3;
	neededBits = MAXBITS - state->pipedBits;

	// This will check to see if we have enough bits to run compress (512), and if not it
	// will add those bits to the queue and then return
	if(dataBitsLeft < neededBits ){
		// if we are on the last call to update we could have a bits left that is not divisible
		// by 8. So if we have any bits we have to make sure we get the full last byte. 
		if( (dataBitsLeft & 7) > 0 ){
			bytesToCpy = ((UI)databitlen / BYTELENGTH) + 1; 
		}else{
			bytesToCpy = (UI)databitlen / BYTELENGTH;
		}
		memcpy(&(state->queuedData[qDataIndex]),data,(size_t)bytesToCpy);
		state->pipedBits += (int)databitlen;
		return SUCCESS;
	}

	/*	
	 *	This is true when the piped bits are greater than 0, but not yet 512, but because 
	 *	we passed the previous condition we know we have enough bits to process between
	 *	what is in the queue already and what has currently been input to the function
	 */
	if(state->pipedBits > 0){
		// figure out how many bytes are needed to complete 512 bits then put them into 
		// the message queue
		bytesToCpy = neededBits / BYTELENGTH;
		memcpy(&(state->queuedData[qDataIndex]),data,(size_t)bytesToCpy);		
		state->pipedBits = MAXBITS;
		dataIndex = bytesToCpy;
		dataBitsLeft -= neededBits;
		/*
		 *	now we need to check if this is the first call to compress, and if it is it will
		 *	require a special first run to set state variables to all subsequent calls to compress.
		 *	 if it is not the first time then do a normal compress
		 */	
		if(state->initCompressFlag == 0){
			initCompress(state);
		}else{
			compress(state);
		}
	}

	// fix this while loop so we don't have to set neededBits each time through
	while(dataBitsLeft>=MAXBITS){
		memcpy(state->queuedData,&(data[dataIndex]),MAXBYTES);
		dataBitsLeft -= MAXBITS;
		dataIndex += MAXBYTES;
		state->pipedBits = MAXBITS;

		// compress(state);
		if(state->initCompressFlag == 0){
			initCompress(state);
		}else{
			compress(state);
		}
	}

	state->pipedBits = (int)dataBitsLeft;
	if( (dataBitsLeft & 7) > 0 ){
		bytesToCpy = ((UI)dataBitsLeft / BYTELENGTH) + 1; 
	}else{
		bytesToCpy = (UI)dataBitsLeft / BYTELENGTH;
	}
	if(bytesToCpy != 0) memcpy(state->queuedData,&(data[dataIndex]),(size_t)bytesToCpy);

	return SUCCESS;
}

/*
 * Perform any post processing and output filtering required and return the final hash value.
 * Parameters:
 *		state: a structure that holds the hashState information
 *		hashval: the storage for the final hash value to be returned
 * Returns:
 *		SUCCESS - on success
 *		HashReturn Final(hashState *state, BitSequence *hashval);
 */
HashReturn Final(hashState *state, BitSequence *hashval){
	int lastDataByteIndex, i, j;
	BitSequence mask, ormask, validBits; 
	DataLength Mess[8], messageLength;

	if(state->hashbitlen > 256){
		sandwfinish(state);

		/* final hash is in state->prev[96-99], so convert to message */
		Mess[0]= state->prev[96].hi;
		Mess[1]= state->prev[96].lo;
		Mess[2]= state->prev[97].hi;
		Mess[3]= state->prev[97].lo;
		Mess[4]= state->prev[98].hi;
		Mess[5]= state->prev[98].lo;
		Mess[6]= state->prev[99].hi;
		Mess[7]= state->prev[99].lo;
		for(j=0;j<8;j++){
			for(i=7;i>=0;i--){
				int finalValIndex = (j*8) + (7-i);
				if(!(state->hashbitlen == 384 && j == 6))
					hashval[finalValIndex] = (char)(Mess[j] >> (i*8));
			}
		}
	}else{
		// if we have some bits leftover, pad them with a one bit value of 1 and then zeros till 512 bits
		validBits = (BitSequence)(state->pipedBits & 7);
		lastDataByteIndex = state->pipedBits >> 3;
		if(validBits > 0){
			// last byte index will be the index of the byte that we have an integral number of bits
			// left to deal with. i.e. we have 4 bits left on the character indexed by this value. 
			mask = WORDMASK << (7-validBits);
			// this mask will zero out the non message bits. 
			state->queuedData[lastDataByteIndex] = state->queuedData[lastDataByteIndex] & mask;
			// set the bit to one to start the padding then perform inclusive or on last character
			ormask = ORMASK << (7-validBits);
			state->queuedData[lastDataByteIndex] = state->queuedData[lastDataByteIndex] | ormask;
		}else{
			state->queuedData[lastDataByteIndex] = 0x80; 
		}

		// pad the rest of the message out with zeros
		for(i=lastDataByteIndex+1;i<64;i++)state->queuedData[i] = 0x00;		

		// If we haven't done Level 0 compress do it, and go straight to Level 4 from there
		if(state->initCompressFlag == 0){
			// no level zero has been performed so we run here and set the message for level 4
			initCompress(state);
			createMessageFromBlock(Mess,initialVectorTempWords); 
			messageLength = state->pipedBits;
		}else{
			messageLength = (state->blockIters[0] + 1) * MAXBITS + state->pipedBits;		// add 1 for level 0
			// perform one last run of compress then find out where last ouput is at
			compress(state);
			createMessageFromBlock(Mess,state->prevBlock[0]);
			// handle last set of do_block calls
			if(state->blockIters[1] > 0){
							#if INTERMEDIATE_VALUES == 1
								print_flag = 1;
								printf("Level 2: Block %llu:\n", state->blockIters[1]);
							#endif
				Do_Block_ModMix_Ref(Mess,state->prevBlock[1]);
				createMessageFromBlock(Mess,state->prevBlock[1]);
				if(state->blockIters[2] > 0){
							#if INTERMEDIATE_VALUES == 1
								print_flag = 1;
								printf("Level 3: Block %llu:\n", state->blockIters[2]);
							#endif
					Do_Block_ModMix_Ref(Mess,state->prevBlock[2]);
					createMessageFromBlock(Mess,state->prevBlock[2]);
				}
			}
		}
		// xor message length into level four constants
		for(i=0;i<5;i++){
			for(j=1;j<4;j+=2){
				levelOneToFourConst[3][i][j] = levelOneToFourConst[3][i][j] ^ messageLength; 
			}
		}
							#if INTERMEDIATE_VALUES == 1
								print_flag = 1;
								printf("Level 4:\n");
							#endif
		// final solution will be in levelOneToFourConst[3]
		Do_Block_ModMix_Ref(Mess,levelOneToFourConst[3]);	
		/* output = s1 ^ s2 ^ s3 ^ s4 4 ULLs */
		for(i=0;i<4;i++){
			Mess[i] = levelOneToFourConst[3][1][i] ^ levelOneToFourConst[3][2][i] ^ levelOneToFourConst[3][3][i] ^ levelOneToFourConst[3][4][i];	
		}
		// Final hash is in Mess so move it into hashval
		for(j=0;j<4;j++){
			for(i=7;i>=0;i--){
				int finalValIndex = (j*8) + (7-i);
				if(!(state->hashbitlen == 224 && j == 3 && i <= 3)){ 
					hashval[finalValIndex] = (char)(Mess[j] >> (i*8));
				}
			}
		}
	}
	return SUCCESS;
}
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
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval){
	hashState state;
	HashReturn ercode;

	// Initialize Hash Algorithm
	ercode = Init(&state,hashbitlen);

	// Hash the data
	if (ercode == SUCCESS)
		ercode = Update (&state, data, databitlen);
	
	// Finalize the hashing, passing the var hashval to hold the data
	if (ercode == SUCCESS)
		ercode = Final(&state,hashval);

	// return status code
	return ercode;
}

void initCompress(hashState *state){
	int i, j, k; 
	DataLength Mess[8];
	state->initCompressFlag = 1;

							#if INTERMEDIATE_VALUES == 1
								print_flag = 1;
								printf("Level 0:\n");
							#endif

	// Copy the data in the queue to a variable capable of holding it as 8 64 bit words (ULL)
	createMessageFromQueue(Mess,state);
		
	// perform initial do_block and store all outputs into the array LevelZeroConst, we won't need
	// these any more for the rest of the algorithm
	Do_Block_ModMix_Ref(Mess, initialVectorTempWords);
	
	// Now we need to set up the constants for levels 1 through 3 constants as some function of the
	// output of the initial block. The index works like for C0 words it is 
	// mainConstINW[0][i] C1=MCIW[1][i] for level 1
	for(i=0;i<4;i++){
		levelOneToFourConst[0][0][i] = mainConstantInputWords[0][i] ^ initialVectorTempWords[4][i]; //for level 1 constant 0 = co ^ s4
		levelOneToFourConst[0][1][i] = mainConstantInputWords[1][i] ^ initialVectorTempWords[1][i]; //for level 1 constant 1 = c1 ^ s1
		levelOneToFourConst[0][2][i] = mainConstantInputWords[2][i] ^ initialVectorTempWords[2][i]; //for level 1 constant 2 = c2 ^ s2
		levelOneToFourConst[0][3][i] = mainConstantInputWords[3][i] ^ initialVectorTempWords[3][i]; //for level 1 constant 3 = c3 ^ s3
		levelOneToFourConst[0][4][i] = mainConstantInputWords[4][i] ^ initialVectorTempWords[4][i]; //for level 1 constant 4 = c4 ^ s4
	}

	// level 2, 3, and 4
	for(i=0;i<5;i++){
		for(j=0;j<4;j++){
			// level 2
			levelOneToFourConst[1][i][j] = levelOneToFourConst[0][i][j];
			// level 3
			levelOneToFourConst[2][i][j] = levelOneToFourConst[0][i][j];
			// level 4 
			levelOneToFourConst[3][i][j] = mainConstantInputWords[i][j];
		}
	}
	// special fixups for extra terms in constant table
	for (i=0;i<5;i++) {
	  levelOneToFourConst[1][i][3] ^= CCONST_256;
	  levelOneToFourConst[2][i][3] ^= DCONST_256;
	  levelOneToFourConst[3][i][3] ^= DCONST_256;
	  levelOneToFourConst[3][i][0] = ~levelOneToFourConst[3][i][0];
	  levelOneToFourConst[3][i][1] = ~levelOneToFourConst[3][i][1];
	}

	/* Copy over new constants into the prevBlock array for subsequent calls to compress */
	for(i=0;i<3;i++){
		for(j=0;j<5;j++){
			for(k=0;k<4;k++){
				state->prevBlock[i][j][k] = levelOneToFourConst[i][j][k];
			}
		}
	}
	
	// fixup for superblock numbers starting at 1 in levels 1 and 2
	for(i=0;i<2;i++){
		for(j=0;j<5;j++){
			for(k=1;k<4;k+=2){
				state->prevBlock[i][j][k] ^= 1;
			}
		}
	}
}

// At the exit from compress, level 1 has 1-10 blocks in the current superblock
// and level 2 has 0-99 blocks.  If we're doing final, and the last compress was
// from the possibly fractional final block and/or padding: We know that after
// the compress exit, the retained level 1 state is valid to forward up the tree
// to level 2 or 4.  Given the code in Final, we must be prepared for level 2 to
// accept the input from level 1, without checking if level 2 is already full.
// So level 2 <= 99 at compress exit.  So we must place the level-2-full check
// after the level 2 processing, before the level 3 check.

void compress(hashState *state){
	// First thing to do is convert the BitSequence character array to 8 64 bit ULLs
	int i, j;
	DataLength MessL1[8],MessL2[8],MessL3[8],levelOneSuperBlock, levelTwoSuperBlock;

	// Copy the data in the queue to a variable capable of holding it as 8 64 bit words (ULL)
	createMessageFromQueue(MessL1,state);

	if((state->blockIters[0]%10) == 0 && state->blockIters[0] > 1){

						#if INTERMEDIATE_VALUES == 1
							print_flag = 1;
							printf("Level 2: Block %llu:\n",state->blockIters[1]);
						#endif

		createMessageFromBlock(MessL2,state->prevBlock[0]);
		// run block function on the 100 block level
		Do_Block_ModMix_Ref(MessL2,state->prevBlock[1]);

		// Reset rounds 2 through 5 for the next set of 10 and xor the super block #
		levelOneSuperBlock = state->blockIters[0] / L1SBLENGTH + 1;
		for(i=0;i<5;i++){
			for(j=0;j<4;j++){
				if (j&1)
					state->prevBlock[0][i][j] = levelOneToFourConst[0][i][j] ^ levelOneSuperBlock;
				else
					state->prevBlock[0][i][j] = levelOneToFourConst[0][i][j];
			}
		}
		// increment the block counters
		state->blockIters[1]++;

		/* This will evaluate to true when there is enough information to run a comprees
		* at the last level of mod mix. If we have 100 level 1 blocks complete then we 
		* pass the outputs of rounds 4 and 5 up to the third level as the message to a 
		* mod mix block. 
		*/
		if((state->blockIters[1]%100) == 0 && (state->blockIters[1] > 1) ){
							#if INTERMEDIATE_VALUES == 1
								print_flag = 1;
								printf("Level 3: Block %llu:\n", state->blockIters[2]);
							#endif
			createMessageFromBlock(MessL3,state->prevBlock[1]);
			// run block function on level 3
			Do_Block_ModMix_Ref(MessL3,state->prevBlock[2]);
			// Reset rounds 2 through 5 for the next set of 100
			levelTwoSuperBlock = state->blockIters[1] / L2SBLENGTH + 1;
			for(i=0;i<5;i++){
				for(j=0;j<4;j++){
					if (j&1)
						state->prevBlock[1][i][j] = levelOneToFourConst[1][i][j] ^ levelTwoSuperBlock;
					else
						state->prevBlock[1][i][j] = levelOneToFourConst[1][i][j];
				}
			}	
			state->blockIters[2]++;
		}
	}

							#if INTERMEDIATE_VALUES == 1
								if(state->blockIters[0] == 0 || state->blockIters[0] == 9){
									print_flag = 1;
									printf("Level 1: Block %llu:\n",state->blockIters[0]);
								}
								else
									printf(" ...\n\n");
							#endif
	// run block function on the 10 block level
	Do_Block_ModMix_Ref(MessL1,state->prevBlock[0]);
	state->blockIters[0]++;
}

void createMessageFromQueue(DataLength m[8], hashState *state){
	int i; 

	// Copy the data in the queue to a variable capable of holding it as 8 64 bit words (ULL)
	for(i=0;i<8;i++){
		memcpy(&m[i],&(state->queuedData[i*8]),8);
	}

	for(i=0;i<8;i++){ 
		m[i] = ((((m[i]) & 0x00000000000000FFULL) << 56) | 
			   (((m[i]) & 0x000000000000FF00ULL) << 40) | 
			   (((m[i]) & 0x0000000000FF0000ULL) << 24) | 
			   (((m[i]) & 0x00000000FF000000ULL) << 8) | 
		       (((m[i]) & 0x000000FF00000000ULL) >> 8) | 
		       (((m[i]) & 0x0000FF0000000000ULL) >> 24) | 
		       (((m[i]) & 0x00FF000000000000ULL) >> 40) | 
		       (((m[i]) & 0xFF00000000000000ULL) >> 56));
	}
}

void createMessageFromBlock(DataLength M[8], DataLength input[5][4]){
	M[0] = input[1][0] ^ input[3][0];
	M[1] = input[1][1] ^ input[3][1];
	M[2] = input[1][2] ^ input[3][2];
	M[3] = input[1][3] ^ input[3][3];
	M[4] = input[2][0] ^ input[4][0];
	M[5] = input[2][1] ^ input[4][1];
	M[6] = input[2][2] ^ input[4][2];
	M[7] = input[2][3] ^ input[4][3];
}

void printPrevBlock(DataLength input[5][4], int level){
	int i,j;
	printf("\n\nThis is the output of the current constants for level %d", level);
	for(i=0;i<5;i++){
		printf("\n\tRound %d",i+1);
		for(j=0;j<4;j++){
			printf("\n\t\tWord[%d]: 0x%llx",j,input[i][j]);
		}
	}
	printf("\n");
}

void printMessage(DataLength Mess[8]){
	int i;
	printf("\n\nThe following is the current message:");
	for(i=0;i<8;i++){
		printf("\n\tMess[%d] = 0x%llx",i,Mess[i]);
	}
}

void printQueue(hashState *state, int id){
	int i;
	printf("\n\nID: %d\n  Queued Data:",id);
	for(i=0;i<64;i++){
		printf("%c",state->queuedData[i]);
	}
	printf("\n  Piped Bits:%d\n",state->pipedBits);
}
void print64BS(BitSequence bstmp[64], int id){
	int i;
	printf("\n\nID: %d\n  Queued Data:",id);
	for(i=0;i<64;i++){
		printf("%c",bstmp[i]);
	}
}

void Do_Block_ModMix_Ref (ULL data_input[8], ULL prevBlockArr[5][4]) {
	unsigned short i;
						#if INTERMEDIATE_VALUES == 1
							unsigned short j;
						#endif

	/*===== MESSAGE SCHEDULE =====*/

	/* First 8 M's of the message schedule are the input into this function */
	for (i=0; i < 8; i++)
		MSd[i] = data_input[i];

	/* Calculate the rest of the message schedule */
	for (i=8; i < 33; i++)
		MSd[i] = Msg_M(i);

	/* Set up inputs for the first round */
	for (i=0; i < 4; i++)
   		ws[i] = RotLeft(MSd[i], BITMIX_ROT_BITS) ^ MSd[i+4];
	bit_mix();

						#if INTERMEDIATE_VALUES == 1
							if (print_flag == 1){
								printf("\nCompression Function Data Input Words:\n");
								for (i=0; i < 8; i++)
									printf("d%d = %016llX\n", i, data_input[i]);
								printf("\nMessage Schedule:\n");
								printf("MS(0,D) = ");
								for (i=0; i < 4; i++)
									printf("%016llX ", ws[i]);
								for (j=1; j < 5; j++)
								{
									printf("\nMS(%d,D) = ", j);
									for (i=0; i < 4; i++)
										printf("%016llX ", MSd[9+j*5+i]);
								}
								printf("\nInput Constants:\n");
								for (i=0; i < 5; i++)
								{
									printf("c%d = ", i);
									for (j=0; j < 4; j++)
										printf("%016llX ", prevBlockArr[i][j]);
									printf("\n");
								}
							}
						#endif

	/*===== ROUND FUNCTIONS =====*/

	// Round 0
	for (i=0; i < 4; i++)
   		ws[i] ^= prevBlockArr[0][i];
	do_round(0);
	bit_mix();
	round_out(prevBlockArr[1], prevBlockArr[1]);

	// Round 1
	round_in(prevBlockArr[1], 14);
	do_round(1);
	bit_mix();
	round_out(prevBlockArr[2], prevBlockArr[1]);

	// Round 2
	round_in(prevBlockArr[1], 19);
	do_round(2);
	bit_mix();
	round_out(prevBlockArr[3], prevBlockArr[2]);

	// Round 3
	round_in(prevBlockArr[2], 24);
	do_round(3);
	bit_mix();
	round_out(prevBlockArr[4], prevBlockArr[3]);

	// Round 4
	round_in(prevBlockArr[3], 29);
	do_round(4);
	bit_mix();

	// Extended Security Rounds
	for(i=0;i<TUNABLE_SECURITY_PARAMETER;i++){
		do_round(4);
		bit_mix();
	}
	round4_out(prevBlockArr[4]);

						#if INTERMEDIATE_VALUES == 1
							if (print_flag == 1){
								printf("State Outputs:\n");
								for (i=1; i < 5; i++)
								{
									printf("s%d = ", i);
									for (j=0; j < 4; j++)
										printf("%016llX ", prevBlockArr[i][j]);
									printf("\n");
								}
								printf("\n");
								print_flag = 0;
							}
						#endif
}

/* bit_mix used to mix up the state words. */
void bit_mix() {
	ULL t;

	t = (ws[0] ^ ws[2]) & J6; ws[0] ^= t; ws[2] ^= t;
	t = (ws[1] ^ ws[3]) & J3; ws[1] ^= t; ws[3] ^= t;
	t = (ws[0] ^ ws[1]) & J5; ws[0] ^= t; ws[1] ^= t;
	t = (ws[2] ^ ws[3]) & J5; ws[2] ^= t; ws[3] ^= t;
}

/* Set the round buffer "w" for the next round. */
void round_in(ULL buffer[4], int ms_index) {
	ws[0] = buffer[0] ^ MSd[ms_index];
	ws[1] = buffer[1] ^ MSd[ms_index + 1];
	ws[2] = buffer[2] ^ MSd[ms_index + 2];
	ws[3] = buffer[3] ^ MSd[ms_index + 3];
}

/* Once the round buffer has been set, do the round. Round_num tells the function which M's to get from the message schedule */
void do_round(int r) {
	ws[0] = RotLeft(SB(ws[0]+F(ws[3])+Ch(ws[3],ws[2],ws[1])+B[32-(4*r)-8]),R_ROT_BITS);
	ws[1] = RotLeft(SB(ws[1]+F(ws[0])+Ch(ws[0],ws[3],ws[2])+B[32-(4*r+1)-8]),R_ROT_BITS);
	ws[2] = RotLeft(SB(ws[2]+F(ws[1])+Ch(ws[1],ws[0],ws[3])+B[32-(4*r+2)-8]),R_ROT_BITS);
	ws[3] = RotLeft(SB(ws[3]+F(ws[2])+Ch(ws[2],ws[1],ws[0])+B[32-(4*r+3)-8]),R_ROT_BITS);
}

/* Sets the given buffer equal to the current state of the round buffer */
void round_out(ULL prev_block[4], ULL current_block[4]) {
	current_block[0] = prev_block[0] ^ ws[0];
	current_block[1] = prev_block[1] ^ ws[1];
	current_block[2] = prev_block[2] ^ ws[2];
	current_block[3] = prev_block[3] ^ ws[3];
}

/* Sets the given buffer equal to the current state of the round buffer, after XORing it with buffer_in */
void round4_out(ULL current_block[4]) {
	current_block[0] = ws[0];
	current_block[1] = ws[1];
	current_block[2] = ws[2];
	current_block[3] = ws[3];
}

/* Rotate a 64-bit variable left by i bits */
ULL RotLeft(ULL n, int i) {
	return (n << i) | (n >> (64 - i));
}

/* Rotate a 64-bit variable 32 bits.  Left or Right makes no difference. */
ULL Rot32(ULL n) {
	return (n << 32) | (n >> (32));
}

/* F(x) used in round function */
ULL F(ULL z) {
	ULL x, y, f_res;

	x = z >> 32;
	y = z & msk32;
   f_res = x*x + y*y;
	return f_res;
}

/* F(x) used in message schedule */
ULL G(ULL z) {
	ULL x, y, g_res;

	x = z >> 32;
	y = z & msk32;
	g_res = (x*x + y*y + Rot32(((x + ACONST_256) & 0xffffffff)*((y + BCONST_256) & 0xffffffff)));
	return g_res;
}

/* Choose function, used in both round function and message schedule */
ULL Ch(ULL a, ULL b, ULL c) {
	return (a & b) ^ (~a & c);
}

/* SB(x), used in both round function and message schedule.  Replaces low byte with member of AES sbox array. */
ULL SB(ULL x) {
	return (x ^ fsbox[(unsigned char)(x & 0xff)]);
}

/* This is the main message schedule function */
ULL Msg_M(int i) {
	return RotLeft(SB(MSd[i-8]+B[i-8]+G(MSd[i-1])+Ch(MSd[i-1],MSd[i-2],MSd[i-3])+MSd[i-4]),MS_ROT_BITS);
}

// make a 128 bit constant from two 64 bit constants
u128 k128(u64 hi, u64 lo) { u128 hl; hl.hi = hi; hl.lo = lo; return hl; }

// add two 128 bit numbers, dropping any carry
u128 a128(u128 x, u128 y)
{ u128 sum;  sum.hi = x.hi + y.hi; sum.lo = x.lo + y.lo;
 if (sum.lo<x.lo) sum.hi++; return sum; }

// xor two 128 bit numbers
u128 x128(u128 x, u128 y)
{ u128 xor; xor.hi = x.hi ^ y.hi; xor.lo = x.lo ^ y.lo; return xor; }

// complement a 128 bit number
u128 c128(u128 x)
{ u128 comp; comp.hi = ~ x.hi; comp.lo = ~ x.lo; return comp; }

// and two 128 bit numbers
u128 b128(u128 x, u128 y)
{ u128 and; and.hi = x.hi & y.hi; and.lo = x.lo & y.lo; return and; }

// rotate left a 128 bit number
u128 r128(u128 x, int sh)
{ u128 rot; sh &= 127;
 if (sh==0)       { rot.hi = x.hi;
                    rot.lo = x.lo; }
 else if (sh<64)  { rot.hi = (x.hi << sh) | (x.lo >> (64-sh));
                    rot.lo = (x.lo << sh) | (x.hi >> (64-sh)); }
 else if (sh==64) { rot.hi = x.lo;
                    rot.lo = x.hi; }
 else             { rot.hi = (x.lo << (sh-64)) | (x.hi >> (128-sh));
                    rot.lo = (x.hi << (sh-64)) | (x.lo >> (128-sh)); };
 return rot; }

// multiply two 64 bit numbers, producing a 128 bit product
u128 m128(u64 x, u64 y)
{ u128 prod;
  u64 xhi = x>>32, xlo = x&msk32, yhi = y>>32, ylo = y&msk32;
  u64 tmp,tmp2;
  prod.hi = xhi*yhi; prod.lo = xlo*ylo; tmp = xlo*yhi; tmp2 = xhi*ylo;
  tmp += tmp2; if (tmp<tmp2) prod.hi += b32;
  prod.hi += tmp>>32;
  tmp <<= 32;
  prod.lo += tmp; if (prod.lo<tmp) prod.hi++;
  return prod; }

u128 sandwf(u128 x)
{ return a128(m128(x.hi,x.hi),m128(x.lo,x.lo)); }

u128 sandwg(u128 x)
{ return a128(m128(x.hi,x.hi),
              a128(m128(x.lo,x.lo),r128(m128(x.hi+ACONST_512,x.lo+BCONST_512),64))); }

// apply the AES sbox to the low byte of X
u128 sb128(u128 x)
{ u128 val; val.hi = x.hi; val.lo = x.lo ^ fsbox[x.lo & 255]; return val; }

// where to start picking in Message Schedule
int sandwmspick[] = { 4, 14, 19, 24, 29 };

// print a message schedule
void mscpr(u128 *ms)
{ int i; printf("ms ");
   for (i=0;i<33;i++) { printf(" %016llx %016llx",ms[i].hi,ms[i].lo);
   if (i&1) printf("\n   "); } printf("\n"); }

// Compute the message schedule.
// Assumes the message is present in the first 8 words (128 bits each)
// Apply the mixing function to compute words after the first 8.
// Finish xoring the first 4 words (rotated) into the second 4 words,
// and then using BitMix to move the bits between words.
void sandwmsgsch(u128 *MS)
{ int i;  u128 tmp;  // bitmix
 for (i=8;i<33;i++)
  MS[i] = r128(sb128(a128(    MS[i-8],
                      a128(   sandwmsc[i-8],
                       a128(  sandwg(MS[i-1]),
			a128( x128(b128(MS[i-1],MS[i-2]),   // Ch(i-1,i-2,i-3)
                                   b128(c128(MS[i-1]),MS[i-3])),
                              MS[i-4]))))),
               59 );
 for (i=0;i<4;i++) MS[i+4] = x128(r128(MS[i],37),MS[i+4]);
 // bitmix
 tmp = b128(x128(MS[4],MS[6]),J6_128); MS[4] = x128(MS[4],tmp); MS[6] = x128(MS[6],tmp);
 tmp = b128(x128(MS[5],MS[7]),J3_128); MS[5] = x128(MS[5],tmp); MS[7] = x128(MS[7],tmp);
 tmp = b128(x128(MS[4],MS[5]),J5_128); MS[4] = x128(MS[4],tmp); MS[5] = x128(MS[5],tmp);
 tmp = b128(x128(MS[6],MS[7]),J5_128); MS[6] = x128(MS[6],tmp); MS[7] = x128(MS[7],tmp);
}

// Run the compression function
// message (in *msg) is 8 128-bit words;
// prior block output is in prev[20*level+4*round+word]; result goes here too.
// inner state is w[0-3], 4 128-bit words
void sandwcmprs(u128 msg[], u128 prev[], int level, int xrnds)
{ int i,j,rnd; u128 MS[33], w[4];  u128 tmp;
 for (i=0;i<8;i++) MS[i] = msg[i]; 
 sandwmsgsch(MS);
						#if INTERMEDIATE_VALUES == 1 
							if(level == 1) GLOBAL_512_L1_BNUM++;
							else if(level == 2) GLOBAL_512_L2_BNUM++;
							else if(level == 3) GLOBAL_512_L3_BNUM++;
							if(level == 0){ printf("Level 0:\n"); print_flag = 1;}
							else if(level == 4){ printf("Level 4:\n"); print_flag = 1;}
							else if(level == 3){
								printf("Level %d: Block Number %llu:\n",level,GLOBAL_512_L3_BNUM-1);
								print_flag = 1;}
							else if(level == 2){
								printf("Level %d: Block Number %llu:\n",level,GLOBAL_512_L2_BNUM-1);
								print_flag = 1;}
							else if(level == 1 && (GLOBAL_512_L1_BNUM == 1 || GLOBAL_512_L1_BNUM == 10)){
								print_flag = 1;
								printf("Level 1: Block %llu:\n",GLOBAL_512_L1_BNUM-1);
							}
							else
								printf(" ...\n\n");

							if (print_flag == 1){
								printf("\nCompression Function Data Input Words:\n");
								for (i=0; i < 8; i++)
									printf("d%d = %016llX%016llX\n", i, msg[i].hi, msg[i].lo);
								printf("\nMessage Schedule:");
								printf("\nMS(0,D) = %016llX%016llX\n", MS[4].hi, MS[4].lo);
								for (i=1; i < 4; i++)
									printf("          %016llX%016llX\n", MS[4+i].hi, MS[4+i].lo);
								for (j=1; j < 5; j++)
								{
									printf("\nMS(%d,D) = ", j);
									printf("%016llX%016llX\n", MS[9+j*5].hi, MS[9+j*5].lo);
									for (i=1; i < 4; i++)
										printf("          %016llX%016llX\n", MS[9+j*5+i].hi, MS[9+j*5+i].lo);
								}
								printf("\nInput Constants:");
								for (rnd=0; rnd < 5; rnd++)
								{
									int constantIndex = 20*level + 4*rnd; 
									printf("\nc%d = ", rnd);
									printf("%016llX%016llX\n", prev[constantIndex].hi, prev[constantIndex].lo);
									for (i=1; i < 4; i++)
										printf("     %016llX%016llX\n", prev[constantIndex+i].hi, prev[constantIndex+i].lo);
								}
								printf("\n");
								printf("State Outputs:\n");
							}
						#endif

 for (i=0;i<4;i++) w[i] = prev[20*level+i];
 for (rnd=0;rnd<=4;rnd++)
 { for (i=0;i<4;i++) w[i] = x128(w[i],MS[sandwmspick[rnd]+i]);
   for (j=0;j<=((rnd<4)?0:xrnds);j++)
   {for (i=0;i<4;i++)
    w[i] = r128(sb128(a128(   w[i],
                       a128(  sandwf(w[(i+3)&3]),
                        a128( x128(b128(w[(i+3)&3],w[i^2]),
				   b128(c128(w[(i+3)&3]),w[(i+1)&3])),
			      sandwmsc[24-i-(rnd<<2)])))),57);
    // bitmix
    tmp = b128(x128(w[0],w[2]),J6_128); w[0] = x128(w[0],tmp); w[2] = x128(w[2],tmp);
    tmp = b128(x128(w[1],w[3]),J3_128); w[1] = x128(w[1],tmp); w[3] = x128(w[3],tmp);
    tmp = b128(x128(w[0],w[1]),J5_128); w[0] = x128(w[0],tmp); w[1] = x128(w[1],tmp);
    tmp = b128(x128(w[2],w[3]),J5_128); w[2] = x128(w[2],tmp); w[3] = x128(w[3],tmp);
   }
   if (rnd<4) for (i=0;i<4;i++) w[i] = x128(w[i],prev[20*level+4*rnd+4+i]);
   if (rnd) for (i=0;i<4;i++) prev[20*level+4*rnd+i] = w[i]; }
						#if INTERMEDIATE_VALUES == 1
							if (print_flag == 1){
								for (rnd=1;rnd<5;rnd++){
									printf("s%d = ", rnd);
									printf("%016llX%016llX\n", prev[20*level+4*rnd+i].hi, prev[20*level+4*rnd+i].lo);
									for (i=1; i < 4; i++)
										printf("     %016llX%016llX\n", prev[20*level+4*rnd+i].hi, prev[20*level+4*rnd+i].lo);
									printf("\n");
								}
								print_flag = 0;
							}
						#endif
}

void hstpr(hashState *hst)
{ int i;
 printf("\nsandstate %x:\n", hst);
 printf("mbcnt %d\n", hst->mbcnt);
 for (i=0;i<128;i++) { if (!i) printf("msgbytes ");
 printf(" %02x",hst->msgbytes[i]); if (i%20==16 || i==127) printf("\n"); };
 printf("msg ");
 for(i=0;i<8;i++) { printf(" %016llx %016llx",hst->msg[i].hi,hst->msg[i].lo);
                    if (i&1 && i<7) printf("\n    "); if (i==7) printf("\n"); }
 printf("msglen %lld %lld  blkn1 %lld %lld  blkn2 %lld %lld\n",
	hst->msglen.hi, hst->msglen.lo, hst->blkn1.hi,
	hst->blkn1.lo, hst->blkn2.hi, hst->blkn2.lo);
 printf("lvl0flag %d  lvl1cnt %d  lvl2cnt %d  lvl3flag %d\n",
	hst->lvl0flag, hst->lvl1cnt, hst->lvl2cnt, hst->lvl3flag);
 printf("prev:\n");
 for (i=0;i<100;i++) { printf(" %16llx %16llx",hst->prev[i].hi,hst->prev[i].lo);
                       if (i&1)printf("\n"); if (i%20==19)printf("\n"); };
 printf("outsize %d  lvlc %x\n\n", hst->outsize, hst->lvlc); }

int xtrnds=TUNABLE_SECURITY_PARAMETER;     // number of extra times to do round 4

// general philosophy is lazy evaluation
// we postpone all use of the compression function until absolutely needed

// process a block of message
// may trigger processing of higher levels if necessary
void sandwdoit( hashState *hstate )
{ int i; u128 w;
  // check if there's higher level work to do
  if (hstate->lvl1cnt==10)
  { if (hstate->lvl2cnt==100)
    { for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[44+i],hstate->prev[52+i]);
      if (!hstate->lvl3flag)  // setup level 3 starting round constants
      { for (i=0;i<20;i++) hstate->prev[60+i] = x128((hstate->lvlc)[i],hstate->prev[(i<4)?i+16:i]);
        for (i=0;i<20;i+=4) hstate->prev[63+i] = x128(hstate->prev[63+i],sandwblkd); }
      sandwcmprs(hstate->msg,hstate->prev,3,xtrnds);
      hstate->lvl2cnt=0; hstate->blkn2 = a128(hstate->blkn2,k128(0,1));
      hstate->lvl3flag=1; }
    if (!hstate->lvl2cnt)  // setup level2 superblock starting round constants
    { for (i=0;i<20;i++) hstate->prev[40+i] = x128((hstate->lvlc)[i],hstate->prev[(i<4)?i+16:i]);
      for (i=0;i<20;i+=4) hstate->prev[43+i] = x128(hstate->prev[43+i],sandwblkc);
      for (i=0;i<20;i+=2) hstate->prev[41+i] = x128(hstate->prev[41+i], hstate->blkn2); }
    for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[24+i],hstate->prev[32+i]);
    sandwcmprs(hstate->msg,hstate->prev,2,xtrnds);
    hstate->lvl1cnt=0; hstate->blkn1 = a128(hstate->blkn1,k128(0,1));
    hstate->lvl2cnt++; }
  for (i=0;i<8;i++) hstate->msg[i] = k128(0,0);
  for (i=0;i<128;i++)   // pack 128 message bytes into eight 128-bit words
  { w = k128(0,hstate->msgbytes[i]);
    hstate->msg[i>>4] = x128(hstate->msg[i>>4], r128(w,120-((i&15)<<3))); }
  hstate->mbcnt = 0;   // reset byte count to 0.
  // if lvl0flag = 0, we're doing level 0
  if (hstate->lvl0flag==0)
  { sandwcmprs(hstate->msg,hstate->prev,0,xtrnds); hstate->lvl0flag = 1; }
  else
  { if (!hstate->lvl1cnt)  // setup level1 superblock starting round constants
    { for (i=0;i<20;i++) hstate->prev[20+i] = x128((hstate->lvlc)[i],hstate->prev[(i<4)?i+16:i]);
      for (i=0;i<20;i+=2) hstate->prev[21+i] = x128(hstate->prev[21+i], hstate->blkn1); }
    sandwcmprs(hstate->msg,hstate->prev,1,xtrnds); hstate->lvl1cnt++; };
 }

// bits of data must be a multiple of 8, except for last partial byte
// update is responsible for zeroing unused low order bits in last byte
// mbcnt points to first unused byte, including after any partial byte
void sandwupdate( hashState *hstate, u64 bitsofdata, const unsigned char *data )
{ int j;
  for (j=0;j<bitsofdata;)
  { if (hstate->mbcnt>=128) sandwdoit(hstate); // we've got a full message block to process
    hstate->msgbytes[hstate->mbcnt] = *data; data++; j+=8;
    if (j>bitsofdata) // handle partial byte
      hstate->msgbytes[hstate->mbcnt] &= 0xFF<<(j-bitsofdata);
    hstate->mbcnt++; }
  hstate->msglen = a128(hstate->msglen,k128(0,bitsofdata)); }

// do padding, process any partial block, propagate up levels
void sandwfinish( hashState *hstate )
{ int i, padbitpos;
  // process message buffer if full
  if (hstate->mbcnt>=128 && !(hstate->msglen.lo & 7)) sandwdoit(hstate);
  for (i=hstate->mbcnt;i<128;i++) hstate->msgbytes[i]=0; // zero out unused message bytes
  padbitpos = (int)(hstate->msglen.lo & 7);
  if (!padbitpos) hstate->mbcnt++;
  hstate->msgbytes[hstate->mbcnt-1] |= 0x80 >> padbitpos;
  sandwdoit(hstate);

  // at this point, the message buffer is emptied out.
  // we've just completed either a level 0 block, or a level 1 block.
  // if a level 0 block, we can push on with impunity.
  // if a level 1 block, we need to ask about the situation with levels 2 and 3.
  // if we've never started level 2, we can just use the level 1 results, for
  // input to level 4, as we do below.  but if we've started level 2, and
  // there's a level 1 residue, we need to move that level 1 block up to level 2.
  // we might need to vacate the present level 2 occupant, moving him up to level 3.
  // and we might need to terminate level 2 and go directly to level 4;
  // or to push out any level 2 partial superblock into level 3.

  // if we've ever used level 2, we might need to cleanup partial blocks
  //  from levels 1-3.
  if (!(hstate->lvl2cnt==0 && hstate->blkn2.hi==0 && hstate->blkn2.lo==1))
  { // unless level 1 is empty, send partial superblock to level 2
    if (hstate->lvl1cnt)
    { // make sure there's room at level 2
      if (hstate->lvl2cnt==100)
      { for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[44+i],hstate->prev[52+i]);
        if (!hstate->lvl3flag)  // setup level 3 starting round constants
        { for (i=0;i<20;i++) hstate->prev[60+i] = x128((hstate->lvlc)[i],hstate->prev[(i<4)?i+16:i]);
          for (i=0;i<20;i+=4) hstate->prev[63+i] = x128(hstate->prev[63+i],sandwblkd); }
	sandwcmprs(hstate->msg,hstate->prev,3,xtrnds);
	hstate->lvl2cnt=0; hstate->blkn2 = a128(hstate->blkn2,k128(0,1));
	hstate->lvl3flag=1; }
      if (!hstate->lvl2cnt)  // setup level2 superblock starting round constants
      { for (i=0;i<20;i++) hstate->prev[40+i] = x128((hstate->lvlc)[i],hstate->prev[(i<4)?i+16:i]);
        for (i=0;i<20;i+=4) hstate->prev[43+i] = x128(hstate->prev[43+i],sandwblkc);
	for (i=0;i<20;i+=2) hstate->prev[41+i] = x128(hstate->prev[41+i], hstate->blkn2); }
      for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[24+i],hstate->prev[32+i]);
      sandwcmprs(hstate->msg,hstate->prev,2,xtrnds);
      hstate->lvl1cnt=0; hstate->blkn1 = a128(hstate->blkn1,k128(0,1));
      hstate->lvl2cnt++; }
    // we've forwarded any partial superblock from level 1 to level 2
    // if we've ever used level 3, we need to forward any partial level 2 superblock
    if (hstate->lvl3flag && hstate->lvl2cnt)

    { for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[44+i],hstate->prev[52+i]);
      sandwcmprs(hstate->msg,hstate->prev,3,xtrnds);
      hstate->lvl2cnt=0; hstate->blkn2 = a128(hstate->blkn2,k128(0,1)); }; };

  // any partial superblocks have been forwarded up the tree, unless they
  // are the first superblock at their level.

  // ready for level 4.  input might come from level 0, 1, 2, or 3.

  // setup level4 round constants
  for (i=0;i<20;i++) hstate->prev[80+i] = (hstate->lvlc)[i];
  for (i=0;i<20;i+=4) hstate->prev[83+i] = x128(hstate->prev[83+i],sandwblkd);
  for (i=0;i<20;i+=2) hstate->prev[81+i] = x128(hstate->prev[81+i], hstate->msglen);
  for (i=0;i<20;i++) if (!(i&2)) hstate->prev[80+i] = c128(hstate->prev[80+i]);
  // see if we've only used level 0
  if (hstate->lvl1cnt==0 && hstate->blkn1.hi==0 && hstate->blkn1.lo==1)
   for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[4+i],hstate->prev[12+i]);
  // or if we've only used levels 0 & 1
  else if (hstate->lvl2cnt==0 && hstate->blkn2.hi==0 && hstate->blkn2.lo==1)
   for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[24+i],hstate->prev[32+i]);
  // or if we've only used level 0, 1, & 2
  else if (hstate->lvl3flag==0)
   for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[44+i],hstate->prev[52+i]);
  else  // we've used level 3
   for (i=0;i<8;i++) hstate->msg[i] = x128(hstate->prev[64+i],hstate->prev[72+i]);
  sandwcmprs(hstate->msg,hstate->prev,4,xtrnds);
  // xor round values from rounds 1-4 to create final hash value
  for (i=0;i<4;i++)
    hstate->prev[96+i] = x128(hstate->prev[84+i],
			  x128(hstate->prev[88+i],
			   x128(hstate->prev[92+i],hstate->prev[96+i])));
  // final hash in prev[96-99]
}

void sandwprint( hashState *hstate )
{ if (hstate->outsize==384)
    printf(" %016llx %016llx %016llx\n %016llx %016llx %016llx\n",
	   hstate->prev[96].hi, hstate->prev[96].lo, hstate->prev[97].hi,
	   hstate->prev[97].lo, hstate->prev[98].hi, hstate->prev[98].lo);
  else printf(" %016llx %016llx %016llx %016llx\n %016llx %016llx %016llx %016llx\n",
  hstate->prev[96].hi, hstate->prev[96].lo, hstate->prev[97].hi, hstate->prev[97].lo,
  hstate->prev[98].hi, hstate->prev[98].lo, hstate->prev[99].hi, hstate->prev[99].lo);
}
