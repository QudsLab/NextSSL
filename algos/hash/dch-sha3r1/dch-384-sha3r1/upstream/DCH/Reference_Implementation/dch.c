/**
 *  Hash function reference implementation
 *  David Wilson, 2008
 */

#include "dch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

//Initialize hashing state with output length hashbitlen.  
//Return initialized state in state.
HashReturn Init(hashState *state, int hashbitlen){
  int i;

  //Make sure the input hash bit length is supported
  if((hashbitlen != 224) && (hashbitlen != 256) &&
     (hashbitlen != 384) && (hashbitlen != 512)){
    return BAD_HASHBITLEN;
  }

  //initialize hashing structures
  state->hashbitlen = hashbitlen;
  state->numUnprocessed = 0;
  state->unprocessed = malloc(BLOCK_LENGTH_BYTES * sizeof(BitSequence));
  state->curr = malloc(BLOCK_LENGTH_BYTES * sizeof(BitSequence));
  memset(state->curr, 0, BLOCK_LENGTH_BYTES);
  state->datalen = 0;

  //initialize square-free sequence state.  
  //See reference.h for definitions of these values or the documentation for 
  //  general information on the square-free sequence.
  state->p[0] = malloc(64*sizeof(unsigned char));
  state->p[1] = malloc(64*sizeof(unsigned char));
  state->p[2] = malloc(64*sizeof(unsigned char));
  for(i=0;i<63;i++){
    state->p[0][i]= 64-i;
  }
  state->p[1][0]=64;
  state->p[2][0]=64;
  state->top[0] = &(state->p[0][63]);
  state->top[1] = &(state->p[1][0]);
  state->top[2] = &(state->p[2][0]);
  state->parity = 1;
  state->small = 0;
  state->count = 0;
  state->move = 0x60;  //3 << 5

  return SUCCESS;
}

//Update the hash function's internal state with the new data, processing 
//  as much of it as possible.
HashReturn Update(hashState *state, const BitSequence *data, 
		  DataLength databitlen){

  int max;

  if (databitlen == 0){
    return SUCCESS;
  }

  //If this is the beginning of the data block, we need to add sequence padding
  if(state->numUnprocessed == 0){
    setNextSequenceValue(state);
    state->numUnprocessed = 8;
  }

  //Determine the maximum amount we can process, up to one block.
  max=8*BLOCK_LENGTH_BYTES - state->numUnprocessed;
  if (databitlen < max){
    max = databitlen;
  }
  databitlen -= max;

  //copy the new data (up to one block) to our internal state
  state->datalen += max;
  memcpy(state->unprocessed + (state->numUnprocessed / 8), data, (max+7) / 8);
  state->numUnprocessed += max;
  data += max/8;
  
  //If we've got a complete block of data, process it, then read more (up 
  // to one block).  Repeat until we've read all the full blocks of data.
  while(state->numUnprocessed == PADDED_BLOCK_LENGTH_BITS){

    //process block
    hashOneBlock(state);

    //read next chunk of data
    if(databitlen > 0){
      setNextSequenceValue(state);
      state->numUnprocessed = 8;
      max = PADDED_BLOCK_LENGTH_BITS - 8;
      if(databitlen < max){
	max = databitlen;
      }
      databitlen -= max;
      state->datalen += max;

      memcpy(state->unprocessed + (state->numUnprocessed / 8), data, (max+7)/8);
      state->numUnprocessed = max + 8;
      data += max/8;
    } else {
      state->numUnprocessed = 0;
    }

  }

  return SUCCESS;
}

//perform MD strengthening and final hashing, return result in hashval
HashReturn Final(hashState *state, BitSequence *hashval){

  int i;

  if(state->numUnprocessed == 0){
    state->numUnprocessed = 8;
    setNextSequenceValue(state);
  }

  //pad the last block with 1, 0s
  state->unprocessed[state->numUnprocessed / 8] |= 
    (0x80U >> (state->numUnprocessed % 8));
  state->unprocessed[state->numUnprocessed / 8] &= 
    (0xFF ^ ((1 << (7 - (state->numUnprocessed % 8))) - 1));
  memset(&state->unprocessed[state->numUnprocessed/8 + 1], 0, 
	 BLOCK_LENGTH_BYTES - state->numUnprocessed/8 - 1);

  state->numUnprocessed++;

  if(PADDED_BLOCK_LENGTH_BITS - state->numUnprocessed < 64){
    //we're near the end of this block, so the length will 
    //have to go to the next block.  Process this block first, 
    //then prepare the final block.

    hashOneBlock(state);
    memset(&state->unprocessed[0], 0, BLOCK_LENGTH_BYTES);
    setNextSequenceValue(state);
  }
  
  //copy length.  Be aware of endianness!
  for(i=0;i<sizeof(DataLength);i++){
    state->unprocessed[BLOCK_LENGTH_BYTES - 1 - i] = 
      ((BitSequence *)(&state->datalen))[i];
  }

  //set final sequence "move" to be 000.  Keep the counter the same.
  state->unprocessed[0] &= 0x1F;  //00011111

  //hash the final (length) block
  hashOneBlock(state);

  //copy the result into hashval
  memcpy(hashval, state->curr, state->hashbitlen / 8);


  free(state->unprocessed);
  free(state->curr);
  free(state->p[0]);
  free(state->p[1]);
  free(state->p[2]);

  return SUCCESS;
}

// All-at-once hash.
HashReturn Hash(int hashbitlen, const BitSequence *data, 
		DataLength databitlen, BitSequence *hashval){
  hashState *state = malloc(sizeof(hashState));
  HashReturn status = Init(state,  hashbitlen);
  if (status == SUCCESS){
    status = Update(state, data, databitlen);
    if (status == SUCCESS){
      status = Final(state, hashval);
    }
  }
  free(state);
  return status;
}

//Hash a single block of input (in state->unprocessed).  Update state with results.
void hashOneBlock(hashState *state){
  int round;

  //add previous hash value with message plaintext
  // for Miyaguchi-Preneel iteration
  addInto(state->curr, state->unprocessed);

  //process input
  for(round = 0; round < NUM_ROUNDS; round++){
    doSBox(state->unprocessed);
    doTransform(state->unprocessed);
    addInto(state->unprocessed, ROUND_KEY[round]);
  }

  //add processed value to previous value and plaintext for M-P iteration
  addInto(state->curr, state->unprocessed);

  //clear number of unprocessed
  state->numUnprocessed=0;
}

// Obtain the next element of a square-free sequence.  Set it as the first byte.
void setNextSequenceValue(hashState *state){
  BitSequence a, b;
  //high-order three bits come from the Towers of Hanoi SF sequence
  //low-order five bits are a counter
  state->unprocessed[0] = state->move ^ state->count;
  state->count++;
  if(state->count == 32){
    state->count = 0;

    //counter has rolled over; generate next ToH sequence value
    if(state->parity){
      //on odd-numbered moves, the smallest disk rotates to the "next" peg

      state->move = (state->small + 3*((state->small + 1) % 3)) << 5;
      state->top[state->small]--;
      state->small++;
      state->small %= 3;
      state->top[state->small]++;
      *(state->top[state->small]) = 1;
    }
    else{
      //on even-numbered moves, the small disk is not involved--the smaller of
      //  the other two topmost disks goes on top of the other one

      a=1;
      b=2;
      if(state->small == 1){
	a=0;
      }
      else if(state->small == 2){
	b=0;
      }
      if(*(state->top[b]) > *(state->top[a])){
	//swap a, b so that b is the peg of the smaller disk
	b ^= a;
	a ^= b;
	b ^= a;
      }
      state->move = (b + 3*a) << 5;
      state->top[a]++;
      *(state->top[a]) = *(state->top[b]);
      state->top[b]--; 
    }
    state->parity ^= 1;
  }
}

//XORs two bit sequences and puts the result in "to".
void addInto(BitSequence *to, const BitSequence *from){
  int i;
  for(i=0; i<BLOCK_LENGTH_BYTES; i++){
    to[i] ^= from[i];
  }
}

//Perform the nonlinear substitution on each byte of a block.
void doSBox(BitSequence *data){
  int i;
  for(i=0; i<BLOCK_LENGTH_BYTES; i++){
    data[i] = SBOX[data[i]];
  }
}

//Perform the linear (Fourier-based) transform on a block.
void doTransform(BitSequence *data){
  int i, j;
  BitSequence *transformed;
  transformed = malloc(BLOCK_LENGTH_BYTES*sizeof(BitSequence));
  for(i=0; i<BLOCK_LENGTH_BYTES; i++){
    transformed[i] = data[BLOCK_LENGTH_BYTES - 1];
    for(j=BLOCK_LENGTH_BYTES-1; j>0; ){
      transformed[i] = mult(transformed[i], transformvals[i]/*gf[i]*/);
      transformed[i] ^= data[--j];
    }
  }

  memcpy(data, transformed, BLOCK_LENGTH_BYTES);
  free(transformed);
}

//Multiply two elements over GF(2^8)
BitSequence mult(BitSequence a, BitSequence b){
  if((a == 0)||(b == 0)){
    return 0;
  }
  return gf[((int)gfinv[a] + gfinv[b]) % 255];
}
