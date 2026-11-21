/* laneref.c   v1.1   October 2008
 * Reference ANSI C implementation of LANE
 *
 * Based on the AES reference implementation of Paulo Barreto and Vincent Rijmen.
 *
 * Author: Nicky Mouha
 *
 * This code is placed in the public domain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "laneref.h"

/* Swap two bytes. */
void swap_bytes(uint8 *a, uint8 *b) {
  uint8 tmp;
  tmp = *a;
  *a = *b;
  *b = tmp;
}

/* Select a byte from a 32-bit word, most significant byte has index 0. */
uint8 select_byte_32(uint32 word, int idx) {
  return (word >> (3-idx)*8) & 0xFF;
}

/* Select a byte from a 64-bit word, most significant byte has index 0. */
uint8 select_byte_64(DataLength word, int idx) {
  return (word >> (7-idx)*8) & 0xFF;
}

/* Multiply an element of GF(2^m) by 2, needed for MixColumns256() and MixColumns512(). */
uint8 mul2(uint8 a) {
  return a&0x80 ? (a<<1) ^ 0x1B : a<<1;
}

/* Multiply an element of GF(2^m) by 3, needed for MixColumns256() and MixColumns512(). */
uint8 mul3(uint8 a) {
  return mul2(a)^a;
}

/* Initialize the hashState structure. */
HashReturn Init(hashState *state, /* structure that holds hashState information */
                int hashbitlen) { /* length in bits of the hash value */
  int i;

  if (hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512) {
    return BAD_HASHBITLEN; /* unsupported length of the output hash value */
  }
  state->hashbitlen   = hashbitlen;   /* length in bits of the hash value  */
  state->databitcount = 0;            /* number of data bits processed so far */

  /* explicitly calculate IV */
  memset(state->hash, 0, 64);         /* set to zero to calculate the initial IV */
  memset(state->buffer, 0, 128);
  state->buffer[0] = 0x02; /* flag byte 0x02: IV derivation without salt */
  for (i=0; i!=4; i++) {
    state->buffer[i+1] = select_byte_32(state->hashbitlen, i);
  }
  if (hashbitlen <= 256) {
    Lane256Transform(state,state->buffer,0);
  } else {
    Lane512Transform(state,state->buffer,0);
  }

  return SUCCESS;
}

/* Process data using the algorithm's compression function.
 * Precondition: Init() has been called.
 */
HashReturn Update(hashState *state,        /* structure that holds hashState information */
                  const BitSequence *data, /* the data to be hashed */
                  DataLength databitlen) { /* length of the data to be hashed, in bits */

  DataLength bytes = databitlen >> 3; /* length of the data to be hashed, in bytes */
  const int BLOCKSIZE = state->hashbitlen <= 256 ? 64 : 128; /* the block size, in bytes */
  const DataLength buffill = BLOCKSIZE == 64 ?
    (state->databitcount >> 3) & 0x3f : (state->databitcount >> 3) & 0x7f;

  if (state->databitcount & 0x7) {
    return BAD_DATABITLEN; /* last call to Update() was already performed */
  }

  /* If the buffer is not empty, add the data to the buffer and process the buffer */
  if (buffill) {
    /* number of bytes to copy */
    const DataLength n = buffill + bytes > BLOCKSIZE ? BLOCKSIZE-buffill : bytes;
    memcpy(state->buffer + buffill, data, n);
    state->databitcount += n << 3;
    if (buffill + n == BLOCKSIZE) { /* the buffer is full */
      if (state->hashbitlen <= 256) {
        Lane256Transform(state, state->buffer, state->databitcount);
      } else {
        Lane512Transform(state, state->buffer, state->databitcount);
      }
    }
    data += n;
    bytes -= n;
  }

  /* Process as many full blocks as possible directly from the input message */
  while (bytes >= BLOCKSIZE) {
    state->databitcount += BLOCKSIZE << 3;
    if (state->hashbitlen <= 256) {
      Lane256Transform(state, data, state->databitcount);
    } else {
      Lane512Transform(state, data, state->databitcount);
    }
    data += BLOCKSIZE;
    bytes -= BLOCKSIZE;
  }

  /* And finally, save the last, incomplete message block */
  if (bytes || (databitlen & 0x7)) {
    memcpy(state->buffer, data, databitlen & 0x7 ? bytes+1 : bytes); /* also copy partial byte */
    state->databitcount += (bytes << 3) + (databitlen & 0x7);
  }

  return SUCCESS;
}

/* Perform post processing and output filtering and return the final hash value.
 * Precondition: Init() has been called.
 * Final() may only be called once.
 */
HashReturn Final(hashState *state,       /* structure that holds hashState information */
                 BitSequence *hashval) { /* storage for the final hash value */
  int i;
  const int BLOCKSIZE = state->hashbitlen <= 256 ? 64 : 128; /* the block size, in bytes */

  /* If there is unprocessed data in the buffer: zero-pad and compress the last block */
  if (BLOCKSIZE == 64) {
    if (state->databitcount & 0x1ff) {
      /* number of bytes in buffer that are (partially) filled */
      const DataLength n = (((state->databitcount - 1) >> 3) + 1) & 0x3f;
      if (n < BLOCKSIZE)
        memset(state->buffer + n, 0, BLOCKSIZE-n);
      /* zero-pad partial byte */
      state->buffer[(state->databitcount >> 3) & 0x3f]
        &= ~(0xff >> (state->databitcount & 0x7));
      Lane256Transform(state, state->buffer, state->databitcount);
    }
  } else {
    if (state->databitcount & 0x3ff) {
      /* number of bytes in buffer that are (partially) filled */
      const DataLength n = (((state->databitcount - 1) >> 3) + 1) & 0x7f;
      if (n < BLOCKSIZE)
        memset(state->buffer + n, 0, BLOCKSIZE-n);
      /* zero-pad partial byte */
      state->buffer[(state->databitcount >> 3) & 0x7f]
        &= ~(0xff >> (state->databitcount & 0x7));
      Lane512Transform(state, state->buffer, state->databitcount);
    }
  }

  /* output transformation */
  memset(state->buffer, 0, BLOCKSIZE);

  state->buffer[0] = 0x00; /* flag byte 0x00: output transformation without salt */
  /* message length in big endian */
  for (i=0; i!=8; i++) {
    state->buffer[i+1] = select_byte_64(state->databitcount, i);
  }

  /* output transformation */
  if (state->hashbitlen <= 256) {
    Lane256Transform(state, state->buffer, 0);
  } else {
    Lane512Transform(state, state->buffer, 0);
  }

  /* write back result */
  memcpy(hashval, state->hash, state->hashbitlen/8);

  return SUCCESS;
}

/* Hash the supplied data and provide the resulting hash code. */
HashReturn Hash(int hashbitlen,          /* length in bits of desired hash value */
                const BitSequence *data, /* the data to be hashed */
                DataLength databitlen,   /* length of the data to be hashed, in bits */
                BitSequence *hashval) {  /* resulting hash value */
  hashState state;
  HashReturn hashReturn;

  if ((hashReturn = Init(&state, hashbitlen)) != SUCCESS)         return hashReturn;
  if ((hashReturn = Update(&state, data, databitlen)) != SUCCESS) return hashReturn;
  if ((hashReturn = Final(&state, hashval)) != SUCCESS)           return hashReturn;
  return SUCCESS;
}

#ifdef SHOW_INTERMEDIATE
int main() {
  /* hash one block and two blocks using every LANE variant */
  int i, idx;
  int bitlens[4] = { 224, 256, 384, 512};
  const BitSequence data1[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  DataLength databitlen1 = strlen((char*)data1)*8;
  const BitSequence data2[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  DataLength databitlen2 = strlen((char*)data2)*8;
  BitSequence hashvalue[64];
  BitSequence *hashval = hashvalue;
  HashReturn hashReturn;

  for (idx=0; idx!=4; idx++) {
    /* a one block message */
    printf("--- One-block input message: %s, using LANE-%i ---\n\n", data1, bitlens[idx]);
    hashReturn = Hash(bitlens[idx], data1, databitlen1, hashval);
    switch (hashReturn) {
      case 0:
        fprintf(stderr,"Execution successful.\n");
        printf("Final hash value: ");
        for (i=0; i!=bitlens[idx]/8; i++) {
          printf("%02X",hashvalue[i]);
        }
        printf("\n\n\n");
        break;
      case 1:
        fprintf(stderr,"Unspecified failure occurred.\n"); return -1;
      case 2:
        fprintf(stderr,"Bad length in bits of the hash value.\n"); return -2;
      case 3:
        fprintf(stderr,"Incomplete byte before the last call to Update().\n"); return -3;
      default:
        fprintf(stderr,"Undocumented error.\n"); return -4; /* should not occur */
    }
    /* a two block message */
    printf("--- Two-block input message: %s, using LANE-%i ---\n\n", data1, bitlens[idx]);
    hashReturn = Hash(bitlens[idx], data2, databitlen2, hashval);
    switch (hashReturn) {
      case 0:
        fprintf(stderr,"Execution successful.\n");
        printf("Final hash value: ");
        for (i=0; i!=bitlens[idx]/8; i++) {
          printf("%02X",hashvalue[i]);
        }
        printf("\n\n\n");
        break;
      case 1:
        fprintf(stderr,"Unspecified failure occurred.\n"); return -1;
      case 2:
        fprintf(stderr,"Bad length in bits of the hash value.\n"); return -2;
      case 3:
        fprintf(stderr,"Incomplete byte before the last call to Update().\n"); return -3;
      default:
        fprintf(stderr,"Undocumented error.\n"); return -4; /* should not occur */
    }
  }
  return 0;
}
#endif /* SHOW_INTERMEDIATE */
