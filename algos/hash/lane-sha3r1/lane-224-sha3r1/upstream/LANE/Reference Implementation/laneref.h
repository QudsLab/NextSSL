/* laneref.h   v1.1   October 2008
 * Reference ANSI C implementation of LANE
 *
 * Based on the AES reference implementation of Paulo Barreto and Vincent Rijmen.
 *
 * Author: Nicky Mouha
 *
 * This code is placed in the public domain.
 */

#ifndef LANEREF_H
#define LANEREF_H

typedef unsigned char       uint8; /* an unsigned  8-bit integer */
typedef unsigned int       uint32; /* an unsigned 32-bit integer */
typedef unsigned long long uint64; /* an unsigned 64-bit integer */

typedef uint8  BitSequence;        /* an unsigned  8-bit integer */
typedef uint64 DataLength;         /* an unsigned 64-bit integer */

#include "tables.h"

typedef enum { SUCCESS        = 0, /* Execution successful */
               FAIL           = 1, /* Unspecified failure occurred */
               BAD_HASHBITLEN = 2, /* Bad length in bits of the hash value */
               BAD_DATABITLEN = 3  /* Incomplete byte before last call to Update() */
             } HashReturn;

typedef struct {
  int hashbitlen;          /* length in bits of the hash value */
  DataLength databitcount; /* number of data bits processed so far */
  uint8 buffer[128];       /* space for one block of data to be hashed */
  uint8 hash[64];          /* intermediate hash value */
} hashState;

typedef uint8 aes_state[4][4]; /* a 4x4 byte array containing the AES state */

/* Swap two bytes. */
void swap_bytes(uint8 *a, uint8 *b);

/* Select a byte from a 32-bit word, most significant byte has index 0. */
uint8 select_byte_32(uint32 word, int idx);

/* Select a byte from a 64-bit word, most significant byte has index 0. */
uint8 select_byte_64(DataLength word, int idx);

/* Multiply an element of GF(2^m) by 3, needed for MixColumns256() and MixColumns512(). */
uint8 mul2(uint8 a);

/* Multiply an element of GF(2^m) by 3, needed for MixColumns256() and MixColumns512(). */
uint8 mul3(uint8 a);

/* Initialize the hashState structure. */
HashReturn Init(hashState *state, /* structure that holds hashState information */
                int hashbitlen);  /* length in bits of the hash value */

/* Process data using the algorithm's compression function.
 * Precondition: Init() has been called.
 */
HashReturn Update(hashState *state,        /* structure that holds hashState information */
                  const BitSequence *data, /* the data to be hashed */
                  DataLength databitlen);  /* length of the data to be hashed, in bits */

/* Perform post processing and output filtering and return the final hash value.
 * Precondition: Init() has been called.
 * Final() may only be called once.
 */
HashReturn Final(hashState *state,       /* structure that holds hashState information */
                 BitSequence *hashval);  /* storage for the final hash value */

/* Hash the supplied data and provide the resulting hash code. */
HashReturn Hash(int hashbitlen,          /* length in bits of the hash value */
                const BitSequence *data, /* the data to be hashed */
                DataLength databitlen,   /* length of the data to be hashed, in bits */
                BitSequence *hashval);   /* resulting hash value */

#include "laneref256.h"
#include "laneref512.h"

#endif /* LANEREF_H */
