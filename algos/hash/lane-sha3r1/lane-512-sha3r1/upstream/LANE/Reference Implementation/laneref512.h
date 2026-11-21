/* laneref512.h   v1.1   October 2008
 * Reference ANSI C implementation of LANE
 *
 * Based on the AES reference implementation of Paulo Barreto and Vincent Rijmen.
 *
 * Author: Nicky Mouha
 *
 * This code is placed in the public domain.
 */

#ifndef LANEREF512_H
#define LANEREF512_H

typedef aes_state lane512_state[4];  /* a LANE-512 state consists of four AES states */

/* Adds a 32-bit constant to each column of the state.
 * This operation is performed for each part of the LANE state.
 */
void AddConstants512(int r, lane512_state a);

/* Adds part of the 64-bit counter to the state.
 * This operation is performed for each part of the LANE state.
 */
void AddCounter512(int r, lane512_state a, DataLength counter);

/* Row 0 remains unchanged, the other three rows are shifted a variable amount.
 * This operation is performed for each part of the LANE state.
 */
void ShiftRows512(lane512_state a);

/* Replace every byte of the input by the byte at that place in the nonlinear S-box.
 * This operation is performed for each part of the LANE state.
 */
void SubBytes512(lane512_state a);

/* Mix the four bytes of every column in a linear way
 * This operation is performed for each part of the LANE state.
 */
void MixColumns512(lane512_state a);

/* XOR all the elements of two LANE states together, put the result in the first one */
void XorLaneState512(lane512_state a, lane512_state b);

/* Reorder the columns of a LANE state. */
void SwapColumns512(lane512_state a);

/* Apply permutation P to the input LANE state. */
void PermuteP512(int j,               /* permutation number */
                 lane512_state a,     /* the input LANE state */
                 DataLength counter); /* the counter value used by AddCounter() */

/* Apply permutation Q to the input LANE state. */
void PermuteQ512(int j,               /* permutation number */
                 lane512_state a,     /* the input LANE state */
                 DataLength counter); /* the counter value used by AddCounter() */

/* Perform the message expansion. */
void ExpandMessage512(uint8 *hashval,       /* storage for the intermediate hash value */
                   const uint8 buffer[128], /* the block to be hashed */
                   lane512_state W0,        /* W0 */
                   lane512_state W1,        /* W1 */
                   lane512_state W2,        /* W2 */
                   lane512_state W3,        /* W3 */
                   lane512_state W4,        /* W4 */
                   lane512_state W5);       /* W5 */

/* Store the hash value. */
void StoreHash512(uint8* hashval,    /* storage for the intermediate hash value */
                  lane512_state W0); /* W0 */

/* Apply the algorithm's compression function to one block of input. */
void Lane512Transform(hashState *state, /* structure that holds hashState information */
                      const uint8 buffer[128],   /* the block to be hashed */
                      const DataLength counter); /* counter value */

#endif /* LANEREF512_H */
