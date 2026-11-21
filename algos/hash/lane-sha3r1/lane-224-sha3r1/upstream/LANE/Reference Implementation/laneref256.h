/* laneref256.h   v1.1   October 2008
 * Reference ANSI C implementation of LANE
 *
 * Based on the AES reference implementation of Paulo Barreto and Vincent Rijmen.
 *
 * Author: Nicky Mouha
 *
 * This code is placed in the public domain.
 */

#ifndef LANEREF256_H
#define LANEREF256_H

typedef aes_state lane256_state[2];  /* a LANE-256 state consists of four AES states */

/* Adds a 32-bit constant to each column of the state.
 * This operation is performed for each part of the LANE state.
 */
void AddConstants256(int r, lane256_state a);

/* Adds part of the 64-bit counter to the state.
 * This operation is performed for each part of the LANE state.
 */
void AddCounter256(int r, lane256_state a, DataLength counter);

/* Row 0 remains unchanged, the other three rows are shifted a variable amount.
 * This operation is performed for each part of the LANE state.
 */
void ShiftRows256(lane256_state a);

/* Replace every byte of the input by the byte at that place in the nonlinear S-box.
 * This operation is performed for each part of the LANE state.
 */
void SubBytes256(lane256_state a);

/* Mix the four bytes of every column in a linear way
 * This operation is performed for each part of the LANE state.
 */
void MixColumns256(lane256_state a);

/* XOR all the elements of two LANE states together, put the result in the first one */
void XorLaneState256(lane256_state a, lane256_state b);

/* Reorder the columns of a LANE state. */
void SwapColumns256(lane256_state a);

/* Apply permutation P to the input LANE state. */
void PermuteP256(int j,               /* permutation number */
                 lane256_state a,     /* the input LANE state */
                 DataLength counter); /* the counter value used by AddCounter() */

/* Apply permutation Q to the input LANE state. */
void PermuteQ256(int j,               /* permutation number */
                 lane256_state a,     /* the input LANE state */
                 DataLength counter); /* the counter value used by AddCounter() */

/* Perform the message expansion. */
void ExpandMessage256(uint8 *hashval,      /* storage for the intermediate hash value */
                   const uint8 buffer[64], /* the block to be hashed */
                   lane256_state W0,       /* W0 */
                   lane256_state W1,       /* W1 */
                   lane256_state W2,       /* W2 */
                   lane256_state W3,       /* W3 */
                   lane256_state W4,       /* W4 */
                   lane256_state W5);      /* W5 */

/* Store the hash value. */
void StoreHash256(uint8 *hashval,    /* storage for the intermediate hash value */
                  lane256_state W0); /* W0 */

/* Apply the algorithm's compression function to one block of input. */
void Lane256Transform(hashState *state, /* structure that holds hashState information */
                      const uint8 buffer[64],    /* the block to be hashed */
                      const DataLength counter); /* counter value */

#endif /* LANEREF256_H */
