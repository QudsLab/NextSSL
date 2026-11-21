/* laneref256.c   v1.1   October 2008
 * Reference ANSI C implementation of LANE
 *
 * Based on the AES reference implementation of Paulo Barreto and Vincent Rijmen.
 *
 * Author: Nicky Mouha
 *
 * This code is placed in the public domain.
 */
#include "laneref.h"
#ifdef SHOW_INTERMEDIATE
#include <stdio.h>
#endif /* SHOW_INTERMEDIATE */

#ifdef SHOW_INTERMEDIATE
/* Show the intermediate values */
void print_debug256(lane256_state a) {
  int i,j;
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      printf("%02X",a[0][j][i]);
  printf(" ");
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      printf("%02X",a[1][j][i]);
  printf("\n");
}
#endif /* SHOW_INTERMEDIATE */

/* Adds a 32-bit constant to each column of the state.
 * This operation is performed for each part of the LANE state.
 */
void AddConstants256(int r, lane256_state a) {
  int i, j, m;

  for(m=0; m!=2; m++) { /* for each AES state of the LANE-256 state */
    for(i=0; i!=4; i++) {
      for(j=0; j!=4; j++) {
        a[m][j][i] ^= select_byte_32( k[8*r+4*m+i], j);
      }
    }
  }
}

/* Adds part of the 64-bit counter to the state
 * This operation is performed for each part of the LANE state.
 */
void AddCounter256(int r, lane256_state a, DataLength counter) {
  int j;
  for(j=0; j!=4; j++) {
    a[0][j][3] ^= select_byte_64(counter,4*(r%2)+j);
  }
}

/* Row 0 remains unchanged, the other three rows are shifted a variable amount.
 * This operation is performed for each part of the LANE state.
 */
void ShiftRows256(lane256_state a) {

  uint8 tmp[4];
  int i, j, m;

  for(m=0; m!=2; m++) { /* for each AES state of the LANE-256 state */
    for(i=1; i!=4; i++) {
      for(j=0; j!=4; j++) tmp[j] = a[m][i][(j+i) % 4];
      for(j=0; j!=4; j++) a[m][i][j] = tmp[j];
    }
  }
}

/* Replace every byte of the input by the byte at that place in the nonlinear S-box.
 * This operation is performed for each part of the LANE state.
 */
void SubBytes256(lane256_state a) {
  int i, j, m;

  for(m=0; m!=2; m++) { /* for each AES state of the LANE-256 state */
    for(i=0; i!=4; i++) {
      for(j=0; j!=4; j++) {
        a[m][i][j] = S[a[m][i][j]];
      }
    }
  }
}

/* Mix the four bytes of every column in a linear way
 * This operation is performed for each part of the LANE state.
 */
void MixColumns256(lane256_state a) {
  uint8 b[4][4];
  int i, j, m;

  for(m=0; m!=2; m++) { /* for each AES state of the LANE-256 state */
    for(j = 0; j != 4; j++)
      for(i = 0; i != 4; i++)
        b[i][j] = mul2(a[m][i][j])
                  ^ mul3(a[m][(i + 1) % 4][j])
                  ^ a[m][(i + 2) % 4][j]
                  ^ a[m][(i + 3) % 4][j];
    for(i = 0; i != 4; i++)
      for(j = 0; j != 4; j++) a[m][i][j] = b[i][j];
  }
}

/* XOR all the elements of two LANE states together, put the result in the first one */
void XorLaneState256(lane256_state a, lane256_state b) {
  int i, j, m;
  for(m=0; m!=2; m++) /* for each AES state of the LANE-256 state */
    for (i=0; i!=4; i++)
      for (j=0; j!=4; j++)
        a[m][i][j] ^= b[m][i][j];
}

/* Reorder the columns of a LANE state. */
void SwapColumns256(lane256_state a) {
  int i;
  for (i=0; i!=4; i++) {
    swap_bytes(&a[0][i][2],&a[1][i][0]);
    swap_bytes(&a[0][i][3],&a[1][i][1]);
  }
}

/* Apply permutation P to the input LANE state. */
void PermuteP256(int j,                /* permutation number */
                 lane256_state a,      /* the input LANE state */
                 DataLength counter) { /* the counter value used by AddCounter() */
  int i, r;

  #ifdef SHOW_INTERMEDIATE
  printf("Calculating LANE permutation P%i\n",j);
  #endif /* SHOW_INTERMEDIATE */
  /* rounds-1 ordinary rounds */
  for(i=0; i!=5; i++) {
    r = 5*j+i;
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, before SubBytes():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    SubBytes256(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after SubBytes():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    ShiftRows256(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after ShiftRows():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    MixColumns256(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after MixColumns():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    AddConstants256(r,a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after AddConstants():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    AddCounter256(r,a,counter);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after AddCounter():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    SwapColumns256(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after SwapColumns():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
  }
  /* special last round: no AddConstants() nor AddCounter() */
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, before SubBytes():\n",j,5);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
  SubBytes256(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, after SubBytes():\n",j,5);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
  ShiftRows256(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, after ShiftRows():\n",j,5);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
  MixColumns256(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, after MixColumns():\n",j,5);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
  SwapColumns256(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, after SwapColumns():\n",j,5);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
}

/* Apply permutation Q to the input LANE state. */
void PermuteQ256(int j,                /* permutation number */
                 lane256_state a,      /* the input LANE state */
                 DataLength counter) { /* the counter value used by AddCounter() */
  int i, r;

  #ifdef SHOW_INTERMEDIATE
  printf("Calculating LANE permutation Q%i\n",j);
  #endif /* SHOW_INTERMEDIATE */
  /* rounds-1 ordinary rounds */
  for(i=0; i!=2; i++) {
    r = 30+2*j+i;
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, before SubBytes():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    SubBytes256(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after SubBytes():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    ShiftRows256(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after ShiftRows():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    MixColumns256(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after MixColumns():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    AddConstants256(r,a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after AddConstants():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    AddCounter256(r,a,counter);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after AddCounter():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
    SwapColumns256(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after SwapColumns():\n",j,i);
    print_debug256(a);
    #endif /* SHOW_INTERMEDIATE */
  }
  /* special last round: no AddConstants() nor AddCounter() */
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, before SubBytes():\n",j,i);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
  SubBytes256(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, after SubBytes():\n",j,i);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
  ShiftRows256(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, after ShiftRows():\n",j,i);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
  MixColumns256(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, after MixColumns():\n",j,i);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
  SwapColumns256(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, after SwapColumns():\n",j,i);
  print_debug256(a);
  #endif /* SHOW_INTERMEDIATE */
}

/* Perform the message expansion. */
void ExpandMessage256(uint8 *hashval, /* storage for the intermediate hash value */
                      const uint8 buffer[64], /* the block to be hashed */
                      lane256_state W0,       /* W0 */
                      lane256_state W1,       /* W1 */
                      lane256_state W2,       /* W2 */
                      lane256_state W3,       /* W3 */
                      lane256_state W4,       /* W4 */
                      lane256_state W5) {     /* W5 */

  int i, j;

  /* calculate W_0 (first and second parts) */
  /* W_0a = h_0 ^ m_0 ^ m_1 ^ m_2 ^ m_3 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W0[0][j][i] = hashval[4*i+j] ^ buffer[4*i+j] ^ buffer[16+4*i+j]
                  ^ buffer[32+4*i+j] ^ buffer[48+4*i+j];
  /* W_0b = h_1 ^ m_0 ^ m_2 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W0[1][j][i] = hashval[16+4*i+j] ^ buffer[4*i+j] ^ buffer[32+4*i+j];

  /* calculate W_1 (first and second parts) */
  /* W_1a = h_0 ^ h_1  ^ m_0 ^ m_2 ^ m_3 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W1[0][j][i] = hashval[4*i+j] ^ hashval[16+4*i+j] ^ buffer[4*i+j]
                  ^ buffer[32+4*i+j] ^ buffer[48+4*i+j];
  /* W_1b = h_0 ^ m_1 ^ m_2 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W1[1][j][i] = hashval[4*i+j] ^ buffer[16+4*i+j] ^ buffer[32+4*i+j];

  /* calculate W_2 (first and second parts) */
  /* W_2a = h_0 ^ h_1  ^ m_0 ^ m_1 ^ m_2 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W2[0][j][i] = hashval[4*i+j] ^ hashval[16+4*i+j] ^ buffer[4*i+j]
                  ^ buffer[16+4*i+j] ^ buffer[32+4*i+j];
  /* W_2b = h_0 ^ m_0 ^ m_3 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W2[1][j][i] = hashval[4*i+j] ^ buffer[4*i+j] ^ buffer[48+4*i+j];

  /* calculate W_3 (first and second parts) */
  /* W_3a = h_0 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W3[0][j][i] = hashval[4*i+j];
  /* W_3b = h_1 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W3[1][j][i] = hashval[16+4*i+j];

  /* calculate W_4 (first and second parts) */
  /* W_4a = m_0 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W4[0][j][i] = buffer[4*i+j];
  /* W_4b = m_1 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W4[1][j][i] = buffer[16+4*i+j];

  /* calculate W_5 (first and second parts) */
  /* W_5a = m_1 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W5[0][j][i] = buffer[32+4*i+j];
  /* W_5b = m_2 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      W5[1][j][i] = buffer[48+4*i+j];

}
/* Store the hash value. */
void StoreHash256(uint8 *hashval,     /* storage for the intermediate hash value */
                  lane256_state W0) { /* W0 */
  int i, j, m;
  for(m=0; m!=2; m++) /* for each AES state of the LANE-256 state */
    for (i=0; i!=4; i++)
      for (j=0; j!=4; j++)
        hashval[16*m+4*i+j] = W0[m][j][i];
}

/* Apply the algorithm's compression function to one block of input. */
void Lane256Transform(hashState *state, /* structure that holds hashState information */
                      const uint8 buffer[64],     /* the block to be hashed */
                      const DataLength counter) { /* counter value */
  lane256_state W0, W1, W2, W3, W4, W5;

  #ifdef SHOW_INTERMEDIATE
  int i;
  printf("Intermediate hash value before processing one full message block:\n");
  for (i=0; i!=state->hashbitlen/8; i++) {
    printf("%02X",state->hash[i]);
  }
  printf("\n");
  printf("Compressing one full message block:\n");
  for (i=0; i!=64; i++) printf("%02X",buffer[i]);
  printf("\n");
  printf("Counter value: %llu\n\n",counter);
  #endif /* SHOW_INTERMEDIATE */

  /* expand message */
  ExpandMessage256(state->hash, buffer, W0, W1, W2, W3, W4, W5);

  /* apply permutations */
  /* process the first layer */
  PermuteP256(0,W0,counter);
  PermuteP256(1,W1,counter);
  PermuteP256(2,W2,counter);
  PermuteP256(3,W3,counter);
  PermuteP256(4,W4,counter);
  PermuteP256(5,W5,counter);

  XorLaneState256(W0,W1);
  XorLaneState256(W0,W2);
  XorLaneState256(W3,W4);
  XorLaneState256(W3,W5);

  /* process the second layer */
  PermuteQ256(0,W0,counter);
  PermuteQ256(1,W3,counter);

  XorLaneState256(W0,W3);

  /* store resulting hash value */
  StoreHash256(state->hash, W0);

  #ifdef SHOW_INTERMEDIATE
  printf("Intermediate hash value after processing one full message block:\n");
  for (i=0; i!=state->hashbitlen/8; i++) {
    printf("%02X",state->hash[i]);
  }
  printf("\n\n");
  #endif /* SHOW_INTERMEDIATE */
}
