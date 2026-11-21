/* laneref512.c   v1.1   October 2008
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
void print_debug512(lane512_state a) {
  int i,j;
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      printf("%02X",a[0][j][i]);
  printf(" ");
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      printf("%02X",a[1][j][i]);
  printf(" ");
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      printf("%02X",a[2][j][i]);
  printf(" ");
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++)
      printf("%02X",a[3][j][i]);
  printf("\n");
}
#endif /* SHOW_INTERMEDIATE */

/* Adds a 32-bit constant to each column of the state.
 * This operation is performed for each part of the LANE state.
 */
void AddConstants512(int r, lane512_state a) {
  int i, j, m;

  for(m=0; m!=4; m++) { /* for each AES state of the LANE-512 state */
    for(i=0; i!=4; i++) {
      for(j=0; j!=4; j++) {
        a[m][j][i] ^= select_byte_32( k[16*r+4*m+i], j);
      }
    }
  }
}

/* Adds part of the 64-bit counter to the state
 * This operation is performed for each part of the LANE state.
 */
void AddCounter512(int r, lane512_state a, DataLength counter) {
  int j;
  for(j=0; j!=4; j++) {
    a[0][j][3] ^= select_byte_64(counter,4*(r%2)+j);
  }
}

/* Row 0 remains unchanged, the other three rows are shifted a variable amount.
 * This operation is performed for each part of the LANE state.
 */
void ShiftRows512(lane512_state a) {

  uint8 tmp[4];
  int i, j, m;

  for(m=0; m!=4; m++) { /* for each AES state of the LANE-512 state */
    for(i=1; i!=4; i++) {
      for(j=0; j!=4; j++) tmp[j] = a[m][i][(j+i) % 4];
      for(j=0; j!=4; j++) a[m][i][j] = tmp[j];
    }
  }
}

/* Replace every byte of the input by the byte at that place in the nonlinear S-box.
 * This operation is performed for each part of the LANE state.
 */
void SubBytes512(lane512_state a) {
  int i, j, m;

  for(m=0; m!=4; m++) { /* for each AES state of the LANE-512 state */
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
void MixColumns512(lane512_state a) {
  uint8 b[4][4];
  int i, j, m;

  for(m=0; m!=4; m++) { /* for each AES state of the LANE-512 state */
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
void XorLaneState512(lane512_state a, lane512_state b) {
  int i, j, m;
  for(m=0; m!=4; m++) /* for each AES state of the LANE-512 state */
    for (i=0; i!=4; i++)
      for (j=0; j!=4; j++)
        a[m][i][j] ^= b[m][i][j];
}

/* Reorder the columns of a LANE state. */
void SwapColumns512(lane512_state a) {
  int i;
  for (i=0; i!=4; i++) {
    swap_bytes(&a[0][i][1],&a[1][i][0]);
    swap_bytes(&a[0][i][2],&a[2][i][0]);
    swap_bytes(&a[0][i][3],&a[3][i][0]);
    swap_bytes(&a[1][i][2],&a[2][i][1]);
    swap_bytes(&a[1][i][3],&a[3][i][1]);
    swap_bytes(&a[2][i][3],&a[3][i][2]);
  }
}

/* Apply permutation P to the input LANE state. */
void PermuteP512(int j,                /* permutation number */
                 lane512_state a,      /* the input LANE state */
                 DataLength counter) { /* the counter value used by AddCounter() */
  int i, r;

  #ifdef SHOW_INTERMEDIATE
  printf("Calculating LANE permutation P%i\n",j);
  #endif /* SHOW_INTERMEDIATE */
  /* rounds-1 ordinary rounds */
  for(i=0; i!=7; i++) {
    r = 7*j+i;
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, before SubBytes():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    SubBytes512(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after SubBytes():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    ShiftRows512(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after ShiftRows():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    MixColumns512(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after MixColumns():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    AddConstants512(r,a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after AddConstants():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    AddCounter512(r,a,counter);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after AddCounter():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    SwapColumns512(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE P%i, Round: %i, after SwapColumns():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
  }
  /* special last round: no AddConstants() nor AddCounter() */
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, before SubBytes():\n",j,5);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
  SubBytes512(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, after SubBytes():\n",j,5);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
  ShiftRows512(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, after ShiftRows():\n",j,5);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
  MixColumns512(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, after MixColumns():\n",j,5);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
  SwapColumns512(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE P%i, Round: %i, after SwapColumns():\n",j,5);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
}

/* Apply permutation Q to the input LANE state. */
void PermuteQ512(int j,                /* permutation number */
                 lane512_state a,      /* the input LANE state */
                 DataLength counter) { /* the counter value used by AddCounter() */
  int i, r;

  #ifdef SHOW_INTERMEDIATE
  printf("Calculating LANE permutation Q%i\n",j);
  #endif /* SHOW_INTERMEDIATE */
  /* rounds-1 ordinary rounds */
  for(i=0; i!=3; i++) {
    r = 42+3*j+i;
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, before SubBytes():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    SubBytes512(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after SubBytes():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    ShiftRows512(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after ShiftRows():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    MixColumns512(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after MixColumns():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    AddConstants512(r,a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after AddConstants():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    AddCounter512(r,a,counter);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after AddCounter():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
    SwapColumns512(a);
    #ifdef SHOW_INTERMEDIATE
    printf("LANE Q%i, Round: %i, after SwapColumns():\n",j,i);
    print_debug512(a);
    #endif /* SHOW_INTERMEDIATE */
  }
  /* special last round: no AddConstants() nor AddCounter() */
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, before SubBytes():\n",j,i);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
  SubBytes512(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, after SubBytes():\n",j,i);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
  ShiftRows512(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, after ShiftRows():\n",j,i);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
  MixColumns512(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, after MixColumns():\n",j,i);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
  SwapColumns512(a);
  #ifdef SHOW_INTERMEDIATE
  printf("LANE Q%i, Round: %i, after SwapColumns():\n",j,i);
  print_debug512(a);
  #endif /* SHOW_INTERMEDIATE */
}

/* Perform the message expansion. */
void ExpandMessage512(uint8 *hashval, /* storage for the intermediate hash value */
                      const uint8 buffer[128], /* the block to be hashed */
                      lane512_state W0,        /* W0 */
                      lane512_state W1,        /* W1 */
                      lane512_state W2,        /* W2 */
                      lane512_state W3,        /* W3 */
                      lane512_state W4,        /* W4 */
                      lane512_state W5) {      /* W5 */

  int i, j;

  /* calculate W_0 (four parts) */
  /* W_0a = h_0 ^ m_0 ^ m_1 ^ m_2 ^ m_3 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W0[0][j][i] = hashval[4*i+j] ^ buffer[4*i+j] ^ buffer[32+4*i+j]
                  ^ buffer[64+4*i+j] ^ buffer[96+4*i+j];
      W0[1][j][i] = hashval[16+4*i+j] ^ buffer[16+4*i+j] ^ buffer[16+32+4*i+j]
                  ^ buffer[16+64+4*i+j] ^ buffer[16+96+4*i+j];
      }
  /* W_0b = h_1 ^ m_0 ^ m_2 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W0[2][j][i] = hashval[32+4*i+j] ^ buffer[4*i+j] ^ buffer[64+4*i+j];
      W0[3][j][i] = hashval[16+32+4*i+j] ^ buffer[16+4*i+j] ^ buffer[16+64+4*i+j];
    }

  /* calculate W_1 (four parts) */
  /* W_1a = h_0 ^ h_1  ^ m_0 ^ m_2 ^ m_3 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W1[0][j][i] = hashval[4*i+j] ^ hashval[32+4*i+j] ^ buffer[4*i+j]
                  ^ buffer[64+4*i+j] ^ buffer[96+4*i+j];
      W1[1][j][i] = hashval[16+4*i+j] ^ hashval[16+32+4*i+j] ^ buffer[16+4*i+j]
                  ^ buffer[16+64+4*i+j] ^ buffer[16+96+4*i+j];
    }
  /* W_1b = h_0 ^ m_1 ^ m_2 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W1[2][j][i] = hashval[4*i+j] ^ buffer[32+4*i+j] ^ buffer[64+4*i+j];
      W1[3][j][i] = hashval[16+4*i+j] ^ buffer[16+32+4*i+j] ^ buffer[16+64+4*i+j];
    }

  /* calculate W_2 (four parts) */
  /* W_2a = h_0 ^ h_1  ^ m_0 ^ m_1 ^ m_2 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W2[0][j][i] = hashval[4*i+j] ^ hashval[32+4*i+j] ^ buffer[4*i+j]
                  ^ buffer[32+4*i+j] ^ buffer[64+4*i+j];
      W2[1][j][i] = hashval[16+4*i+j] ^ hashval[16+32+4*i+j] ^ buffer[16+4*i+j]
                  ^ buffer[16+32+4*i+j] ^ buffer[16+64+4*i+j];
      }
  /* W_2b = h_0 ^ m_0 ^ m_3 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W2[2][j][i] = hashval[4*i+j] ^ buffer[4*i+j] ^ buffer[96+4*i+j];
      W2[3][j][i] = hashval[16+4*i+j] ^ buffer[16+4*i+j] ^ buffer[16+96+4*i+j];
    }

  /* calculate W_3 (four parts) */
  /* W_3a = h_0 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W3[0][j][i] = hashval[4*i+j];
      W3[1][j][i] = hashval[16+4*i+j];
    }
  /* W_3b = h_1 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W3[2][j][i] = hashval[32+4*i+j];
      W3[3][j][i] = hashval[48+4*i+j];
    }

  /* calculate W_4 (four parts) */
  /* W_4a = m_0 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W4[0][j][i] = buffer[4*i+j];
      W4[1][j][i] = buffer[16+4*i+j];
    }
  /* W_4b = m_1 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W4[2][j][i] = buffer[32+4*i+j];
      W4[3][j][i] = buffer[48+4*i+j];
    }

  /* calculate W_5 (four parts) */
  /* W_5a = m_1 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W5[0][j][i] = buffer[64+4*i+j];
      W5[1][j][i] = buffer[80+4*i+j];
    }
  /* W_5b = m_2 */
  for (i=0; i!=4; i++)
    for (j=0; j!=4; j++) {
      W5[2][j][i] = buffer[96+4*i+j];
      W5[3][j][i] = buffer[112+4*i+j];
    }

}
/* Store the hash value. */
void StoreHash512(uint8 *hashval,     /* storage for the intermediate hash value */
                  lane512_state W0) { /* W0 */
  int i, j, m;
  for(m=0; m!=4; m++) /* for each AES state of the LANE-512 state */
    for (i=0; i!=4; i++)
      for (j=0; j!=4; j++)
        hashval[16*m+4*i+j] = W0[m][j][i];
}

/* Apply the algorithm's compression function to one block of input. */
void Lane512Transform(hashState *state, /* structure that holds hashState information */
                      const uint8 buffer[128],    /* the block to be hashed */
                      const DataLength counter) { /* counter value */
  lane512_state W0, W1, W2, W3, W4, W5;

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
  ExpandMessage512(state->hash, buffer, W0, W1, W2, W3, W4, W5);

  /* apply permutations */
  /* process the first layer */
  PermuteP512(0,W0,counter);
  PermuteP512(1,W1,counter);
  PermuteP512(2,W2,counter);
  PermuteP512(3,W3,counter);
  PermuteP512(4,W4,counter);
  PermuteP512(5,W5,counter);

  XorLaneState512(W0,W1);
  XorLaneState512(W0,W2);
  XorLaneState512(W3,W4);
  XorLaneState512(W3,W5);

  /* process the second layer */
  PermuteQ512(0,W0,counter);
  PermuteQ512(1,W3,counter);

  XorLaneState512(W0,W3);

  /* store resulting hash value */
  StoreHash512(state->hash, W0);

  #ifdef SHOW_INTERMEDIATE
  printf("Intermediate hash value after processing one full message block:\n");
  for (i=0; i!=state->hashbitlen/8; i++) {
    printf("%02X",state->hash[i]);
  }
  printf("\n\n");
  #endif /* SHOW_INTERMEDIATE */
}
