/*
 * encrypt256.c
 *
 *		Implements the Encrypt256 function, used by Transform256
 *		Authors: Penazzi - Montes
 */

#include "global.h"

/* Expansion */

/* Processes 4 64 bits words, and returns one.
 * Used by EXPANSION
 * Input words:
 *	di10, di8, di3, di2
 * Output word:
 *	di
 */
#define PSI(di,di10,di8,di3,di2) \
	di=(di3+(di2<<32))^di10^di8^(di2>>32);\
	di+=(di<<32)+(di<<43);\
	di^=(di>>39);

/* Expands 8 64 bit words to 32
 * Input:
 *	D: an array of 64 bit words, with the first 8 already filled
 *	pk: the previous block
 *	bits: bits processed, including this block
 * Output:
 *	D: the array with the 32 words filled
 */
#define EXPANSION(D,pk,bits) \
   PSI(D[8],(D[3]^pk[0]),(D[4]^pk[1]),(D[5]^pk[2]),(D[1]^pk[3]));\
   PSI(D[9],(D[2]^0x428a2f98d728ae22ull^pk[4]),(D[7]^bits^pk[5]),(D[6]^pk[7]),(D[0]^pk[6]));\
   for( i = 10; i!=32;i++) {\
     PSI(D[i],D[i-10],D[i-8],D[i-3],D[i-2]);\
   }

/* Macros used in the round function */
#define F(X,Y,Z) ((~X)^(Y&(~Z)))
#define G(X,Y,Z) (Z^((~X)&(~Y)))
#define H(X,Y,Z) (Y^(X&Z))

/* Bitsliced Sbox */
#define Sbox(m0,m1,m2)    \
{ register uint64_t temp0, temp1;\
        temp0=F(m0,m1,m2);         \
        temp1=G(m0,m1,m2);         \
        m2=H(m0,m1,m2);         \
        m0=temp0;                  \
	    m1=temp1; }

#define PHTX(D)  \
       D+=(D<<32)+(D<<47);\
       D^=(D>>32)^(D>>43);

#define DIFFUSION(A,C,E,G) \
	A=((A&0xffffffff00000000)+(G&0xffffffff00000000))|((A+G)&0xffffffff);\
	PHTX(C);\
	G=((G&0xffffffff00000000)+(E&0xffffffff00000000))|((G+E)&0xffffffff);

/* Round function
 * Input:
 *	A,C,E,G: state, as 4 64 bit words
 *	k0,k2,k4: round key, as 3 64 bit words.
 * Output:
 *	A,C,E,G: state, modified by the S-Box
 */
#define ROUND(A,C,E,G,k0,k2,k4) \
    A^=k0;\
	C^=k2;\
	E^=k4;\
	G^=C;\
	PHTX(G);\
    Sbox(A,C,E) ;\
    DIFFUSION(A,C,E,G);


/* Calls the round function 4 times, rotating the words of the state,
 * and changing the round key.
 * Input:
 *	k0,k2,k4,k6,k8,k10,k12,k14,k16,k18,k20,k22: key material
 *	h0,h2,h4,h6: 256 bits state
 * Output:
 *	h0,h2,h4,h6: state, modified by the 4 round functions.
 */
#define FOURROUNDSBOX(k0,k2,k4,k6,k8,k10,k12,k14,k16,k18,k20,k22,h0,h2,h4,h6)\
	ROUND(h0,h2,h4,h6,k0, k2, k4);\
	ROUND(h2,h4,h6,h0,k6, k8, k10);\
	ROUND(h4,h6,h0,h2,k12,k14,k16);\
	ROUND(h6,h0,h2,h4,k18,k20,k22);

/* First four-round group, using the expanded D and the block k */
#define INPUTONE\
	FOURROUNDSBOX(D[0],k[0],D[1],D[2],k[1],D[3],D[4],k[2],D[5],D[6],k[3],D[7],hsh[0],hsh[1],hsh[2],hsh[3]);

/* Second four-round group, using the expanded D and the remaining words of block k  */
#define INPUTTWO\
	FOURROUNDSBOX(D[8],k[4],D[9],D[10],k[5],D[11],D[12],k[6],D[13],D[14],k[7],D[15],hsh[0],hsh[1],hsh[2],hsh[3]);

/* Third four-round group, using the expanded D and all the words of the previous block pk  */
#define INPUTTHREE\
	FOURROUNDSBOX(pk[0],D[16],pk[1],pk[2],D[17],pk[3],pk[4],D[18],pk[5],pk[6],D[19],pk[7],hsh[0],hsh[1],hsh[2],hsh[3]);

/* Fourth four-round group, using the remaining words of the expanded D  */
#define INPUTFOUR\
	FOURROUNDSBOX(D[20],D[21],D[22],D[23],D[24],D[25],D[26],D[27],D[28],D[29],D[30],D[31],hsh[0],hsh[1],hsh[2],hsh[3]);

/* Encrypt function. Encrypts the state, using the block, the previous block 
 * and the bits processed as key material. Modifies the state in place.
 * Input:
 *	hsh: Array of 4 64 bit words, storing the state.
 *	k: Array of 8 64 bit words, storing the current block.
 *	pk: Array of 8 64 bit words, storing the previous block.
 *	bits: 64 bit word representing the bits processes, up to and including the current block.
 * Output:
 *	hsh: the state, encrypted.
 */
void Encrypt256(uint64_t hsh[4], uint64_t k[8], uint64_t pk[8],
		uint64_t bits) {

	uint64_t D[32];
	int i;

	/* Start  */

	/*expansion*/
	D[0] = pk[0] ^ k[0];
	for (i = 7; i; i--)
		D[i] = pk[i] ^ k[i];

	EXPANSION(D,pk,bits);

	INPUTONE;

	INPUTTWO;

	INPUTTHREE;

	INPUTFOUR;

}

