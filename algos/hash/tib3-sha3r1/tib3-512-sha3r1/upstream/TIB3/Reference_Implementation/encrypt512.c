/*
 * encrypt512.c
 *
 *		Implements the Encrypt512 function, used by Transform512
 *      Authors: Penazzi - Montes
 */
#include "global.h"

/* Expansion */

/* Processes 8 64 bits words, and returns 2.
 * Used by EXPANSION
 * Input words:
 *	wi20,wi19,wi16,wi15,wi6,wi5,wi4,wi3
 * Output words:
 *	wi,wim1
 */
#define PHI(wi,wim1,wi20,wi19,wi16,wi15,wi6,wi5,wi4,wi3) \
      wi=wi20^wi16^wi6^wi3;\
      wim1=((wi5+wi4)^wi19^wi15)+wi+(wi<<23);\
      wi^=(wim1>>15);

/* Expands 16 64 bit words to 64
 * Input:
 *	W: an array of 64 bit words, with the first 16 already filled
 *	pk: the previous block
 *	bits: bits processed, including this block
 * Output:
 *	W: the array with the 64 words filled
 */
#define EXPANSION(W,pk,bits) \
	PHI(W[16],W[17],(W[6]^pk[0]),(W[7]^pk[1]),(W[8]^pk[2]),(W[9]^pk[3]),(W[10]^pk[4]),(W[11]^pk[5]),(W[2]^pk[6]),(W[3]^pk[7]));\
    PHI(W[18],W[19],(W[4]^0x428a2f98d728ae22ull^pk[8]),(W[5]^pk[9]),(W[14]^bits^pk[10]),(W[15]^pk[11]),(W[12]^pk[14]),(W[13]^pk[15]),(W[0]^pk[12]),(W[1]^pk[13]));\
    for( i = 20; i!=64; i=i+2) {\
        PHI(W[i],W[i+1],W[i-20],W[i-19],W[i-16],W[i-15],W[i-6],W[i-5],W[i-4],W[i-3]);\
    }

#define F(X,Y,Z) ((~X)^(Y&(~Z)))
#define G(X,Y,Z) (Z^((~X)&(~Y)))
#define H(X,Y,Z) (Y^(X&Z))

/*Sbox in bitslice mode */
#define Sbox(m0,m1,m2) \
  { register uint64_t temp0, temp1;\
		temp0=F(m0,m1,m2);\
        temp1=G(m0,m1,m2);\
        m2=H(m0,m1,m2);\
        m0=temp0;\
		m1=temp1; }

#define PHTX(D)  \
       D+=(D<<32)+(D<<47);\
       D^=(D>>32)^(D>>43);

#define PHTXD(L,H)  \
	H^=L;\
	PHTX(H);\
	L^=H;\
	PHTX(L);

#define DIFFUSION(A,B,C,D,E,F,G,H) \
	A+=G;\
	B+=H;\
	PHTXD(C,D);\
	G+=E;\
	H+=F;

/* Round function
 * Input:
 *	A,B,C,D,E,F,G,H: state, as 8 64 bit words
 *	k0,k1,k2,k3,k4,k5: round key, as 6 64 bit words.
 * Output:
 *	A,B,C,D,E,F,G,H: state, modified by the S-Box
 */
#define ROUND(A,B,C,D,E,F,G,H,k0,k1,k2,k3,k4,k5) \
    A^=k0;\
	B^=k1;\
	C^=k2;\
	D^=k3;\
	E^=k4;\
    F^=k5;\
	G^=C;\
	H^=D;\
	PHTXD(G,H);\
    Sbox(A,C,E) ;\
	Sbox(B,D,F) ;\
    DIFFUSION(A,B,C,D,E,F,G,H);

/* Calls the round function 4 times, rotating the words of the state,
 * and changing the round key.
 * Input:
 *	k0,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19,k20,k21,k22,k23: key material
 *	h0,h1,h2,h3,h4,h5,h6,h7: 512 bits state
 * Output:
 *	h0,h1,h2,h3,h4,h5,h6,h7: state, modified by the 4 round functions.
 */

#define FOURROUNDSBOX(k0,k1,k2,k3,k4,k5,k6,k7,k8,k9,k10,k11,k12,k13,k14,k15,k16,k17,k18,k19,k20,k21,k22,k23,h0,h1,h2,h3,h4,h5,h6,h7)\
	ROUND(h0,h1,h2,h3,h4,h5,h6,h7, k0, k1, k2, k3, k4, k5);\
	ROUND(h2,h3,h4,h5,h6,h7,h0,h1, k6, k7, k8, k9,k10,k11);\
	ROUND(h4,h5,h6,h7,h0,h1,h2,h3,k12,k13,k14,k15,k16,k17);\
	ROUND(h6,h7,h0,h1,h2,h3,h4,h5,k18,k19,k20,k21,k22,k23);

/* First four-round group, using the expanded W and the block k */
#define INPUTONE\
	FOURROUNDSBOX(W[0],W[1],k[0],k[1],W[2],W[3],W[4],W[5],k[2],k[3],W[6],W[7],W[8],W[9],k[4],k[5],W[10],W[11],W[12],W[13],k[6],k[7],W[14],W[15],hsh[0],hsh[1],hsh[2],hsh[3],hsh[4],hsh[5],hsh[6],hsh[7]);

/* Second four-round group, using the expanded W and the remaining words of block k  */
#define INPUTTWO\
	FOURROUNDSBOX(W[16],W[17],k[8],k[9],W[18],W[19],W[20],W[21],k[10],k[11],W[22],W[23],W[24],W[25],k[12],k[13],W[26],W[27],W[28],W[29],k[14],k[15],W[30],W[31],hsh[0],hsh[1],hsh[2],hsh[3],hsh[4],hsh[5],hsh[6],hsh[7]);

/* Third four-round group, using the expanded W and all the words of the previous block pk  */
#define INPUTTHREE\
	FOURROUNDSBOX(pk[0],pk[1],W[32],W[33],pk[2],pk[3],pk[4],pk[5],W[34],W[35],pk[6],pk[7],pk[8],pk[9],W[36],W[37],pk[10],pk[11],pk[12],pk[13],W[38],W[39],pk[14],pk[15],hsh[0],hsh[1],hsh[2],hsh[3],hsh[4],hsh[5],hsh[6],hsh[7]);

/* Fourth four-round group, using the remaining words of the expanded W  */
#define INPUTFOUR\
	FOURROUNDSBOX(W[40],W[41],W[42],W[43],W[44],W[45],W[46],W[47],W[48],W[49],W[50],W[51],W[52],W[53],W[54],W[55],W[56],W[57],W[58],W[59],W[60],W[61],W[62],W[63],hsh[0],hsh[1],hsh[2],hsh[3],hsh[4],hsh[5],hsh[6],hsh[7]);


/* Encrypt function. Encrypts the state, using the block, the previous block 
 * and the bits processed as key material. Modifies the state in place.
 * Input:
 *	hsh: Array of 8 64 bit words, storing the state.
 *	k: Array of 16 64 bit words, storing the current block.
 *	pk: Array of 16 64 bit words, storing the previous block.
 *	bits: 64 bit word representing the bits processed, up to and including the current block.
 * Output:
 *	hsh: the state, encrypted.
 */
void Encrypt512(uint64_t hsh[8], uint64_t k[16], uint64_t pk[16],
		uint64_t bits) {
	/* Start  */

	uint64_t W[64];
	int i;

	/*expansion*/
	W[0] = pk[0] ^ k[0];
	for (i = 15; i; i--)
		W[i] = pk[i] ^ k[i];

	EXPANSION(W,pk,bits);

	INPUTONE;

	INPUTTWO;

	INPUTTHREE;

	INPUTFOUR;

}
