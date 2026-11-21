///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PROJECT : ARIRANG family(ARIRANG-224,ARIRANG-256,ARIRANG-384,ARIRANG-512)
//
// DATE    : 2008.10.23
//
///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FILE  : ARIRANG_Ref64.c
//
// NOTES : Reference code of ARIRANG family
// 
//         Based on 64-bit platform
//
///////////////////////////////////////////////////////////////////////////////////////////////////

#include <memory.h>
#include "Arirang_Ref64.h"

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Macro

#define ff_mult(a, b)	(a && b ? pow_tab[(log_tab[a] + log_tab[b]) % 255] : 0)
#define byte(x, n)		((BYTE)((x) >> (8 * n)))

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Constant


static const DWORD K256[16] = {0x517cc1b7, 0x76517cc1, 0xbd76517c, 0x2dbd7651,
							   0x272dbd76, 0xcb272dbd, 0x90cb272d, 0x0a90cb27,
							   0xec0a90cb, 0x5bec0a90, 0x9a5bec0a, 0xe69a5bec,
							   0xb7e69a5b, 0xc1b7e69a, 0x7cc1b7e6, 0x517cc1b7};

static const QWORD K512[16] = {0x517cc1b727220a94, 0x2db6517cc1b72722, 0xe6952db6517cc1b7, 0x90cbe6952db6517c, 
								  0x7cca90cbe6952db6, 0xcb237cca90cbe695, 0x765ecb237cca90cb, 0xec01765ecb237cca, 
								  0xb7e9ec01765ecb23, 0xbd7db7e9ec01765e, 0x9a5fbd7db7e9ec01, 0x5be89a5fbd7db7e9, 
								  0x0a945be89a5fbd7d, 0x27220a945be89a5f, 0xc1b727220a945be8, 0x517cc1b727220a94};




BYTE	sbx[256];  // Prepare S-box 
BYTE	F2[256];   // i*2 in GF(256)
BYTE	F3[256];   // i*3 in GF(256)
BYTE	F4[256];   // i*4 in GF(256)
BYTE	F8[256];   // i*8 in GF(256)
BYTE	F9[256];   // i*9 in GF(256)
BYTE    FA[256];   // i*10 in GF(256)

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : gen_tabs
//
// DESCRIPTION    : Generate the s-box table and field multiplication table
//
// PARAMETERS     : void
//                  
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////

void gen_tabs(void)
{   
	#ifndef __GEN_TABS__
	#define __GEN_TABS__ 100
	int i; 	
	BYTE p, q;
	BYTE log_tab[256];
	BYTE pow_tab[256];


	/* log and power tables for GF(2**8) finite field with  */
	/* 0x011b as modular polynomial - the simplest primitive */
	/* root is 0x03, used here to generate the tables       */

	for(i = 0,p = 1;i<256;i++){
		pow_tab[i] = (BYTE)p; 
		log_tab[p] = (BYTE)i; 
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x01b : 0);		
	}

	/* note that the affine byte transformation matrix in   */
	/* ARIRANG specification is in big endian format with  */
	/* bit 0 as the most significant bit. In the remainder  */
	/* of the specification the bits are numbered from the  */
	/* least significant end of a byte.                     */

	
	for(i=0;i<256;i++)
	{   
		p = (i ? pow_tab[255 - log_tab[i]] : 0); q = p; 
		q = (q >> 7) | (q << 1); p ^= q; 
		q = (q >> 7) | (q << 1); p ^= q; 
		q = (q >> 7) | (q << 1); p ^= q; 
		q = (q >> 7) | (q << 1); p ^= q ^ 0x63; 
		sbx[i] = p;
	}

	for(i=0;i<256;i++)
	{   
		F2[i] = ff_mult(i,2);
		F3[i] = ff_mult(i,3);
		F4[i] = ff_mult(i,4);
		F8[i] = ff_mult(i,8);
		F9[i] = ff_mult(i,9);
		FA[i] = ff_mult(i,10);
	}
	#endif
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : step256
//
// DESCRIPTION    : Step function of ARIRANG-224 and ARIRANG-256
//
// PARAMETERS     : R  - working variables
//                  M1,M2 - message block
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////
void step256(DWORD R[8], DWORD M1, DWORD M2){

	DWORD temp1,temp2;
	
	// Message XOR
	R[0] ^= M1;																										
	R[4] ^= M2;																								        
	
	// Sub-byte
	temp1 =    (DWORD)(sbx[byte(R[0], 0)]) ^ ((DWORD)(sbx[byte(R[0], 1)]) <<  8) ^ ((DWORD)(sbx[byte(R[0], 2)]) << 16) ^ ((DWORD)(sbx[byte(R[0], 3)]) << 24);	    
	temp2 =    (DWORD)(sbx[byte(R[4], 0)]) ^ ((DWORD)(sbx[byte(R[4], 1)]) <<  8) ^ ((DWORD)(sbx[byte(R[4], 2)]) << 16) ^ ((DWORD)(sbx[byte(R[4], 3)]) << 24);		
	
	// MDS transformation
	temp1 =  ( (DWORD)(F2[byte(temp1,0)]) ^ (DWORD)(F3[byte(temp1,1)]) ^ (DWORD)(   byte(temp1,2) ) ^ (DWORD)(   byte(temp1,3) )       ) ^				
		     (((DWORD)(   byte(temp1,0) ) ^ (DWORD)(F2[byte(temp1,1)]) ^ (DWORD)(F3[byte(temp1,2)]) ^ (DWORD)(   byte(temp1,3) )) <<  8) ^				
		     (((DWORD)(   byte(temp1,0) ) ^ (DWORD)(   byte(temp1,1) ) ^ (DWORD)(F2[byte(temp1,2)]) ^ (DWORD)(F3[byte(temp1,3)])) << 16) ^				
		     (((DWORD)(F3[byte(temp1,0)]) ^ (DWORD)(   byte(temp1,1) ) ^ (DWORD)(   byte(temp1,2) ) ^ (DWORD)(F2[byte(temp1,3)])) << 24);

	temp2 =  ( (DWORD)(F2[byte(temp2,0)]) ^ (DWORD)(F3[byte(temp2,1)]) ^ (DWORD)(   byte(temp2,2) ) ^ (DWORD)(   byte(temp2,3) )       ) ^				
		     (((DWORD)(   byte(temp2,0) ) ^ (DWORD)(F2[byte(temp2,1)]) ^ (DWORD)(F3[byte(temp2,2)]) ^ (DWORD)(   byte(temp2,3) )) <<  8) ^				
		     (((DWORD)(   byte(temp2,0) ) ^ (DWORD)(   byte(temp2,1) ) ^ (DWORD)(F2[byte(temp2,2)]) ^ (DWORD)(F3[byte(temp2,3)])) << 16) ^				
		     (((DWORD)(F3[byte(temp2,0)]) ^ (DWORD)(   byte(temp2,1) ) ^ (DWORD)(   byte(temp2,2) ) ^ (DWORD)(F2[byte(temp2,3)])) << 24);								
	
	R[1] ^= temp1;																										
	R[2] ^= ROTL_DWORD(temp1, 13);																						
	R[3] ^= ROTL_DWORD(temp1, 23);																						
	R[5] ^= temp2;																										
	R[6] ^= ROTL_DWORD(temp2, 29);																						
	R[7] ^= ROTL_DWORD(temp2, 7);

	// Register swap
	temp1=R[7];	 R[7]=R[6];	 R[6]=R[5];	 R[5]=R[4]; R[4]=R[3];
	R[3]=R[2];	R[2]=R[1];	R[1]=R[0];	R[0]=temp1;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : step512
//
// DESCRIPTION    : Step function of ARIRANG-384 and Arirang-512
//
// PARAMETERS     : R  - working variables
//                  M1,M2 - message block
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////
void step512(QWORD R[8], QWORD M1, QWORD M2){

	QWORD temp1,temp2;
	
	// Message XOR
	R[0] ^= M1;																										
	R[4] ^= M2;																								        
	
	// Sub-byte
	temp1 =     (QWORD)(sbx[byte(R[0], 0)])         ^ ((QWORD)(sbx[byte(R[0], 1)]) <<  8) ^ ((QWORD)(sbx[byte(R[0], 2)]) << 16) ^ ((QWORD)(sbx[byte(R[0], 3)]) << 24) ^
			   ((QWORD)(sbx[byte(R[0], 4)]) <<  32) ^ ((QWORD)(sbx[byte(R[0], 5)]) << 40) ^ ((QWORD)(sbx[byte(R[0], 6)]) << 48) ^ ((QWORD)(sbx[byte(R[0], 7)]) << 56);	
	temp2 =     (QWORD)(sbx[byte(R[4], 0)])         ^ ((QWORD)(sbx[byte(R[4], 1)]) <<  8) ^ ((QWORD)(sbx[byte(R[4], 2)]) << 16) ^ ((QWORD)(sbx[byte(R[4], 3)]) << 24) ^
			   ((QWORD)(sbx[byte(R[4], 4)]) <<  32) ^ ((QWORD)(sbx[byte(R[4], 5)]) << 40) ^ ((QWORD)(sbx[byte(R[4], 6)]) << 48) ^ ((QWORD)(sbx[byte(R[4], 7)]) << 56);	

	// MDS transformation
	temp1 = ( (QWORD)(   byte(temp1,0) ) ^ (QWORD)(F2[byte(temp1,1)]) ^ (QWORD)(FA[byte(temp1,2)]) ^ (QWORD)(F9[byte(temp1,3)]) ^ (QWORD)(F8[byte(temp1,4)]) ^ (QWORD)(   byte(temp1,5) ) ^ (QWORD)(F4[byte(temp1,6)]) ^ (QWORD)(   byte(temp1,7) )        ) ^
			(((QWORD)(   byte(temp1,0) ) ^ (QWORD)(   byte(temp1,1) ) ^ (QWORD)(F2[byte(temp1,2)]) ^ (QWORD)(FA[byte(temp1,3)]) ^ (QWORD)(F9[byte(temp1,4)]) ^ (QWORD)(F8[byte(temp1,5)]) ^ (QWORD)(   byte(temp1,6) ) ^ (QWORD)(F4[byte(temp1,7)])) <<  8 ) ^
			(((QWORD)(F4[byte(temp1,0)]) ^ (QWORD)(   byte(temp1,1) ) ^ (QWORD)(   byte(temp1,2) ) ^ (QWORD)(F2[byte(temp1,3)]) ^ (QWORD)(FA[byte(temp1,4)]) ^ (QWORD)(F9[byte(temp1,5)]) ^ (QWORD)(F8[byte(temp1,6)]) ^ (QWORD)(   byte(temp1,7) )) << 16 ) ^
			(((QWORD)(   byte(temp1,0) ) ^ (QWORD)(F4[byte(temp1,1)]) ^ (QWORD)(   byte(temp1,2) ) ^ (QWORD)(   byte(temp1,3) ) ^ (QWORD)(F2[byte(temp1,4)]) ^ (QWORD)(FA[byte(temp1,5)]) ^ (QWORD)(F9[byte(temp1,6)]) ^ (QWORD)(F8[byte(temp1,7)])) << 24 ) ^
			(((QWORD)(F8[byte(temp1,0)]) ^ (QWORD)(   byte(temp1,1) ) ^ (QWORD)(F4[byte(temp1,2)]) ^ (QWORD)(   byte(temp1,3) ) ^ (QWORD)(   byte(temp1,4) ) ^ (QWORD)(F2[byte(temp1,5)]) ^ (QWORD)(FA[byte(temp1,6)]) ^ (QWORD)(F9[byte(temp1,7)])) << 32 ) ^
			(((QWORD)(F9[byte(temp1,0)]) ^ (QWORD)(F8[byte(temp1,1)]) ^ (QWORD)(   byte(temp1,2) ) ^ (QWORD)(F4[byte(temp1,3)]) ^ (QWORD)(   byte(temp1,4) ) ^ (QWORD)(   byte(temp1,5) ) ^ (QWORD)(F2[byte(temp1,6)]) ^ (QWORD)(FA[byte(temp1,7)])) << 40 ) ^
			(((QWORD)(FA[byte(temp1,0)]) ^ (QWORD)(F9[byte(temp1,1)]) ^ (QWORD)(F8[byte(temp1,2)]) ^ (QWORD)(   byte(temp1,3) ) ^ (QWORD)(F4[byte(temp1,4)]) ^ (QWORD)(   byte(temp1,5) ) ^ (QWORD)(   byte(temp1,6) ) ^ (QWORD)(F2[byte(temp1,7)])) << 48 ) ^
			(((QWORD)(F2[byte(temp1,0)]) ^ (QWORD)(FA[byte(temp1,1)]) ^ (QWORD)(F9[byte(temp1,2)]) ^ (QWORD)(F8[byte(temp1,3)]) ^ (QWORD)(   byte(temp1,4) ) ^ (QWORD)(F4[byte(temp1,5)]) ^ (QWORD)(   byte(temp1,6) ) ^ (QWORD)(   byte(temp1,7) )) << 56 );
	
	temp2 = ( (QWORD)(   byte(temp2,0) ) ^ (QWORD)(F2[byte(temp2,1)]) ^ (QWORD)(FA[byte(temp2,2)]) ^ (QWORD)(F9[byte(temp2,3)]) ^ (QWORD)(F8[byte(temp2,4)]) ^ (QWORD)(   byte(temp2,5) ) ^ (QWORD)(F4[byte(temp2,6)]) ^ (QWORD)(   byte(temp2,7) )        ) ^
			(((QWORD)(   byte(temp2,0) ) ^ (QWORD)(   byte(temp2,1) ) ^ (QWORD)(F2[byte(temp2,2)]) ^ (QWORD)(FA[byte(temp2,3)]) ^ (QWORD)(F9[byte(temp2,4)]) ^ (QWORD)(F8[byte(temp2,5)]) ^ (QWORD)(   byte(temp2,6) ) ^ (QWORD)(F4[byte(temp2,7)])) <<  8 ) ^
			(((QWORD)(F4[byte(temp2,0)]) ^ (QWORD)(   byte(temp2,1) ) ^ (QWORD)(   byte(temp2,2) ) ^ (QWORD)(F2[byte(temp2,3)]) ^ (QWORD)(FA[byte(temp2,4)]) ^ (QWORD)(F9[byte(temp2,5)]) ^ (QWORD)(F8[byte(temp2,6)]) ^ (QWORD)(   byte(temp2,7) )) << 16 ) ^
			(((QWORD)(   byte(temp2,0) ) ^ (QWORD)(F4[byte(temp2,1)]) ^ (QWORD)(   byte(temp2,2) ) ^ (QWORD)(   byte(temp2,3) ) ^ (QWORD)(F2[byte(temp2,4)]) ^ (QWORD)(FA[byte(temp2,5)]) ^ (QWORD)(F9[byte(temp2,6)]) ^ (QWORD)(F8[byte(temp2,7)])) << 24 ) ^
			(((QWORD)(F8[byte(temp2,0)]) ^ (QWORD)(   byte(temp2,1) ) ^ (QWORD)(F4[byte(temp2,2)]) ^ (QWORD)(   byte(temp2,3) ) ^ (QWORD)(   byte(temp2,4) ) ^ (QWORD)(F2[byte(temp2,5)]) ^ (QWORD)(FA[byte(temp2,6)]) ^ (QWORD)(F9[byte(temp2,7)])) << 32 ) ^
			(((QWORD)(F9[byte(temp2,0)]) ^ (QWORD)(F8[byte(temp2,1)]) ^ (QWORD)(   byte(temp2,2) ) ^ (QWORD)(F4[byte(temp2,3)]) ^ (QWORD)(   byte(temp2,4) ) ^ (QWORD)(   byte(temp2,5) ) ^ (QWORD)(F2[byte(temp2,6)]) ^ (QWORD)(FA[byte(temp2,7)])) << 40 ) ^
			(((QWORD)(FA[byte(temp2,0)]) ^ (QWORD)(F9[byte(temp2,1)]) ^ (QWORD)(F8[byte(temp2,2)]) ^ (QWORD)(   byte(temp2,3) ) ^ (QWORD)(F4[byte(temp2,4)]) ^ (QWORD)(   byte(temp2,5) ) ^ (QWORD)(   byte(temp2,6) ) ^ (QWORD)(F2[byte(temp2,7)])) << 48 ) ^
			(((QWORD)(F2[byte(temp2,0)]) ^ (QWORD)(FA[byte(temp2,1)]) ^ (QWORD)(F9[byte(temp2,2)]) ^ (QWORD)(F8[byte(temp2,3)]) ^ (QWORD)(   byte(temp2,4) ) ^ (QWORD)(F4[byte(temp2,5)]) ^ (QWORD)(   byte(temp2,6) ) ^ (QWORD)(   byte(temp2,7) )) << 56 );
	
	R[1] ^= temp1;																										
	R[2] ^= ROTL_QWORD(temp1, 29);																						
	R[3] ^= ROTL_QWORD(temp1, 41);																						
	R[5] ^= temp2;																										
	R[6] ^= ROTL_QWORD(temp2, 53);																						
	R[7] ^= ROTL_QWORD(temp2, 13);

	// Register swap
	temp1=R[7];	 R[7]=R[6];	 R[6]=R[5];	 R[5]=R[4]; R[4]=R[3];
	 R[3]=R[2];	 R[2]=R[1];	 R[1]=R[0];	 R[0]=temp1;	
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Arirang_Compression256
//
// DESCRIPTION    : Counter addition and compression function of Arirang-224 and ARIRANG-256
//
// PARAMETERS     : state - a structure that holds the hashState information
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////
void Arirang_Compression256(hashState *state)
{
	DWORD	R[8], W[32];
	int i;

	// Counter Addition
	state->workingvar[0] ^= ((DWORD*)state->counter)[1];
	state->workingvar[4] ^= ((DWORD*)state->counter)[0];

	// Compression function
	#if defined(BIG_ENDIAN)
		#define GetData(x) x
	#else
		#define GetData(x) ENDIAN_REVERSE_DWORD(x)
	#endif

	// Message Schedue
	for (i = 0; i < 16; i++)
		W[i] = GetData(((DWORD*)state->block)[i]);

	W[16] = ROTL_DWORD((W[ 9] ^ W[11] ^ W[13] ^ W[15] ^ K256[ 0]),  5);
	W[17] = ROTL_DWORD((W[ 8] ^ W[10] ^ W[12] ^ W[14] ^ K256[ 1]), 11);
	W[18] = ROTL_DWORD((W[ 1] ^ W[ 3] ^ W[ 5] ^ W[ 7] ^ K256[ 2]), 19);
	W[19] = ROTL_DWORD((W[ 0] ^ W[ 2] ^ W[ 4] ^ W[ 6] ^ K256[ 3]), 31);

	W[20] = ROTL_DWORD((W[14] ^ W[ 4] ^ W[10] ^ W[ 0] ^ K256[ 4]),  5);
	W[21] = ROTL_DWORD((W[11] ^ W[ 1] ^ W[ 7] ^ W[13] ^ K256[ 5]), 11);
	W[22] = ROTL_DWORD((W[ 6] ^ W[12] ^ W[ 2] ^ W[ 8] ^ K256[ 6]), 19);
	W[23] = ROTL_DWORD((W[ 3] ^ W[ 9] ^ W[15] ^ W[ 5] ^ K256[ 7]), 31);

	W[24] = ROTL_DWORD((W[13] ^ W[15] ^ W[ 1] ^ W[ 3] ^ K256[ 8]),  5);
	W[25] = ROTL_DWORD((W[ 4] ^ W[ 6] ^ W[ 8] ^ W[10] ^ K256[ 9]), 11);
	W[26] = ROTL_DWORD((W[ 5] ^ W[ 7] ^ W[ 9] ^ W[11] ^ K256[10]), 19);
	W[27] = ROTL_DWORD((W[12] ^ W[14] ^ W[ 0] ^ W[ 2] ^ K256[11]), 31);

	W[28] = ROTL_DWORD((W[10] ^ W[ 0] ^ W[ 6] ^ W[12] ^ K256[12]),  5);
	W[29] = ROTL_DWORD((W[15] ^ W[ 5] ^ W[11] ^ W[ 1] ^ K256[13]), 11);
	W[30] = ROTL_DWORD((W[ 2] ^ W[ 8] ^ W[14] ^ W[ 4] ^ K256[14]), 19);
	W[31] = ROTL_DWORD((W[ 7] ^ W[13] ^ W[ 3] ^ W[ 9] ^ K256[15]), 31);

	
	// Register Initialize
	for(i=0;i<8;i++)	R[i] = (DWORD)state->workingvar[i];
	
	// 1 Round
	step256(R, W[16], W[17]);
	step256(R, W[ 0], W[ 1]);
	step256(R, W[ 2], W[ 3]);
	step256(R, W[ 4], W[ 5]);
	step256(R, W[ 6], W[ 7]);

	step256(R, W[18], W[19]);
	step256(R, W[ 8], W[ 9]);
	step256(R, W[10], W[11]);
	step256(R, W[12], W[13]);
	step256(R, W[14], W[15]);

	// 2 Round
	step256(R, W[20], W[21]);
	step256(R, W[ 3], W[ 6]);
	step256(R, W[ 9], W[12]);
	step256(R, W[15], W[ 2]);
	step256(R, W[ 5], W[ 8]);

	step256(R, W[22], W[23]);
	step256(R, W[11], W[14]);
	step256(R, W[ 1], W[ 4]);
	step256(R, W[ 7], W[10]);
	step256(R, W[13], W[ 0]);

	// Feedforward_1
	for(i=0;i<8;i++)	R[i] ^= state->workingvar[i];

	// 3 Round
	step256(R, W[24], W[25]);
	step256(R, W[12], W[ 5]);
	step256(R, W[14], W[ 7]);
	step256(R, W[ 0], W[ 9]);
	step256(R, W[ 2], W[11]);

	step256(R, W[26], W[27]);
	step256(R, W[ 4], W[13]);
	step256(R, W[ 6], W[15]);
	step256(R, W[ 8], W[ 1]);
	step256(R, W[10], W[ 3]);

	// 4 Round
	step256(R, W[28], W[29]);
	step256(R, W[ 7], W[ 2]);
	step256(R, W[13], W[ 8]);
	step256(R, W[ 3], W[14]);
	step256(R, W[ 9], W[ 4]);

	step256(R, W[30], W[31]);
	step256(R, W[15], W[10]);
	step256(R, W[ 5], W[ 0]);
	step256(R, W[11], W[ 6]);
	step256(R, W[ 1], W[12]);

	// Feedforward_2
	for(i=0;i<8;i++)	state->workingvar[i] ^= R[i];

	state->counter[0]++;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : ARIRANG_Compression512
//
// DESCRIPTION    : Counter Addition and compression function of ARIRANG-384 and ARIRANG-512
//
// PARAMETERS     : state - a structure that holds the hashState information
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////

void Arirang_Compression512(hashState *state)
{
	QWORD	R[8], W[32];
	int i;

	// Counter Addition
	state->workingvar[0] ^= state->counter[1];
	state->workingvar[4] ^= state->counter[0];


	// Compression function 
	#if defined(BIG_ENDIAN)
		#define GetData(x) x
	#else
		#define GetData(x) ENDIAN_REVERSE_DWORD(x)
	#endif

	// Message Scheduling
	for (i = 0; i < 16; i++)
		W[i] = (QWORD)(GetData(((DWORD*)state->block)[2*i+1])) | ((QWORD)(GetData(((DWORD*)state->block)[2*i])) << 32); 
											
	W[16] = ROTL_QWORD((W[ 9] ^ W[11] ^ W[13] ^ W[15] ^ K512[ 0]), 11);
	W[17] = ROTL_QWORD((W[ 8] ^ W[10] ^ W[12] ^ W[14] ^ K512[ 1]), 23);
	W[18] = ROTL_QWORD((W[ 1] ^ W[ 3] ^ W[ 5] ^ W[ 7] ^ K512[ 2]), 37);
	W[19] = ROTL_QWORD((W[ 0] ^ W[ 2] ^ W[ 4] ^ W[ 6] ^ K512[ 3]), 59);

	W[20] = ROTL_QWORD((W[14] ^ W[ 4] ^ W[10] ^ W[ 0] ^ K512[ 4]), 11);
	W[21] = ROTL_QWORD((W[11] ^ W[ 1] ^ W[ 7] ^ W[13] ^ K512[ 5]), 23);
	W[22] = ROTL_QWORD((W[ 6] ^ W[12] ^ W[ 2] ^ W[ 8] ^ K512[ 6]), 37);
	W[23] = ROTL_QWORD((W[ 3] ^ W[ 9] ^ W[15] ^ W[ 5] ^ K512[ 7]), 59);

	W[24] = ROTL_QWORD((W[13] ^ W[15] ^ W[ 1] ^ W[ 3] ^ K512[ 8]), 11);
	W[25] = ROTL_QWORD((W[ 4] ^ W[ 6] ^ W[ 8] ^ W[10] ^ K512[ 9]), 23);
	W[26] = ROTL_QWORD((W[ 5] ^ W[ 7] ^ W[ 9] ^ W[11] ^ K512[10]), 37);
	W[27] = ROTL_QWORD((W[12] ^ W[14] ^ W[ 0] ^ W[ 2] ^ K512[11]), 59);

	W[28] = ROTL_QWORD((W[10] ^ W[ 0] ^ W[ 6] ^ W[12] ^ K512[12]), 11);
	W[29] = ROTL_QWORD((W[15] ^ W[ 5] ^ W[11] ^ W[ 1] ^ K512[13]), 23);
	W[30] = ROTL_QWORD((W[ 2] ^ W[ 8] ^ W[14] ^ W[ 4] ^ K512[14]), 37);
	W[31] = ROTL_QWORD((W[ 7] ^ W[13] ^ W[ 3] ^ W[ 9] ^ K512[15]), 59);
																		
	

	// Register Initialize 
	for(i=0;i<8;i++)	R[i] = state->workingvar[i];
	
	// 1 Round
	step512(R, W[16], W[17]);
	step512(R, W[ 0], W[ 1]);
	step512(R, W[ 2], W[ 3]);
	step512(R, W[ 4], W[ 5]);
	step512(R, W[ 6], W[ 7]);

	step512(R, W[18], W[19]);
	step512(R, W[ 8], W[ 9]);
	step512(R, W[10], W[11]);
	step512(R, W[12], W[13]);
	step512(R, W[14], W[15]);

	// 2 Round
	step512(R, W[20], W[21]);
	step512(R, W[ 3], W[ 6]);
	step512(R, W[ 9], W[12]);
	step512(R, W[15], W[ 2]);
	step512(R, W[ 5], W[ 8]);

	step512(R, W[22], W[23]);
	step512(R, W[11], W[14]);
	step512(R, W[ 1], W[ 4]);
	step512(R, W[ 7], W[10]);
	step512(R, W[13], W[ 0]);

	// Feedforward_1
	for(i=0;i<8;i++)	R[i] ^= state->workingvar[i];

	// 3 Round
	step512(R, W[24], W[25]);
	step512(R, W[12], W[ 5]);
	step512(R, W[14], W[ 7]);
	step512(R, W[ 0], W[ 9]);
	step512(R, W[ 2], W[11]);

	step512(R, W[26], W[27]);
	step512(R, W[ 4], W[13]);
	step512(R, W[ 6], W[15]);
	step512(R, W[ 8], W[ 1]);
	step512(R, W[10], W[ 3]);

	// 4 Round
	step512(R, W[28], W[29]);
	step512(R, W[ 7], W[ 2]);
	step512(R, W[13], W[ 8]);
	step512(R, W[ 3], W[14]);
	step512(R, W[ 9], W[ 4]);

	step512(R, W[30], W[31]);
	step512(R, W[15], W[10]);
	step512(R, W[ 5], W[ 0]);
	step512(R, W[11], W[ 6]);
	step512(R, W[ 1], W[12]);

	// Feedforward_2
	for(i=0;i<8;i++)	state->workingvar[i] ^= R[i];

	// Increment Counter
	state->counter[0]++; if(state->counter[0] == 0) state->counter[1]++;
}

