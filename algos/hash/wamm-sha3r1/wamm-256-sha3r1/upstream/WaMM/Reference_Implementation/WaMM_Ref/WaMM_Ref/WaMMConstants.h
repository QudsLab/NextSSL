/*
 * WaMMConstants.h ($RCSfile: WaMMConstants.h,v $)
 *
 * Defines WaMM Specific constants used in the algoritm.
 *
 * Copyright 2008 John Washburn.  All rights reserved until I win the SHA3 contest.
 
$Header: D:\\RCSArchive\\D\\Programming\\WaMM\\ReferenceImplementation\\WaMM\\WaMM\\WaMMConstants.h,v 1.7 2008-10-19 08:25:48-05 johnwashburn Exp johnwashburn $
$Revision: 1.7 $

$Log: WaMMConstants.h,v $
Revision 1.7  2008-10-19 08:25:48-05  johnwashburn
Daily Checkpointing

Revision 1.6  2008-10-13 18:13:55-05  johnwashburn
Daily Check Point

Revision 1.2  2008-10-08 02:27:14-05  johnwashburn
Improved comment header block to better use RCS keywords

Revision 1.1  2008-10-08 02:08:03-05  johnwashburn
Added RCS Header Comment block using RCS Keywords.


*/
#ifndef WaMMConstants_h_8232BE83_F6AE_4cf3_9FE5_9DC60B5DACCC
#define WaMMConstants_h_8232BE83_F6AE_4cf3_9FE5_9DC60B5DACCC 1

#include <limits.h>

#pragma warning(disable : 4996)

#ifndef BOOL
	typedef int BOOL;
#endif
#ifndef TRUE
	#define FALSE ((BOOL) 0)
	#define TRUE (!FALSE)
#endif
/* 
 * Gurantee there is at type that is EXACT 8bits in size.  
 * char is only curanteed to be the smallest integer type
 * sizeof(char) <= sizeof(short) <= sizeof(int) <= sizeof(long) <= sizeof(long)
 */
#ifndef BYTE
	#if 8 == CHAR_BIT
		typedef unsigned char BYTE;
	#endif
#endif
/*
 * define the sizes of various WaMM data structures.
 * Dimension of the state matrix in number of bytes
 * Length of the data vector in bits and bytes
 * dimension of the operator in bytes
 */
#define WaMM_BitsPerBitSequence CHAR_BIT	/* it is possible a char is more than 8 bits/char */

#define WaMM_BitsPerByte 8			/* Do what is necessary to make this so */
#define WaMM_NumStatesPerByte (256)	/* 256 = 2^WaMM_BitsPerByte */

/*
 * Define constants Related to the structure of the hash state and the internal construction of the 
 * WaMM hash machine
 */
#define WaMM_MatrixDimension (32)
#define WaMM_VectorLength_Bytes (WaMM_MatrixDimension)
#define WaMM_VectorLength_Bits (WaMM_VectorLength_Bytes * WaMM_BitsPerByte)
#define WaMM_VectorLength_BitSequences (WaMM_VectorLength_Bits / WaMM_BitsPerBitSequence)
#define WaMM_NumBytesStateMatrix (WaMM_MatrixDimension * WaMM_MatrixDimension)
#define WaMM_BitSequencePerDataLength (sizeof(DataLength) * WaMM_BitsPerByte)
#define WaMM_NumberOfRounds (2)
#define WaMM_LITTLE_ENDIAN (1)	/* if BigEndian then set to WaMM_LITTLE_ENDIAN (0)*/

/*
 * Define constants limiting possible hash lengths produced by the WaMM algorithm
 */
#define WaMM_HashLen_MinBytes (24)
#define WaMM_HashLen_MaxBytes (256)
#define WaMM_HashLen_BytesModulus (4)

#define WaMM_HashLen_MinBitLength (WaMM_HashLen_MinBytes * WaMM_BitsPerByte)
#define WaMM_HashLen_MaxBitLength (WaMM_HashLen_MaxBytes * WaMM_BitsPerByte)
#define WaMM_HashLen_BitLengthModulus (WaMM_HashLen_BytesModulus*WaMM_BitsPerByte)

/*
 * Define the size of the prime number array used to create the tapping sequence.
 * Since the array is zero indexed the list must have WaMM_HashLen_MaxBytes + 1 array elements.
 * This way:
 *     TappingPrime[0] = P_0 = 1
 *     TappingPrime[1] = P_1 = 2
 *     TappingPrime[2] = P_2 = 3
 *     TappingPrime[3] = P_3 = 5
 *     TappingPrime[4] = P_4 = 7
 *             *
 *             *
 *             *
 *     TappingPrime[N-1] = P_n-1
 *     TappingPrime[N] = P_n
 */
#define WaMM_NumTappingPrimes (WaMM_HashLen_MaxBytes+1)	

/*
 * Define constants related to global variable storing error messages and error states
 */
#define WaMM_MaxCharsInErrorMessage (4096)
#define WaMM_ErrorMessageLength (WaMM_MaxCharsInErrorMessage * sizeof(char))
#define WaMM_ErrorMessageBufferSize ((WaMM_ErrorMessageLength + 1) * sizeof(char))  /* 1 character is needed for NULL terminations */

#endif /* #ifndef WaMMConstants_h_8232BE83_F6AE_4cf3_9FE5_9DC60B5DACCC */