///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PROJECT : Arirang family
//
// DATE    : 2008.10.23
//
///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FILE  : Arirang_Ref64.h
//
// NOTES : Reference code of Arirang family
// 
//         Based on 64-bit platform
//
///////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef _ARIRANG_OP64_H__
#define _ARIRANG_OP64_H__ 100
#include <stdlib.h>
#include "SHA3api_ref.h"


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Macro

// Define the Endianness
#undef BIG_ENDIAN
#undef LITTLE_ENDIAN

#if defined(USER_BIG_ENDIAN)
	#define BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
	#define LITTLE_ENDIAN
#else
	#if 0
		#define BIG_ENDIAN
	#elif defined(_MSC_VER)
		#define LITTLE_ENDIAN
	#else
		#error
	#endif
#endif

// Left and rigth rotation
#define ROTL_DWORD(x, n) ( (DWORD)((x) << (n)) | (DWORD)((x) >> (32-(n))) )	
#define ROTL_QWORD(x, n) ( (QWORD)((x) << (n)) | (QWORD)((x) >> (64-(n))) )

// Reverse the byte order of DWORD and WORD.
#define ENDIAN_REVERSE_DWORD(dwS)	( (ROTL_DWORD((dwS),  8) & 0x00ff00ff) | (ROTL_DWORD((dwS), 24) & 0xff00ff00) )
#define ENDIAN_REVERSE_QWORD(w, x)  {														\
     QWORD tmp = (w);																		\
     tmp = (tmp >> 32) | (tmp << 32);														\
     tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) | ((tmp & 0x00ff00ff00ff00ffULL) << 8);		\
     (x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | ((tmp & 0x0000ffff0000ffffULL) << 16);	\
 }

// Move DWORD type to BYTE type and BYTE type to DWORD type
#if defined(BIG_ENDIAN)
	#define BIG_B2D(B, D)		D = *(DWORD *)(B)
	#define BIG_D2B(D, B)		*(DWORD *)(B) = (DWORD)(D)
	#define LITTLE_B2D(B, D)	D = ENDIAN_REVERSE_DWORD(*(DWORD *)(B))
	#define LITTLE_D2B(D, B)	*(DWORD *)(B) = ENDIAN_REVERSE_DWORD(D)
#elif defined(LITTLE_ENDIAN)
	#define BIG_B2D(B, D)		D = ENDIAN_REVERSE_DWORD(*(DWORD *)(B))
	#define BIG_Q2B(D, B)		ENDIAN_REVERSE_QWORD(D, *(QWORD *)(B))
	#define BIG_D2B(D, B)		*(DWORD *)(B) = ENDIAN_REVERSE_DWORD(D)
	#define LITTLE_B2D(B, D)	D = *(DWORD *)(B)
	#define LITTLE_D2B(D, B)	*(DWORD *)(B) = (DWORD)(D)
#endif

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Function

void gen_tabs(void);
void Arirang_Compression256(hashState *state);
void Arirang_Compression512(hashState *state);

#endif