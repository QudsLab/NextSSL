/*
 * SHA3API.h ($RCSfile: SHA3API.h,v $)
 *
 * Defines the required API elements dictated by the rules of the SHA3 contest.
 *
 * Copyright 2008 John Washburn.  All rights reserved until I win the SHA3 contest.

$Header: D:\\RCSArchive\\D\\Programming\\WaMM\\ReferenceImplementation\\WaMM\\WaMM\\SHA3API.h,v 1.7 2008-10-19 08:25:49-05 johnwashburn Exp johnwashburn $
$Revision: 1.7 $

$Log: SHA3API.h,v $
Revision 1.7  2008-10-19 08:25:49-05  johnwashburn
Daily Checkpointing

Revision 1.6  2008-10-13 18:13:55-05  johnwashburn
Daily Check Point

Revision 1.2  2008-10-08 02:26:03-05  johnwashburn
proved comment header block to better use RCS keywords

Revision 1.1  2008-10-08 02:08:03-05  johnwashburn
Added RCS Header Comment block using RCS Keywords.


 */
#ifndef SHA3API_h_4414D8B2_CCCD_421f_BC68_C15396A4D1E9
#define SHA3API_h_4414D8B2_CCCD_421f_BC68_C15396A4D1E9 1

/*
 * Mandated type definitions
 */
typedef unsigned char BitSequence;
typedef unsigned long long DataLength;

/*
 * Mandated Enumerations
 */
typedef enum {
	SUCCESS = 0
,	FAIL = 1
,	BAD_HASHLENGTH = 2
,	ERORR_NULL_STATE_POINTER		= 101
,	ERORR_NULL_INPUT_POINTER		= ERORR_NULL_STATE_POINTER + 1
,	ERORR_NULL_OUTPUT_POINTER		= ERORR_NULL_INPUT_POINTER + 1
,	ERORR_OPERATOR_OUT_OF_RANGE		= ERORR_NULL_OUTPUT_POINTER + 1
,	ERORR_NULL_PRODUCT_POINTER		= ERORR_OPERATOR_OUT_OF_RANGE + 1
,	ERORR_NULL_HASHDATA_POINTER		= ERORR_NULL_PRODUCT_POINTER + 1
,	ERORR_NULL_HASHVALUE_POINTER	= ERORR_NULL_HASHDATA_POINTER + 1
,	ERORR_INITALIZE_NULL_VECTOR		= ERORR_NULL_HASHVALUE_POINTER + 1
,	ERORR_COPY_NULL_VECTOR			= ERORR_INITALIZE_NULL_VECTOR + 1
,	ERORR_NULL_REMAINDER_BUFFER		= ERORR_COPY_NULL_VECTOR + 1
,	ERORR_FAILED_RBUFFER_ALLOC		= ERORR_NULL_REMAINDER_BUFFER + 1
,	ERORR_NULL_BITARRAY				= ERORR_FAILED_RBUFFER_ALLOC + 1
,	ERORR_ZEROLEN_BITARRAY			= ERORR_NULL_BITARRAY + 1
,	ERORR_NEGATVELEN_BITARRAY		= ERORR_ZEROLEN_BITARRAY + 1
,	ERORR_MALLOC_BITARRAY			= ERORR_NEGATVELEN_BITARRAY + 1
,	ERORR_REALLOC_BITARRAY			= ERORR_MALLOC_BITARRAY + 1
,	ERORR_MALLOC_ERROR_MSG_BUFFER	= ERORR_REALLOC_BITARRAY + 1
,	ERORR_NULL_BITSEQUENCE			= ERORR_MALLOC_ERROR_MSG_BUFFER + 1
,	ERORR_NULL_ALIAS_ERROR			= ERORR_NULL_BITSEQUENCE + 1
,	ERORR_NULL_FILE_POINTER			= ERORR_NULL_ALIAS_ERROR + 1

,	WARNING_BITSEQUENCE_TOO_SMALL	= 1000
,	WARNING_BITSEQUENCE_TOO_LARGE	= WARNING_BITSEQUENCE_TOO_SMALL + 1

,	NOT_IMPLEMENTED = 5000
,	IMPLEMENTATION_CHAR_SEQUENCE_ERROR	= NOT_IMPLEMENTED + 1
,	IMPLEMENTATION_INTEGER_DIV_IS_FLOOR	= IMPLEMENTATION_CHAR_SEQUENCE_ERROR + 1
} HashReturn;

/* 
 * Mandated API funtion prototypes
 * Note: The forward reference to struct hashState is resolved in in WaMM.H
 */
struct hashState;
HashReturn Init(struct hashState *state, int hashbitlen);
HashReturn Update(struct hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Final(struct hashState *state, BitSequence *hashval);
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);
HashReturn EnableBitArrays(void);

#endif /* SHA3API_h_4414D8B2_CCCD_421f_BC68_C15396A4D1E9 */
