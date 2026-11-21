/*
 * Copyright (c) Innovation Labs, Tata Consultancy Services (TCS), Hyderabad. All Rights
 * reserved.
 *
 * This software is the confidential and proprietary information of TCS.
 * ("Confidential Information").  You shall not disclose such
 * Confidential Information and shall use it only in accordance with
 * the terms of the license agreement you entered into with TCS.
 *
 * TCS MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  TCS SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 */


#include "common.h"

#ifndef _KHICHIDI_H_
#define _KHICHIDI_H_


//
// The C++ part
//
#ifdef  __cplusplus
extern "C" {
#endif

	typedef struct
	{
		
		WORD bitlength; // The algorithm bit length. Must be 224, 256, 384 OR 512
		BitSequence residue[64]; // Contains the data to be processed.
		WORD residuelen; // Length of residue
		BitSequence M[64]; // Message being processed
		BitSequence Mdash[64]; //Message being processed - used in last 5 rounds
		BitSequence count[9]; // total date length in bits max 2^64-1
#ifdef EIGHT_BIT
		BitSequence Z[64]; // Hash value
		BitSequence H[64]; // Initial Hash value
#else
		WORD Z[16]; // Hash value
		WORD H[17]; // Initial hash value
#endif
#ifdef DEBUG
		BitSequence Round[6][130];
#endif
		
	}hashState;

	/* Initialize  hashState with the intended hash length of this particular instantiation */
	HashReturn Init(hashState *state, int hashbitlen);

	/* Hash the supplied data and provide the resulting hash value*/
	HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

#ifndef EIGHT_BIT
	/* convert WORD to bytes - 4 bytes */
	void wordstobytes(WORD *in, int inlen, BitSequence *out, int *outlen);
#endif

	/* Process the supplied Data */
	HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen);

	/* Perform any post processing and output filtering required and return the final hash value */
	HashReturn Final(hashState *state, BitSequence *hashval);

	/* perform the digest - Message preprocessing operations */
	void digest(hashState *state);

	/* Convert to hex form */
	void hexify(BitSequence *in, int inlen, BitSequence *out);

	/* Copy given number of bits */
	int bitcpy(BitSequence *dest, int destoffset, const BitSequence *source, int numbits);

	/* Convert the length in WORD to BitSequence */
	void convertLength(WORD *in, BitSequence *out);

//
// The C++ part
//
#ifdef  __cplusplus
}
#endif

// _KHICHIDI_H_
#endif
