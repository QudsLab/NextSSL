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

#ifndef _KHICHIDI_CORE_H_
#define _KHICHIDI_CORE_H_

//
// The C++ part
//
#ifdef  __cplusplus
extern "C" {
#endif

#ifdef EIGHT_BIT

	/* Shuffling operation */
	void shuffling(const BitSequence *in,BitSequence *out);

	/* T- function */
	void t_function(const BitSequence *in,BitSequence *out);

	/*LFSR*/
	void lfsr(const BitSequence *in,BitSequence *out);

	/* message Pre-processing */
	void message_pre_process(const BitSequence* in,BitSequence* out, short from);

	/* square of unsigned integer - 4 bytes*/
	void square(unsigned char *Cval,const unsigned char *Aval);


#else

	/* Shuffling operation */
	WORD shuffling(WORD x);

	/* T- function */
	WORD t_function(WORD n);

	/*LFSR*/
	WORD lfsr(WORD t_result);

	/* message Pre-processing */
	WORD message_pre_process(WORD z);

#endif
	/* Pad the data if it is less than the required length */
	void dopad(const BitSequence *data, int datalen, BitSequence *paddeddata, int paddeddatalen);

	/* addition of unsigned integer */
	void uadd(unsigned char *Cval,const unsigned char *Aval, const unsigned char *Bval,unsigned char limit);

//
// The C++ part
//
#ifdef  __cplusplus
}
#endif

#endif
