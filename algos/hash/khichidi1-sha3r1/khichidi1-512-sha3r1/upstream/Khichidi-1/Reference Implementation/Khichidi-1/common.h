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

#ifndef _COMMON_H_
#define _COMMON_H_

#ifndef EIGHT_BIT
#define THIRTYTWO_BIT // default 32 bit
#endif

#ifdef THIRTYTWO_BIT
#define WORD unsigned long
#define WORDLENGTH 4

#if defined(WIN32) && !defined(__GNUC__)
#define WORD64	unsigned __int64
#else
#define WORD64	unsigned long long
#endif

// THIRTYTWO_BIT
#endif


#ifdef EIGHT_BIT

#define WORD unsigned short
#define WORDLENGTH 4

// EIGHT_BIT
#endif

#ifdef  __cplusplus
extern "C" {
#endif

	typedef unsigned char BitSequence;

	typedef WORD DataLength; 

	typedef enum {SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2} HashReturn;


#ifdef  __cplusplus
}
#endif

#define KHICHIDI_224 224
#define KHICHIDI_256 256
#define KHICHIDI_384 384
#define KHICHIDI_512 512


#endif
