/*
	Seed Expander using SHAKE256

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#ifndef __SEEDEXPANDER_H__
#define __SEEDEXPANDER_H__

#include <stdint.h>

void se_init(uint8_t *seed, int seedlen, int maxlen);
void se_randombytes(uint8_t *x, int size);
void se_finish(void);

#endif
