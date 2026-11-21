/*
	Giophantus public key cryptosystem

	stub for radombytes and seedexpand

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#ifndef __GENRAND_H__
#define __GENRAND_H__

#include <stdint.h>
#include "rng.h"
#include "seedexpand.h"

#define RNG 0
#define SE  1

void set_randmode(int mode);
void genrand(uint8_t *x, int size);

#endif
