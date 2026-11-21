/*
	Giophantus public key cryptosystem

	random number generator stub

	Copyright(C) by Toshiba Corporation. All rights reserved.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "genrand.h"

static int randmode = 0;

/**
	genrand: set randmode

	@param[in] mode 0:randbytes, 1:seedexpand
*/
void set_randmode(int mode)
{
	randmode = mode;
}


/**
	genrand: generate random bytes

	@param[out] x
	@param[in] size
*/
void genrand(uint8_t *x, int size)
{
	switch(randmode){
	case RNG: // randbytes
		randombytes(x, size);
		break;
	case SE:  // seedexpand
		se_randombytes(x, size);
		break;
	default:
		fprintf(stderr, "genrand: unknown randmode %d\n", randmode);
		exit(EXIT_FAILURE);
	}
}
