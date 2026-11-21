/*
	Seed Expander using SHAKE256

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> // for memcpy
#include "sha3.h"

typedef struct {
	uint8_t *pool;
	int p;
	int maxlen;
} SEEDEXPANDER_CONTEXT;

static SEEDEXPANDER_CONTEXT ctx = {NULL, 0, 0};


/**
	seedexpand: initialize

	@param[in] seed
	@param[in] seedlen seed byte size
	@param[in] maxlen
*/
void se_init(uint8_t *seed, int seedlen, int maxlen)
{
	ctx.p = 0;
	ctx.maxlen = maxlen;

	if(ctx.pool != NULL) free(ctx.pool);
	ctx.pool = (uint8_t *)malloc(maxlen);
	if(ctx.pool == NULL){
		fprintf(stderr, "se_init: can't allocate memory (%d bytes)\n", maxlen);
		exit(EXIT_FAILURE);
	}

	SHAKE256(ctx.pool, maxlen, seed, seedlen);
}


/**
	seedexpand: generate random bytes

	@param[out] x
	@param[in] size
*/
void se_randombytes(uint8_t *x, int size)
{
	if(size == 0) return;
	if(ctx.p + size > ctx.maxlen){
		fprintf(stderr, "se_randombytes: maxlen is too small\n");
		exit(EXIT_FAILURE);
	}
	memcpy(x, &ctx.pool[ctx.p], size);
	ctx.p += size;
}


/**
	seedexpand: cleanup
*/
void se_finish(void)
{
	if(ctx.pool != NULL){
		free(ctx.pool);
		ctx.pool = NULL;
	}
}
