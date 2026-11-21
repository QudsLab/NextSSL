#include <stdio.h>
#include <stdlib.h>

#include "crunch_type.h"
#include "crunch_224.h"
#include "crunch_256.h"
#include "crunch_384.h"
#include "crunch_512.h"

HashReturn Init(hashState *state, int hashbitlen)
{
	state->hashbitlen=hashbitlen;
	if( sizeof(BlockType) == 8 && hashbitlen == 224)
	{
		printf("This size (224) is not available in 64bits\n");
		return BAD_HASHBITLEN;
	}
	switch(hashbitlen)
	{
		case 224:
			return Init_224();
		case 256:
			return Init_256();
		case 384:
			return Init_384();
		case 512:
			return Init_512();
		default:
			return BAD_HASHBITLEN;
	}
}

HashReturn Final(hashState *state, BitSequence *hash)
{
	if( sizeof(BlockType) == 8 && state->hashbitlen == 224)
	{
		printf("This size (224) is not available in 64bits\n");
		return BAD_HASHBITLEN;
	}
	switch(state->hashbitlen)
	{
		case 224:
			return Final_224(hash);
		case 256:
			return Final_256(hash);
		case 384:
			return Final_384(hash);
		case 512:
			return Final_512(hash);
		default:
			return BAD_HASHBITLEN;
	}
}

HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
	if( sizeof(BlockType) == 8 && state->hashbitlen == 224)
	{
		printf("This size (224) is not available in 64bits\n");
		return BAD_HASHBITLEN;
	}
	switch(state->hashbitlen)
	{
		case 224:
			return Update_224(data,databitlen);
		case 256:
			return Update_256(data,databitlen);
		case 384:
			return Update_384(data,databitlen);
		case 512:
			return Update_512(data,databitlen);
		default:
			return BAD_HASHBITLEN;
	}
}

HashReturn Hash(int hashbitlen,const BitSequence *data,DataLength databitlen,BitSequence *hashval) 
{
	if( sizeof(BlockType) == 8 && hashbitlen == 224)
	{
		printf("This size (224) is not available in 64bits\n");
		return BAD_HASHBITLEN;
	}
	switch(hashbitlen)
	{
		case 224:
			return Hash_224(data,databitlen,hashval);
		case 256:
			return Hash_256(data,databitlen,hashval);
		case 384:
			return Hash_384(data,databitlen,hashval);
		case 512:
			return Hash_512(data,databitlen,hashval);
		default:
			return BAD_HASHBITLEN;
	}
}

