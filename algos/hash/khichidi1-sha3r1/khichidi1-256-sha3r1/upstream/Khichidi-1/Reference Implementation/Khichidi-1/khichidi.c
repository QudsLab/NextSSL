#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "khichidi_core.h"
#include "khichidi.h"


HashReturn Init(hashState *state, int hashbitlen)
{
	HashReturn ret = FAIL;
	int bytelen = hashbitlen/8;
	int i=0;

	if(state != NULL)
	{
		switch (hashbitlen)
		{
			case KHICHIDI_224:
			case KHICHIDI_256:
			case KHICHIDI_384:
			case KHICHIDI_512:
				
				state->bitlength = hashbitlen;
				
				for(i=0;i<bytelen;i++)
				{
					state->M[i]=0;
					state->Mdash[i]=0;
					state->residue[i]=0;
				}
				state->residuelen = 0;
				for(i=0;i<9;i++)
					state->count[i]=0;
#ifdef EIGHT_BIT
				for(i=0;i<bytelen;i++)
#else
				for(i=0;i<bytelen/WORDLENGTH;i++)
#endif
				{
					state->Z[i] = 0;
					state->H[i] = 0;
				}
				state->H[i] = 0;

				ret = SUCCESS;
				break;
			default: ret = BAD_HASHBITLEN;
		}
		
	}
	return ret;

}


#ifdef EIGHT_BIT
void digest(hashState *state)
{
	unsigned short j = 0,k=0,i=0;
	unsigned short numword = (state->bitlength/8)/WORDLENGTH;
	BitSequence param[WORDLENGTH];
	for(j=0,k=0;j<numword;j++,k+=WORDLENGTH)
	{
		param[0] = state->H[k+0] ^ state->M[k];
		param[1] = state->H[k+1] ^ state->M[k+1];
		param[2] = state->H[k+2] ^ state->M[k+2];
		param[3] = state->H[k+3] ^ state->M[k+3];

		message_pre_process(param,state->Z,k);

		for(i=0;i<WORDLENGTH;i++)
			state->H[k+i+WORDLENGTH] = state->Z[k+i];
	}
	for(i=0;i<WORDLENGTH;i++)
		state->H[0+i] = state->H[k+i];
}
#else
void digest(hashState *state)
{
	int j = 0,k=0;
	int numword = (state->bitlength/8)/WORDLENGTH;
	WORD Mj =0;

	for(j=0, k=0; j<numword; j++, k+=WORDLENGTH)
	{
		// Get the bitsequence to message word
		Mj = state->M[k];
		Mj = Mj<<8 | state->M[k+1];
		Mj = Mj<<8 | state->M[k+2];
		Mj = Mj<<8 | state->M[k+3];
		
		// message_pre_process will do shuffling, t-function and lfsr
		state->Z[j] = message_pre_process(Mj ^ state->H[j]);
		state->H[j+1] = state->Z[j];

	}
	state->H[0] = state->H[j];
}
#endif


HashReturn Final(hashState *state, BitSequence *hashval)
{
	HashReturn ret = FAIL;
	int i = 0, k=0,j=0;
	int outlen = 0;
	int algsize = state->bitlength/8;
	BitSequence aa[130]="";
	WORD flag=0;

	if(hashval != 0 && state != 0)
	{
		// Initialize the M and Mdash values
		for(i=0;i<algsize;i++)
		{
			state->M[i]=0;
			state->Mdash[i]=0;
		}

		// If there is anything left in the residue, digest that also
		// Or even if no hash has been computed till now(means we are
		// creating hash for empty) then just do padding and compute hash
#ifdef EIGHT_BIT
		if((state->residuelen > 0) || ((state->Z[0] == 0) && (state->Z[1] == 0) && (state->Z[2] == 0) && (state->Z[3] == 0)) )
#else
		if((state->residuelen > 0) || (state->Z[0] == 0))
#endif
		{
			dopad(state->residue, state->residuelen, state->M, algsize);
			state->residuelen = 0;
			digest(state);
		}
		for(i=0;i<algsize-8;i++)
		{
			state->M[i] = 0;
		}
		for(j=1;j<=8;j++,i++)
			state->M[i] = state->count[j];

		digest(state);
			
#ifdef DEBUG
#ifdef EIGHT_BIT
		printf("Round 1 = ");
		for(i=0;i<algsize;i++)
		{
			printf("%02X",state->Z[i]);
		}
		printf("\n");
#else
		wordstobytes(state->Z,algsize/WORDLENGTH,state->M, &outlen);
		hexify(state->M,algsize, aa);
		hexify(state->M,algsize, state->Round[0]);
		printf("Round 1 = %s \n",aa);
#endif
#endif
		// By this time the first outer round is over once. Now we have to do the same for
		// 5 more times. Now M will be constructed from Z's of prior rounds
	

		for(i=0;i<5;i++)
		{
			
#ifdef EIGHT_BIT
			for(j=0;j<algsize;j++)
			{
				state->M[j]=state->Z[j];
				state->Mdash[j]=state->Z[j];
			}
			digest(state);
			for(j=0;j<algsize;j++)
			{
				state->M[j]=state->Mdash[j];
			}
				//process mdash
			digest(state);
#else
			wordstobytes(state->Z, algsize/WORDLENGTH, state->M, &outlen);
			wordstobytes(state->Z, algsize/WORDLENGTH, state->Mdash, &outlen);

			digest(state);
			for(j=0;j<algsize;j++)
			{
				state->M[j]=state->Mdash[j];
			}
			//process mdash
			digest(state);
#endif
#ifdef DEBUG
#ifdef EIGHT_BIT
		printf("Round %d = ",i+2);
		for(k=0;k<algsize;k++)
		{
			printf("%02X",state->Z[k]);
		}
		printf("\n");
#else
		wordstobytes(state->Z,algsize/WORDLENGTH,state->M, &outlen);
		hexify(state->M,algsize, aa);
		hexify(state->M,algsize, state->Round[i+1]);
		printf("Round %d = %s \n",i+2,aa);
#endif
#endif
		}

#ifdef EIGHT_BIT
		for(k=0;k<algsize;k++)
			hashval[k] = state->Z[k];
#else
		wordstobytes(state->Z, algsize/WORDLENGTH, hashval, &outlen);
#endif
		ret = SUCCESS;
	}

	return ret;
}


HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
	HashReturn ret = FAIL;
	int i = 0;
	int numblocks = 0;
	int remlen = 0;
	int totallen = 0;
	int algsize = state->bitlength/8;
	const BitSequence *buff = data;
	BitSequence temp_length[8],temp_count[8];

	if(state !=0 && databitlen >= 0 && data !=0)
	{
		// copy the count for addition
		for(i=1;i<9;i++)
		{
			temp_count[i-1] = state->count[i];
		}

		for(i=0;i<8;i++)
			temp_length[i]=0;
		// initialize the array and convert WORD to bytes
		convertLength(&databitlen,temp_length);

		// add and store the databit length
		uadd(state->count,temp_count,temp_length,8);

		// take the lenght in bytes
		totallen = (state->residuelen+databitlen)/8;
		
		// If the current available data is not enough to start process,
		// then store it.
		if(totallen < algsize)
		{

			ret = bitcpy(state->residue, state->residuelen, data, databitlen);
			if(ret == SUCCESS)
				state->residuelen = state->residuelen+databitlen;
			 
		}
		else
		{
			// Gent the number of 'bitlength' message blocks
			numblocks = totallen / algsize;
			// Also get what will be the residue size (in bits)
			remlen = (state->residuelen+databitlen) % state->bitlength;
			
			for(i=0; i<numblocks; i++)
			{
				if(state->residuelen > 0)
				{
					bitcpy(state->M, 0, state->residue, state->residuelen);
					bitcpy(state->M, state->residuelen, buff, state->bitlength - state->residuelen);
					buff = buff + ((state->bitlength - state->residuelen)/8);
					state->residuelen = 0;
					
				}
				else
				{
					bitcpy(state->M,0, buff, state->bitlength);
					buff = buff + algsize;
				}

				// process M and get value
				digest(state);
			}


			// Copy the unprocessed data to residue
			if(remlen>0)
			{
				bitcpy(state->residue,0, buff, remlen);
				state->residuelen = remlen;
			}

			ret = SUCCESS;
		}
	}

	return ret;
}


#ifndef EIGHT_BIT
void wordstobytes(WORD *in, int inlen, BitSequence *out, int *outlen)
{
	int i = 0;
	int k = 0;
	for(i=0;i<inlen;i++)
	{
		out[k++] = (BitSequence)((in[i] & 0xFF000000)>>24);
		out[k++] = (BitSequence)((in[i] & 0x00FF0000)>>16);
		out[k++] = (BitSequence)((in[i] & 0x0000FF00)>>8);
		out[k++] = (BitSequence)(in[i] & 0x000000FF);

	}
	*outlen = k;
}
#endif

void convertLength(WORD *in, BitSequence *out)
{
	int i = 0;
	int k = 0;

#ifdef SIXTYFOUR_BIT
	out[k++] = (BitSequence)((in[i] & 0xFF00000000000000)>>56);
	out[k++] = (BitSequence)((in[i] & 0x00FF000000000000)>>48);
	out[k++] = (BitSequence)((in[i] & 0x0000FF0000000000)>>40);
	out[k++] = (BitSequence)((in[i] & 0x000000FF00000000)>>32);
#else
		// fill with zeros
	out[k++] = 0;
	out[k++] = 0;
	out[k++] = 0;
	out[k++] = 0;
#endif
	out[k++] = (BitSequence)((in[i] & 0xFF000000)>>24);
	out[k++] = (BitSequence)((in[i] & 0x00FF0000)>>16);
	out[k++] = (BitSequence)((in[i] & 0x0000FF00)>>8);
	out[k++] = (BitSequence)(in[i] & 0x000000FF);
}

void hexify(BitSequence *in, int inlen, BitSequence *out)
{
	int i=0;
	BitSequence *buff = out;
	for(i=0;i<inlen;i++)
	{
		sprintf(buff, "%02X",in[i]);
		buff = buff+2;
	}
	*buff = '\0';
}

HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	hashState state;
	HashReturn ret = FAIL;

	if((data != 0) && (hashval !=0))
	{
		ret = Init(&state, hashbitlen);
		if(ret == SUCCESS)
		{
			ret = Update(&state, data, databitlen);
		}
		if(ret == SUCCESS)
		{
			ret = Final(&state, hashval);
		}
		
	}
	return ret;

}


int bitcpy(BitSequence *dest, int destoffset, const BitSequence *source, int numbits)
{
	BitSequence MASK[8] = {0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF};
	int kdest = destoffset/8;
	int ldest = destoffset%8;
	int retval = FAIL;
	int balbits = numbits%8;

	if((ldest == 0))
	{
		memcpy(dest+kdest,source, numbits/8);
		if(balbits != 0)
		{
			dest[kdest+numbits/8] = source[numbits/8] & MASK[balbits-1];
		}
		retval = SUCCESS;

	}
	
	return retval;
}

