#include <stdio.h>
#include <stdlib.h>

#include "crunch_type.h"

// Constantes liées à l'algorithme

#define K 128 // number of subdivisions of input
// Constantes pour l'entrée et la sortie
#define BLOCKSIZE 1024 //in bits
#define HASHLEN 224

#define NBROUND HASHLEN  //nombre de tours pour chacune des schemas de Feistel non symetriques

#ifdef M64
#define LONGSIZE 64
#else
#define LONGSIZE 32
#endif

#define NE (BLOCKSIZE/LONGSIZE)	// Number of long in input
#define NS (HASHLEN/LONGSIZE)	// Number of long in outpout
#define NPM ((LONGSIZE*K)/BLOCKSIZE)	//Longs (32 or 64 bits) are divided in NPM parts

#define NA 256			// = 2^NBE number of elements in start ensemble of random function
#define NBE (BLOCKSIZE/K)		//  number of bits in elements in start ensemble of random function

//macro used to send final results in same order in 32 and 64  bits version (due to integers representation on X86)
#define idx(a)  ( (LONGSIZE/8) * ((a)/(LONGSIZE/8)) + ((LONGSIZE/8)-1) - (a)%(LONGSIZE/8))

#define SHIFT	((NBROUND%128)*8)/LONGSIZE

#define MAXDATAPERUPDATE 1024ULL*1024ULL*1024ULL

extern BlockType nbalea[];

//Left data after a call of Update function
BlockType LeftData[(BLOCKSIZE-HASHLEN)/LONGSIZE];
unsigned int SizeLeft; //size of left data in bytes
unsigned int BitInLastByte;
BlockType PrevHash[HASHLEN/LONGSIZE];
DataLength TotalInputSizeInBit; //Total size of message in bits


BlockType *padding_224(int *nb_final_block)
{
	int new_nb_bit,i,no_block;
	BlockType *mes;
	char *mes_char,*DL_char;
	int add_one_byte_for_last_ONE;
	int temp;
	new_nb_bit=SizeLeft*8+1+64;
	i=new_nb_bit % (BLOCKSIZE-HASHLEN);
	new_nb_bit+=(BLOCKSIZE-HASHLEN)-i;
	*nb_final_block=new_nb_bit/LONGSIZE;

	mes=(BlockType *)calloc((*nb_final_block),sizeof(BlockType));
	mes_char=(char*)mes;
	DL_char=(char*)LeftData;
	/*copy left data in beginning of the block*/
	for(i=0;i<(int)SizeLeft;i++)
	{
 		temp =idx(i);
		mes_char[temp]=DL_char[temp];
	}
	if(BitInLastByte != 0)
	{
		temp =idx(i);
		mes_char[temp]=DL_char[temp];
		unsigned char mask=0x80;
		for(i=1;i<BitInLastByte;i++)
		{
			mask|=0x80>>i;
		}
		
		mes_char[temp]&=mask;
		add_one_byte_for_last_ONE = 0;
	}
	else
	{
		add_one_byte_for_last_ONE=1;
	}
	no_block=((SizeLeft)*8+BitInLastByte+add_one_byte_for_last_ONE)/LONGSIZE;
	mes[no_block]|=((BlockType)1)<<( (LONGSIZE-1)-( ((SizeLeft)*8 + BitInLastByte )%LONGSIZE));
	/*complete block with 0 and stock message size in the last 64bits*/
	#if LONGSIZE==32
	for(i=no_block+1;i<*nb_final_block-2;i++)
	{
		mes[i]=0;
	}
	mes[*nb_final_block-2]=(BlockType)(TotalInputSizeInBit>>32);
	mes[*nb_final_block-1]=(BlockType)(TotalInputSizeInBit);
	#endif
	#if LONGSIZE==64
	for(i=no_block+1;i<*nb_final_block-1;i++)
	{
		mes[i]=0;
	}
	mes[*nb_final_block-1]=TotalInputSizeInBit; 
	#endif
	return(mes);
}

void Merkle_224(BlockType H[],BlockType mes[],int nb_merkle) {
	int n,k;
	int j_round,j,a,aa,aa2,p,block;
    	int alpha;
	BlockType message[NE],res[NE];
	BlockType i,i2;
	for(k=0;k<(NS);k++)
	{
		message[k]=H[k];
	}

	for(n=0;n<nb_merkle;n++)
	{
		for(k=0;k<NS;k++)
		{
			res[k]=message[k];
		}
		for(k=(NS) ;k<NE;k++)
		{
			message[k]=mes[k-(NS)];
			res[k]=message[k];
		}
		mes=mes+(NE-NS);
		/*for(k=0;k<NE;k++) printf("%08x",message[k]);
		printf("\n"); */

		a=NE-(128/LONGSIZE);
 	   	p=0;block=0;
	   	alpha=1;
 	   	for(j_round=0;j_round<NBROUND;j_round++)
 	   	{
			i2=(res[block]>>((NPM-1-p)*NBE))&(NA-1);
			i2=(i2*alpha)&0xff;
			i=(message[block]>>((NPM-1-p)*NBE))&(NA-1);
			i=(i*alpha)&0xff;
			aa2=(int)(a+NE*NA*16+i2*NE);
			aa=(int)(a+i*NE);
        		for(j=0;j<NE;j++)
			{
	   			message[j]^=nbalea[aa];
				aa++;
            			res[j]^=nbalea[aa2];
	    			aa2++;
        		}
        		if ((j_round & 15) == 15)
			{
				alpha=alpha+2;
				if ( (j_round&127) == 127)
				{
					a=NE-(128/LONGSIZE);
				}
				else
				{
					a-=15*NA*NE+128/LONGSIZE;
				}
			}
			else
			{
				a+=NA*NE;
			}
        		p++;
        		if (p==NPM)
			{
        	    		block++;
		    		if (block==NE) block=0;
        	    		p=0;
        		}
		}
		#if SHIFT==0
		for(j=0;j<NS;j++) message[j]^=res[j];
		#else
		for(j=SHIFT;j<SHIFT+NS;j++) res[j%NE]^=message[j%NE];
		for(j=0;j<NS;j++) message[j]=res[(j+SHIFT)%NE];
		#endif
	}
	for(i=0;i<NS;i++) H[i]=message[i];
}

//concatenate the left data of the previous call of update with the new data 
BlockType *concatenation_update_224(const BitSequence *data,int databitlen,int *nb_block)
{
	BlockType *mes=NULL;
	int nb_bits_restants;
	int nb_block_in_new_mes;
	int nb_bits_in_new_mes;
	int i;
	int bits_traite_dans_data;
	int no_block,pos_block;
	int temp;
	char *mes_char,*DL_char;
	nb_bits_in_new_mes=( (databitlen+8*SizeLeft)/(BLOCKSIZE-HASHLEN) )*(BLOCKSIZE-HASHLEN);
	//printf("%d bit en plus\n",nb_bits_in_new_mes);
	nb_bits_restants=(databitlen+8*SizeLeft)%(BLOCKSIZE-HASHLEN);
	nb_block_in_new_mes=nb_bits_in_new_mes/(LONGSIZE);
	if(nb_block_in_new_mes>0) 
	{
		/*there is enough of new data to complete a block*/
		mes = (BlockType *)calloc( nb_block_in_new_mes,(LONGSIZE/8) );
		if(mes==NULL) return NULL;
		//copy left data to the beginning of the new "message"
		mes_char=(char*)mes;
		DL_char=(char*)LeftData;
		for(i=0;i<(int)SizeLeft;i++)
		{
			temp =(i/(LONGSIZE/8))*(LONGSIZE/8) + ( (LONGSIZE/8-1)-(i%(LONGSIZE/8))) ;
			mes_char[temp]=DL_char[temp];
		}
		/*complete message with new datas*/
		no_block=(i*8)/(LONGSIZE);
		pos_block=(LONGSIZE-8)-( ((i)*8 )%LONGSIZE);
		for(i=0;8*i<nb_bits_in_new_mes-8*(int)SizeLeft;i++) 
		{
			mes[no_block]|=(BlockType)data[i] << pos_block;
			pos_block-=8;
			if (pos_block<0) 
			{
				pos_block=LONGSIZE-8;
				no_block++;
			}
		}
		bits_traite_dans_data=i;
		no_block=0;pos_block=LONGSIZE-8;
		SizeLeft=(nb_bits_restants)/8;
		LeftData[0]=0;
	}
	else
	{
		//no new block with new data
		i=0;
		no_block=((SizeLeft)*8+1)/LONGSIZE;
		pos_block= (LONGSIZE-8)-( ((SizeLeft)*8 )%LONGSIZE);
		SizeLeft=SizeLeft+databitlen/8;
	}
	/*save left data of new data for the next call of update/final*/
	for( ;8*i<databitlen;i++) 
	{
		LeftData[no_block]|=(BlockType)data[i] << pos_block;
		pos_block-=8;
		if (pos_block<0) 
		{
			pos_block=LONGSIZE-8;
			no_block++;
			LeftData[no_block]=0UL;
		}
	}
	if(databitlen%8 != 0)
	{
		BitInLastByte = databitlen%8;
	}
	else
	{
		BitInLastByte = 0;
	}
	*nb_block=nb_block_in_new_mes;
	return mes;	
}

HashReturn Update_224(const BitSequence * data,DataLength databitlen)
{
	BlockType *mes;int nb_final_block[1];
	if(databitlen>=MAXDATAPERUPDATE)
	{
		printf("too many data for an update\n");
		return FAIL;
	}
	mes= concatenation_update_224(data,(int)databitlen,nb_final_block);
	if(*nb_final_block>0)
	{
		if(mes == NULL)
		{
			printf("fail: can't allocate enough memory\n");
			return FAIL;
		}
	}
	if(*nb_final_block>0)
	{
		Merkle_224(PrevHash,mes,*nb_final_block/(NE-NS));
		free(mes);
	}
	TotalInputSizeInBit+=databitlen;
	return SUCCESS;
}



HashReturn Init_224()
{
	int k;
	for(k=0;k<(HASHLEN/LONGSIZE);k++) 
	{
		PrevHash[k]=nbalea[k];
	}
	for(k=0;k<(BLOCKSIZE-HASHLEN)/LONGSIZE;k++)
	{
		LeftData[k]=0;
	}
	SizeLeft=0;
	TotalInputSizeInBit=0;
	return SUCCESS;
}


HashReturn Final_224(BitSequence *hash)
{
	BlockType *mes;
	int i;
	int nb_final_block[1];
	char *tocopy;
	mes=padding_224(nb_final_block);
	tocopy=(char*)mes;
	Merkle_224(PrevHash,mes,*nb_final_block/(NE-NS));
	
	tocopy=(char*)PrevHash;
	for(i=0;i<HASHLEN/8;i++)
	{
		hash[i]=tocopy[idx(i)];
	}

	free(mes);
	return SUCCESS;
}

HashReturn Hash_224(const BitSequence *data,DataLength databitlen,BitSequence *hashval) 
{
	hashState state;
	HashReturn HR;
	int i;
	state.hashbitlen=224;
	HR=Init_224();
	if(HR!=SUCCESS) return HR;
	i=0;
	while(databitlen>MAXDATAPERUPDATE)
	{
		HR=Update_224(&(data[i*MAXDATAPERUPDATE/8]),MAXDATAPERUPDATE);
		if(HR!=SUCCESS) return HR;
		databitlen-=(MAXDATAPERUPDATE);
		i++;
	}
	HR=Update_224(&(data[i*MAXDATAPERUPDATE/8]),databitlen);
	HR=Final_224(hashval);
	return HR;
}



 
