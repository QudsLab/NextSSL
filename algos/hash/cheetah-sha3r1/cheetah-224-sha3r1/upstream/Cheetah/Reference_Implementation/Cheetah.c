#include "Cheetah.h"

/* Multiplication 2*a in the field specified in Cheetah */
u8 xtime(u8  a){	
	u8 b;

	if (a&0x80) b=0x1b;
	else	b=0;
	a<<=1;
	a^=b;
	return a;
}

/* Exponentiation x^power */
u8 xtimeN(u8 x, u8 power){
	int i;	

	for(i=1;i<power;i++)
		x=xtime(x);

	return x;
}

/* SubBytes for the InternalRound transformation */
void SubBytes(hashState *state){
	int i,j;

	for(i=0;i<state->nRows;i++)
		for(j=0;j<8;j++)
			state->a[i][j]=SBox[state->a[i][j]];    			
}

/* SubBytes for the Message Expansion transformation */
void SubBytesM(hashState *state){
	int i,j;
	
	for(i=0;i<8;i++)
		for(j=0;j<16;j++)
			state->MessageBlock[i][j]=SBox[state->MessageBlock[i][j]];    			
}

/* ShiftRows for the InternalRound for Cheetah-224 and Cheetah-256 */
void ShiftRows4(hashState *state){
	int i,j;
	u8 temp[8];
	
	for(i=0;i<state->nRows;i++)
	{			
		for(j=0;j<8;j++)
			temp[j]=state->a[i][(j+ShiftRows4c[i])%8];
		for(j=0;j<8;j++)
			state->a[i][j]=temp[j];
	}
}

/* ShiftRows for the Message Expansion */
void ShiftRows8(hashState *state){
	int i,j;
	u8 temp[16];

	for(i=0;i<8;i++)
	{		
		for(j=0;j<16;j++)
			temp[j]=state->MessageBlock[i][(j+ShiftRows8cMessage[i])%16];
		for(j=0;j<16;j++)
			state->MessageBlock[i][j]=temp[j];
	}
}

/* ShiftRows for the InternalRound for Cheetah-384 and Cheetah-512 */
void ShiftRows64(hashState *state){
	int i,j;
	u8 temp[8];
	
	for(i=0;i<state->nRows;i++)
	{			
		for(j=0;j<8;j++)
			temp[j]=state->a[i][(j+ShiftRows8c[i])%8];
		for(j=0;j<8;j++)
			state->a[i][j]=temp[j];
	}
}

/* Multiplication con * x in the field specified in Cheetah */
u8 mply(u8 con, u8 x){
	int i;
	u8 result=0;
	int power=1;

	for(i=0;i<8;i++){
		if(con%2==1)
			result^=xtimeN(x,power);		
		power++;
		con>>=1;

	}		
	return result;
}

/* MixColumn for InternalRound transformation for Cheetah-224 and Cheetah-256 */
void MixColumn4(hashState *state){
	int i,j,k;
	u8 temp[4][8];

	for(i=0;i<4;i++)
		for(j=0;j<8;j++)
			temp[i][j]=mply(MC4[i][0],state->a[0][j])^mply(MC4[i][1],state->a[1][j])^mply(MC4[i][2],state->a[2][j])^mply(MC4[i][3],state->a[3][j]);
	for(i=0;i<4;i++)
		for(j=0;j<8;j++)
			state->a[i][j]=temp[i][j];
}

/* MixColumn for Message Expansion transformation */
void MixColumn8(hashState *state){
	int i,j,k;
	u8 temp[8][16];

	for(i=0;i<8;i++)
		for(j=0;j<16;j++){
			temp[i][j]=0;
			for(k=0;k<8;k++)
				temp[i][j]^= mply(MC8 [i][k],state->MessageBlock[k][j]);
		}
	for(i=0;i<8;i++)
		for(j=0;j<16;j++)
			state->MessageBlock[i][j]=temp[i][j];
}

/* MixColumn for InternalRound transformation for Cheetah-384 and Cheetah-512 */
void MixColumn64(hashState *state){
	int i,j,k;
	u8 temp[8][8];

	for(i=0;i<8;i++)
		for(j=0;j<8;j++){
			temp[i][j]=0;
			for(k=0;k<8;k++)
				temp[i][j]^=mply(MC64[i][k],state->a[k][j]);
		}
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			state->a[i][j]=temp[i][j];
}

/* AddRoundConst transformation for the Message Expansion */
void AddRoundConstant(hashState *state, int r){
	int i;

	for(i=0;i<=3;i++)
		state->MessageBlock[i][0]^=SBox[4*r+i];		
}

/* Internal Round transformation for Cheetah-224 and Cheetah-256 */
void InternalRound(hashState *state){
	SubBytes(state);
	ShiftRows4(state);
	MixColumn4(state);
}

/* Internal Round transformation for Cheetah-348 and Cheetah-512 */
void InternalRound64(hashState *state){
	SubBytes(state);
	ShiftRows64(state);
	MixColumn64(state);
}

/* Message Expansion transformation. It expands 
   the input message block of 128 bytes to a block 
   of 128*rounds bytes. Each block of 128 bytes is 
   obtained by one application of Rijndael-like 
   transformation to the previous 128 byte block. 
 */
void MessageExpansion(hashState *state,const BitSequence *data, int rounds){
	int i,j,k;

	for(j=0;j<MBLEN/64;j++)
		for(i=0;i<8;i++ )
			state->ExpandedBlock[i][j] = state->MessageBlock[i][j] = *(u8 *)(data+  8*j+7-i);

	/* Salting */
	if( ((state->hashbitlen<=256)&&(SALT==1)) || ((state->hashbitlen>256)&&(SALT==2))){
		for(j=0;j<SALT;j++)		
			for(i=0;i<8;i++)
				state->ExpandedBlock[i][16-SALT+j] = state->salt[16*j+i];
	}

	for(k=1;k<=rounds;k++){
		SubBytesM(state);
		ShiftRows8(state);
		MixColumn8(state);
		AddRoundConstant(state,k);
		for(i=0;i<8;i++)
			for(j=0;j<16;j++) 
				state->ExpandedBlock[k*8+i][j]=state->MessageBlock[i][j];
	}

}

void compressCheetah32(hashState *state, const BitSequence *data, u64 blockCounter){
	u8 temp[8][8];
	int i,j,k;
	
	/* Saving the value of the state for the feedforward at the end 	*/
	for(i=0;i<state->nRows;i++)
		for(j=0;j<8;j++)
			temp[i][j]=state->a[i][j];

	/* Addition of the block counter 	*/		
	for(i=0;i<4;i++){
		state->a[i][0]^=(blockCounter >> (56 - i*8)) & 0xff;
		state->a[i][1]^=(blockCounter >> (24 - i*8)) & 0xff;
	}

	/* Message expansion: expand for three additional rounds  	*/
	MessageExpansion(state,data,3);		

	for(k=0;k<16;k++){
	
		/* Addition of the message block 	*/	
		for(i=0;i<4;i++)
			for(j=0;j<8;j++)
				state->a[i][j]^=state->ExpandedBlock[(k/2)*4+i][(k%2)*8+j];

		/* Internal round 	*/
		InternalRound(state); 		
	}	

	/* Second addition of the block counter  */	
	for(i=0;i<4;i++){
		state->a[i][0]^=(blockCounter >> (56 - i*8)) & 0xff;
		state->a[i][1]^=(blockCounter >> (24 - i*8)) & 0xff;
	}
	
	/*Feedforward 	*/	
	for(i=0;i<state->nRows;i++)
		for(j=0;j<8;j++)
			state->a[i][j]^=temp[i][j];  
}

/* Compression function for Cheetah-384 and Cheetah-512 */
void compressCheetah64(hashState *state, const BitSequence *data, u64 blockCounter){
	u8 temp[8][8];
	int i,j,k;	

	/* Saving the value of the state for the feedforward at the end */
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			temp[i][j]=state->a[i][j];

	/* Addition of the block counter */		
	for(i=0;i<8;i++){
		state->a[i][0]^=(blockCounter >> (56 - i*8)) & 0xff;		
	}

	/* Message expansion: expand for three additional rounds  	*/
	MessageExpansion(state,data,5);		

	for(k=0;k<12;k++){	
		/* Addition of the message block 	*/	
		for(i=0;i<8;i++)
			for(j=0;j<8;j++)
				state->a[i][j]^=state->ExpandedBlock[(k/2)*8+i][(k%2)*8+j];

		/* Internal round 	*/
		InternalRound64(state); 			
	}	

	/* Second addition of the block counter 	*/	
	for(i=0;i<8;i++){
		state->a[i][0]^=(blockCounter >> (56 - i*8)) & 0xff;		
	}
	
	/* Feedforward 	*/	
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			state->a[i][j]^=temp[i][j];
}

/* Permutation of the Internal State before processing the last message block */
void lastBlockPermutation(hashState *state){
	u8 tmp;
	int i,j;

	for(j=0;j<4;j++)
		for(i=0;i<state->nRows;i++){
			tmp=state->a[i][j];
			state->a[i][j]=state->a[i][j+4];
			state->a[i][j+4]=tmp;
		}
}

HashReturn Init(hashState *state, int hashbitlen){
	int i,j;

	if(!((hashbitlen==224)||(hashbitlen==256)||(hashbitlen==384)||(hashbitlen==512)))
		return BAD_HASHBITLEN;

	state->hashbitlen=hashbitlen;

	for(i=0;i<128;i++)
		state->rS[i]=0;

	if(	(hashbitlen==224)||(hashbitlen==256))
		state->nRows=4;
	else
		state->nRows=8;

	for(i=0;i<32;i++)
		state->salt[i]=0;

	for(i=0;i<state->nRows;i++)
		for(j=0;j<8;j++)
			state->a[i][j]=0;

	return SUCCESS;
}

/* The hash function supports salt. Further, the zero value for the salt is taken.   */
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen){
	unsigned long long doneLength=0,i;
	
	state->databitlen=databitlen;

	if(state->hashbitlen<=256){		
		while(doneLength+1<=databitlen/MBLEN){						
			compressCheetah32(state,data+doneLength,doneLength);
			doneLength++;			
		}
	}
	else{
		while(doneLength+1<=databitlen/MBLEN){									
			compressCheetah64(state,data+doneLength,doneLength);
			doneLength++;
		}
	}

	state->doneLength=doneLength;
	state->lRS = databitlen-MBLEN*doneLength;	

	for(i=0;i<state->lRS/8 + (state->lRS%8>1);i++){
		state->rS[i]=data[doneLength+i];		
	}
		
	return SUCCESS;
}


HashReturn Final(hashState *state, BitSequence *hashval){
	int i,j;	


	/* Padding with 1 and a number of 0s to fill the whole block.   */			

	/* If the last block is not filled then padded it with 1 and 0s */
	if(state->lRS>0){
		state->rS[(state->lRS/8)]&=0xff<<(8 - ( (state->lRS) & 0x7) );
		state->rS[(state->lRS/8)]^=0x01<<(7 - ( (state->lRS) & 0x7) );
		
		/*	If the last block is still not filled than try to 
			put the message length in the least block if possible. 
			The message length needs 8 bytes and the digest length 
			needs 2 bytes (in total 10 bytes). 
		 */
		if(state->lRS/8<MBLEN/8-10){
			for(i=1;i<=8;i++)
				state->rS[MBLEN/8-11+i]=((state->databitlen)>>(64-8*i)) & 0xff;
			state->rS[MBLEN/8-2]=((state->hashbitlen) >> 8) & 0xff;
			state->rS[MBLEN/8-1]= (state->hashbitlen) & 0xff;

			lastBlockPermutation(state);
			
			if(state->hashbitlen<=256){
				compressCheetah32(state,state->rS,state->doneLength);		
			}
			else{
				compressCheetah64(state,state->rS,state->doneLength);
			}
		}
		/*	Hash the last block and create additional block that 
			contains only the message length and digest length 
			and hash that block. 
		 */
		else{
			if(state->hashbitlen<=256){				
				compressCheetah32(state,state->rS,state->doneLength);		
			}
			else{
				compressCheetah64(state,state->rS,state->doneLength);
			}
			memset(state->rS,0,128);
			lastBlockPermutation(state);
			for(i=1;i<=8;i++)
				state->rS[MBLEN/8-11+i]=((state->databitlen)>>(64-8*i)) & 0xff;
			state->rS[MBLEN/8-2]=((state->hashbitlen) >> 8) & 0xff;
			state->rS[MBLEN/8-1]= (state->hashbitlen) & 0xff;
			if(state->hashbitlen<=256){				
				compressCheetah32(state,state->rS,state->doneLength+1);		
			}
			else{
				compressCheetah64(state,state->rS,state->doneLength+1);
			}		
		}
	}
	/*  Create new block with 1 and 0s and message length and digest 
		length and hash that block. 
	 */
	else{		
		state->rS[0]=0x80;
		for(i=1;i<=8;i++)
				state->rS[MBLEN/8-11+i]=((state->databitlen)>>(64-8*i)) & 0xff;
			state->rS[MBLEN/8-2]=((state->hashbitlen) >> 8) & 0xff;
			state->rS[MBLEN/8-1]= (state->hashbitlen) & 0xff;
		lastBlockPermutation(state);
		if(state->hashbitlen<=256){				
			compressCheetah32(state,state->rS,state->doneLength);		
		}
		else{
			compressCheetah64(state,state->rS,state->doneLength);
		}		
	}
	
	/* Produce output */
	if(state->hashbitlen<=256){				
		for(j=0;j<state->hashbitlen/32;j++){			
			for(i=0;i<4;i++)
				*(u8*)(hashval+4*j+3-i)=state->a[i][j];			
		}
	}
	else{
		for(j=0;j<state->hashbitlen/64;j++){			
			for(i=0;i<8;i++)
				*(u8*)(hashval+8*j+7-i)=state->a[i][j];			
		}
	}		

	return SUCCESS;
}
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval){
	hashState Temp;
		
	if(Init(&Temp,hashbitlen)==SUCCESS){			
		Update(&Temp,data,databitlen);			
		Final(&Temp,hashval);
		return  SUCCESS;
	}
	else return FAIL;
}
