/*	Reference implementation of hash family LUX 	
	Author: Ivica Nikolic, University of Luxembourg
*/

#include <stdio.h>
#include <string.h>
#include "LUX.h"

/* Multiplication 2*a in the field specified in LUX */
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

/* Multiplication con * x in the field specified in LUX */
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

/* SubBytes for the core function G for LUX-224 and LUX-256 */
void SubBytes4(hashState *state){
	int i,j;

	for(i=0;i<4;i++)
		for(j=0;j<8;j++)
			state->cr[i][j]=SBox[state->cr[i][j]];    			
}

/* SubBytes for LUX-384, LUX-512 */
void SubBytes8(hashState *state){
	int i,j;
	
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			state->cr[i][j]=SBox[state->cr[i][j]];    			
}

/* ShiftRows for the core function G for LUX-224 and LUX-256 */
void ShiftRows4(hashState *state){
	int i,j;
	u8 temp[8];
	
	for(i=0;i<4;i++)
	{			
		for(j=0;j<8;j++)
			temp[j]=state->cr[i][(j+ShiftRows4c[i])%8];
		for(j=0;j<8;j++)
			state->cr[i][j]=temp[j];
	}
}

/* ShiftRows for the core function G for LUX-384 and LUX-512 */
void ShiftRows8(hashState *state){
	int i,j;
	u8 temp[8];
	
	for(i=0;i<8;i++)
	{			
		for(j=0;j<8;j++)
			temp[j]=state->cr[i][(j+ShiftRows8c[i])%8];
		for(j=0;j<8;j++)
			state->cr[i][j]=temp[j];
	}
}

/* MixColumn for the core function G for LUX-224 and LUX-256 */
void MixColumns4(hashState *state){
	int i,j;
	u8 temp[4][8];

	for(i=0;i<4;i++)
		for(j=0;j<8;j++)
			temp[i][j]=mply(MC4[i][0],state->cr[0][j])^mply(MC4[i][1],state->cr[1][j])^mply(MC4[i][2],state->cr[2][j])^mply(MC4[i][3],state->cr[3][j]);
	for(i=0;i<4;i++)
		for(j=0;j<8;j++)
			state->cr[i][j]=temp[i][j];
}

/* MixColumn for the core function G for LUX-384 and LUX-512 */
void MixColumns8(hashState *state){
	int i,j,k;
	u8 temp[8][8];

	for(i=0;i<8;i++)
		for(j=0;j<8;j++){
			temp[i][j]=0;
			for(k=0;k<8;k++)
				temp[i][j]^=mply(MC8[i][k],state->cr[k][j]);
		}
	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			state->cr[i][j]=temp[i][j];
}

/* AddConstant for the core function G for LUX-224 and LUX-256 */
void AddConstant(hashState *state){

	state->cr[0][0]^=0x2a;
	state->cr[1][0]^=0xd0;
	state->cr[2][0]^=0x1c;
	state->cr[3][0]^=0x64;	
}

/* AddConstant the core function G for LUX-384 and LUX-512  */
void AddConstant8(hashState *state){

	state->cr[4][0]^=0x2a;
	state->cr[5][0]^=0xd0;
	state->cr[6][0]^=0x1c;
	state->cr[7][0]^=0x64;	
}

/*	Function G. This is a Rijndael-like transformation. 
	It updates only the core C. 
 */
void functionG(hashState *state){
	if(state->mRows==4){
		SubBytes4(state);
		ShiftRows4(state);
		MixColumns4(state);
		AddConstant(state);
	}
	else{
		SubBytes8(state);
		ShiftRows8(state);
		MixColumns8(state);		
		AddConstant8(state);
	}
}
/* Function F. Simple rotation by 1 to the right of the buffer. */
void functionF(hashState *state){
	u8 temp[8];
	int i,j;

	for(i=0;i<state->mRows;i++)
		temp[i]=state->bf[i][15];

	for(j=15;j>0;j--)
		for(i=0;i<state->mRows;i++)
			state->bf[i][j]=state->bf[i][j-1];

	for(i=0;i<state->mRows;i++)
		state->bf[i][0]=temp[i];
}		


/* State Update Function */
void compressLUX(hashState *st, const BitSequence *data){	
	int i,j; 		
	
	/* Addition of the message block to the buffer and the core	 */
	for(i=0;i<st->mRows;i++){
		st->bf[i][0]^=*(u8 *)(data + st->mRows-1-i);
		st->cr[i][0]^=*(u8 *)(data + st->mRows-1-i);
	}

    /* Core transformation G  */
	functionG(st);

	/* Buffer transformation F 	 */
	functionF(st);

	/* Feedback from the core to the buffer  */
	for(j=0;j<8;j++)
		for(i=0;i<st->mRows;i++)
			st->bf[i][j+4]^=st->cr[i][j];

	/* Feedback from the buffer to the core  */		
	for(i=0;i<st->mRows;i++)
		st->cr[i][7]^=st->bf[i][15];
}

HashReturn Init(hashState *state, int hashbitlen){
	int i,j;

	if(!((hashbitlen==224)||(hashbitlen==256)||(hashbitlen==384)||(hashbitlen==512)))
		return BAD_HASHBITLEN;

	state->hashbitlen=hashbitlen;		

	for(i=0;i<8;i++)
		state->remSeq[i]=0;

	for(i=0;i<8;i++)
		for(j=0;j<8;j++)
			state->cr[i][j]=0;

	for(i=0;i<8;i++)
		for(j=0;j<16;j++)
			state->bf[i][j]=0;
	
	if(state->hashbitlen<=256)
		state->mRows=4;
	else
		state->mRows=8;

	return SUCCESS;
}

HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen){

	unsigned long long doneLength=0,i;

	state->databitlen=databitlen;
		
	/*	Compress all full 4 byte blocks of message */
	while(doneLength+state->mRows <= databitlen/8){		
			compressLUX(state,data+doneLength);				
			doneLength += state->mRows;			
	}
		
	/* The remaining input is stored for further processing in Final()	 */
	state->lenRemSeq=(unsigned int)(databitlen-8*doneLength);	
	for(i=0;i<state->lenRemSeq/8+(state->lenRemSeq%8>0);i++){
			state->remSeq[i]=data[doneLength+i];		
	}

	return SUCCESS;
}

HashReturn Final(hashState *state, BitSequence *hashval){
	int i,j;
	BitSequence empty[128];	

	/*	If the block is not full then add 1 and a number of 0s.	 */
	if(state->lenRemSeq>0){		
		state->remSeq[state->lenRemSeq>>3] &=(0xff)<<(8-(state->lenRemSeq & 7));
		state->remSeq[state->lenRemSeq>>3] ^=(0x01)<<(7-((state->lenRemSeq) & 7));	
	}
	/*	Else create new block with 1 and 31 zeros. */
	else{
		state->remSeq[0]=0x80;
	}

	/*	Hash the padded block.   */
	compressLUX(state,state->remSeq); 
	
	/*	Additional block(s) that contain the input 
		length is(are) created and compressed. For LUX-224 and LUX-256, 
		the message blocks are only 32 bits, therefore the message length 
		represantion takes two block. 
	*/
	for(i=0;i<8;i++)
		empty[i]   = ( (state->databitlen)>>(56-8*i) ) & 0xff;	
	if(state->hashbitlen<=256){		
		compressLUX(state,empty);
		compressLUX(state,empty+4);
	}	
	else{
		compressLUX(state,empty);
	}

	/*	16 blank rounds are iterated. 
		The input for the blank rounds are blocks with 0s.
	 */
	memset(empty, 0, 128);
	for(i=0;i<16;i++){
		compressLUX(state,empty);			
	}

	/*	Input, the core element C_3, is produced */
	if(state->hashbitlen<=256){ 
		for(j=0;j<state->hashbitlen/32;j++){
			compressLUX(state,empty);			
			for(i=3;i>=0;i--)
				*(u8 *)(hashval + 4*j+3-i) = state->cr[i][3 ];			
		}
	}
	else{
		for(j=0;j<state->hashbitlen/64;j++){
			compressLUX(state,empty);
			for(i=7;i>=0;i--)
				*(u8 *)(hashval + 8*j+7-i) = state->cr[i][3];	
		}
	}
 
	return SUCCESS;
}


HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval){
	hashState Temp;

	if(Init(&Temp,hashbitlen)==SUCCESS){	
		Update(&Temp,data,databitlen );	
		Final(&Temp,hashval);
		return  SUCCESS;
	}
	else return FAIL;
}

/*	AddSalt introduces additional rounds in the begining
	of processing the message. 
*/
HashReturn AddSalt(hashState *state, BitSequence *salt){
	
	compressLUX(state,salt);
	compressLUX(state,salt+state->mRows);
	compressLUX(state,salt+2*state->mRows);
	compressLUX(state,salt+3*state->mRows);

	return SUCCESS;
}

/*	Hashing with salt. The value of salt is 16 bytes for LUX-224 and LUX-256,
	and 32 bytes for LUX-384 and LUX-512 
*/
HashReturn HashSalt(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval, BitSequence *salt){
	hashState Temp;

	if(Init(&Temp,hashbitlen)==SUCCESS){			
		AddSalt(&Temp,salt);
		Update(&Temp,data,databitlen );	
		Final(&Temp,hashval);
		return  SUCCESS;
	}
	else return FAIL;
}

