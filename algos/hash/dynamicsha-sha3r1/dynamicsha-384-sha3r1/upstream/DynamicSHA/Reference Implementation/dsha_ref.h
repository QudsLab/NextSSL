#include <stdlib.h>
#define ROTR64(x,n)   (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTR32(x,n)   (((x) >> (n)) | ((x) << (32 - (n))))
typedef unsigned char BitSequence;  
typedef unsigned long long DataLength; 
typedef unsigned long long uint_64t; 
typedef unsigned long uint_32t;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn; 
typedef struct
{
    DataLength databitlen[2];
    unsigned int hashbitlen;
    unsigned int blocksize;
    BitSequence block[129];
	unsigned long hashval[16];
} hashState;
const uint_32t i224[8] =
{
    0xc1059ed8ul, 0x367cd507ul, 0x3070dd17ul, 0xf70e5939ul,
    0xffc00b31ul, 0x68581511ul, 0x64f98fa7ul, 0xbefa4fa4ul
};
const uint_32t i256[8] =
{
    0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,
    0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul
};
const uint_32t  i384[16] =
{
    0xcbbb9d5d,  0xc1059ed8,  0x629a292a,  0x367cd507,
    0x9159015a,  0x3070dd17,  0x152fecd8,  0xf70e5939,
    0x67332667,  0xffc00b31,  0x8eb44a87,  0x68581511,
    0xdb0c2e0d,  0x64f98fa7,  0x47b5481d,  0xbefa4fa4
};
const uint_32t  i512[16] =
{
    0x6a09e667,  0xf3bcc908,  0xbb67ae85,  0x84caa73b,
    0x3c6ef372,  0xfe94f82b,  0xa54ff53a,  0x5f1d36f1,
    0x510e527f,  0xade682d1,  0x9b05688c,  0x2b3e6c1f,
    0x1f83d9ab,  0xfb41bd6b,  0x5be0cd19,  0x137e2179
};

HashReturn Init(hashState *state, int hashbitlen);   
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen); 
HashReturn Final(hashState *state, BitSequence *hashval); 
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);
HashReturn sha32_compile(hashState *state);
HashReturn sha64_compile(hashState *state);

HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
hashState state;
HashReturn HReturn;

HReturn=Init(&state, hashbitlen); 
if (HReturn != SUCCESS) {	return HReturn;}

HReturn=Update(&state, data, databitlen); 
if (HReturn != SUCCESS) { 	return HReturn;}

HReturn=Final(&state, hashval); 
if (HReturn != SUCCESS) { return HReturn;}

return HReturn;
}

HashReturn Init(hashState *state, int hashbitlen)
{
	int i;

state->hashbitlen=hashbitlen ; 
state->databitlen[0]=0;
state->databitlen[1]=0;
for (i=0;i<129;i++) (state->block)[i]= 0x0 ;

if ((hashbitlen==224) || (hashbitlen==256) || (hashbitlen==384) || (hashbitlen==512))
{
    if ((hashbitlen==224) || (hashbitlen==256))   state->blocksize=512;
    if ((hashbitlen==384) || (hashbitlen==512))   state->blocksize=1024;
	if (hashbitlen==224)  for(i=0;i<(state->blocksize/64);i++) (state->hashval)[i]=i224[i] ;
    if (hashbitlen==256)  for(i=0;i<(state->blocksize/64);i++) (state->hashval)[i]=i256[i] ;
    if (hashbitlen==384)  for(i=0;i<(state->blocksize/64);i++) (state->hashval)[i]=i384[i] ;
    if (hashbitlen==512)  for(i=0;i<(state->blocksize/64);i++) (state->hashval)[i]=i512[i] ;
}
else
{
	return BAD_HASHLEN;
}
return SUCCESS;
}

HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
HashReturn HReturn;
BitSequence  tempc;
unsigned int oldbitlen;
int  i,sbyte, mbits;

oldbitlen=state->databitlen[1] % state->blocksize;
state->databitlen[1]+=databitlen;
if (state->databitlen[1]<databitlen) state->databitlen[0]+=1;
sbyte=oldbitlen >> 3;
mbits=oldbitlen & 0x7;
(state->block)[state->blocksize / 8] = 0x0;

for (i=0;i<(databitlen+7)/8;i++)
{
	tempc=data[i];
	(state->block)[sbyte]=(state->block)[sbyte] | (tempc >> mbits);
	(state->block)[sbyte+1]=tempc << (8-mbits);
	sbyte+=1;	
	if (sbyte==( state->blocksize/8))
	{
		if (state->blocksize==512) HReturn=sha32_compile(state);
		if (state->blocksize==1024) HReturn=sha64_compile(state); 
		if (HReturn != SUCCESS) { 	return HReturn;}		
		sbyte=0;
		(state->block)[0]=(state->block)[state->blocksize / 8] ;
	}
}
return SUCCESS;
}
HashReturn Final(hashState *state, BitSequence *hashval)
{
HashReturn HReturn;
BitSequence   hv[64],temp ;
DataLength dl;
int t,t1, i,maxl;

t1=((state->databitlen[1]) % (state->blocksize))/8;
t=7-(state->databitlen[1] % 8);
temp=((state->block)[t1] >> t) | 0x1;
(state->block)[t1]=temp << t; 

maxl=65;
if (state->blocksize==1024) maxl=129;
if ((state->databitlen[1] % (state->blocksize))>(state->blocksize-maxl))
{             
	if (state->blocksize==512) HReturn=sha32_compile(state);
	if (state->blocksize==1024) HReturn=sha64_compile(state);	
    if (HReturn != SUCCESS) { return HReturn;}

    //  second block
    for ( i=0; i<128; i++ )  
        (state->block)[i]=0x0;
}

t=state->blocksize/8;
dl=state->databitlen[1];
for (i=1;i<9;i++){
	(state->block)[t-i]=dl & 0xff;	
	dl=(dl >> 8);
}
if (state->blocksize==1024) {
	dl=state->databitlen[0];
	for (i=9;i<17;i++){
		(state->block)[t-i]=dl & 0xff;	
		dl=(dl >> 8);
	}
}

if (state->blocksize==512) HReturn=sha32_compile(state);
if (state->blocksize==1024) HReturn=sha64_compile(state);

for(i=0;i<16;i++) {
		hv[4*i]=((state->hashval)[i] >> 24) & 0xff ;
		hv[4*i+1]=((state->hashval)[i] >> 16) & 0xff ;
		hv[4*i+2]=((state->hashval)[i] >> 8) & 0xff ;
		hv[4*i+3]=(state->hashval)[i] & 0xff ;			
}
t=state->blocksize/16;
for(i=0;i<t;i++) hashval[i]=hv[i];
return HReturn;
} 

HashReturn sha32_compile(hashState *state)
{  
uint_32t hash_32[8], ch[8], temp, w[16],tt[3];
int i;

for (i=0;i<16;i++)
{
	w[i]=(state->block)[4*i];
	w[i]=w[i]<<8 | ((state->block)[4*i+1]);
	w[i]=w[i]<<8 | ((state->block)[4*i+2]);
	w[i]=w[i]<<8 | ((state->block)[4*i+3]);	
}

for (i=0;i<8;i++) {
	ch[i]=state->hashval[i];
	hash_32[i]=state->hashval[i];
}

tt[0]=0x5a827999;
tt[1]=0x6ed9eba1;
tt[2]=0x8f1bbcdc;

//iterative part
for ( i=0; i<48; i++ ) {
	temp=(((((ch[0]+ch[1])^ch[2])+ch[3])^ch[4])+ch[5])^ch[6];
    temp=((temp>>17) ^ temp) & 0x1ffff;
	temp=((temp>>10) ^ temp) & 0x3ff;
	temp=((temp>>5) ^ temp) & 0x1f;
	temp=ROTR32( ch[7] ,temp );
	ch[7]=ch[6];
	ch[6]=ch[5];
	ch[5]=ch[4];
	ch[4]=ch[3];
	
    switch (i % 4) 
    { case 0: ch[3]=w[i % 16]+(ch[0] ^ ch[1] ^ ch[2])+tt[i / 16];
              break;
      case 1: ch[3]=w[i % 16]+((ch[0] & ch[1]) ^ ch[2] )+tt[i / 16];
		      break;
      case 2: ch[3]=w[i % 16]+((~(ch[0] | ch[2])) | (ch[0] & (ch[1] ^ ch[2])))+tt[i / 16];
		      break;
      case 3: ch[3]=w[i % 16]+((~(ch[0] | (ch[1] ^ ch[2]))) | (ch[0] & (~(ch[2]))))+tt[i / 16]; 
		      break;
    }

    ch[2]=ch[1];
	ch[1]=ch[0];
	ch[0]=temp;	
}
                
// Compute intermediate hash value 
for ( i=0;i<8;i++){
    hash_32[i] +=ch[i];
	state->hashval[i]=hash_32[i];
}
return SUCCESS;
}

HashReturn sha64_compile(hashState *state)
{  
uint_64t hash_64[8], ch[8], temp, w[16],tt[3];
int i;

for (i=0;i<16;i++)
{
	w[i]=(state->block)[8*i];
	w[i]=w[i]<<8 | (state->block)[8*i+1];
	w[i]=w[i]<<8 | (state->block)[8*i+2];
	w[i]=w[i]<<8 | (state->block)[8*i+3];
	w[i]=w[i]<<8 | (state->block)[8*i+4];
	w[i]=w[i]<<8 | (state->block)[8*i+5];
	w[i]=w[i]<<8 | (state->block)[8*i+6];
	w[i]=w[i]<<8 | (state->block)[8*i+7];
}

//Initialize eight working variables 
for (i=0;i<8;i++)
{	
	temp=(state->hashval)[i*2];
	ch[i]=(temp<< 32)+(state->hashval)[i*2+1];
	hash_64[i]=ch[i];
}


tt[0]=0x5a82799950a28be6;
tt[1]=0x6ed9eba15c4dd124;
tt[2]=0x8f1bbcdc6d703ef3;

//iterative part
for (i=0;i<48;i++)
{
 	temp=(((((ch[0]+ch[1])^ch[2])+ch[3])^ch[4])+ch[5])^ch[6];
    temp=((temp>>36) ^ temp) & 0xfffffffff;
	temp=((temp>>18) ^ temp) & 0x3ffff;
	temp=((temp>>12) ^ temp) & 0xfff;
	temp=((temp>>6) ^ temp) & 0x3f;
	temp=ROTR64(ch[7],temp);
	ch[7]=ch[6];
	ch[6]=ch[5];
	ch[5]=ch[4];
	ch[4]=ch[3];
	
    switch (i % 4) 
    { case 0: ch[3]=w[i % 16]+(ch[0] ^ ch[1] ^ ch[2])+tt[i / 16];
              break;
      case 1: ch[3]=w[i % 16]+((ch[0] & ch[1]) ^ ch[2] )+tt[i / 16];
		      break;
      case 2: ch[3]=w[i % 16]+((~(ch[0] | ch[2])) | (ch[0] & (ch[1] ^ ch[2])))+tt[i / 16];
		      break;
      case 3: ch[3]=w[i % 16]+((~(ch[0] | (ch[1] ^ ch[2]))) | (ch[0] & (~(ch[2]))))+tt[i / 16]; 
		      break;
    }
    ch[2]=ch[1];
	ch[1]=ch[0];
	ch[0]=temp;
}

// Compute intermediate hash value 
for (i=0;i<8;i++){
    hash_64[i] +=ch[i];	
	(state->hashval)[2*i]=hash_64[i] >> 32 ;
	(state->hashval)[2*i+1]=hash_64[i] & 0xffffffff;
}
return SUCCESS;
}