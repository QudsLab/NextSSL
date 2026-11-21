#include "portable.h"
#include "AESround.h"
#include "SHA3api_ref.h"
 
#define InternalRounds512 4
#define ExternalRounds512 14
#define ExpandedMessageSize512 (ExternalRounds512*4*(InternalRounds512)*2)

/* The message expansion takes a 16 words (stored in rk[0,.,15]) and */
/* the salt/counter values to produce the full expanded message      */

int MessageExpansion512 (u32 rk[ExpandedMessageSize512], u32 salt[16],
			 u32 counter[4])
{
   int i,j,k;
   u32 input[4],output[4];

/* There are six full iterations of the message expansion steps      */

   for (k=0;k<7;k++) 
      {

/* The nonlinear expansion step                                      */

      for (i=32+64*k;i<64+64*k;)
      {
         input[0]=rk[i-31];
         input[1]=rk[i-30];
         input[2]=rk[i-29];
         input[3]=rk[i-32];

/* Round of AES using salt[0..3] as the masking subkey               */
         roundAESkeyfirst(input,output,salt);

         for (j=0;j<4;j++)
            rk[i+j] = output[j] ^ rk[i+j-4];

/* Mixing the counter                                                */
	 if (i==32) 
	 {
	    rk[32] ^= counter[0];
	    rk[33] ^= counter[1];
	    rk[34] ^= counter[2];
	    rk[35] ^= ~counter[3];
         }

         i += 4;

         input[0]=rk[i-31];
         input[1]=rk[i-30];
         input[2]=rk[i-29];
         input[3]=rk[i-32];

/* Round of AES using salt[4..7] as the masking subkey               */
         roundAESkeyfirst(input,output,salt+4);

         for (j=0;j<4;j++)
            rk[i+j] = output[j] ^ rk[i+j-4];

/* Mixing the counter                                                */
	 if (i==164) 
	 {
	    rk[164] ^= counter[3];
	    rk[165] ^= counter[2];
	    rk[166] ^= counter[1];
	    rk[167] ^= ~counter[0];
         }
         i += 4;

         input[0]=rk[i-31];
         input[1]=rk[i-30];
         input[2]=rk[i-29];
         input[3]=rk[i-32];

/* Round of AES using salt[8..11] as the masking subkey              */
         roundAESkeyfirst(input,output,salt+8);

         for (j=0;j<4;j++)
            rk[i+j] = output[j] ^ rk[i+j-4];

/* Mixing the counter                                                */

	 if (i==440) 
	 {
	    rk[440] ^= counter[1];
	    rk[441] ^= counter[0];
	    rk[442] ^= counter[3];
	    rk[443] ^= ~counter[2];
         }

         i += 4;

         input[0]=rk[i-31];
         input[1]=rk[i-30];
         input[2]=rk[i-29];
         input[3]=rk[i-32];

/* Round of AES using salt[12..15] as the masking subkey             */
         roundAESkeyfirst(input,output,salt+12);

         for (j=0;j<4;j++)
            rk[i+j] = output[j] ^ rk[i+j-4];

/* Mixing the counter                                                */
	 if (i==316) 
	 {
	    rk[316] ^= counter[2];
	    rk[317] ^= counter[3];
	    rk[318] ^= counter[0];
	    rk[319] ^= ~counter[1];
         }
         i += 4;
      }

/* The linear expansion step is done only six times                  */

      if (k!=6)
         for (i=64+64*k;i<96+64*k;i++)
            rk[i] = rk[i-32]^rk[i-7];
   }

   return;
}

/* Encrypts the plaintext pt[] using the key message[], salt[],      */
/* and counter[], to produce the ciphertext ct[]                     */

void E512(u32 pt[16], u32 ct[16], u32 message[32], u32 salt[16], u32 counter[4])
{
   u32 state[16],i,j;
   u32 input[4],output[4],temp;
   u32 rk[ExpandedMessageSize512];

/* Setting the internal state                                        */

   for (i=0;i<16;i++) 
      state[i]=pt[i]; 

  
/* Initializing the rk[] array with the message words                */

   for (i=0;i<32;i++) 
      rk[i]=message[i];


/* Expanding the message                                             */

   MessageExpansion512(rk,salt,counter);


/* Repeat the round function 14 times                                */

   for (i=0;i<ExternalRounds512;i++)
   {


/* setting the round function input                                  */

      for (j=0;j<4;j++) 
          input[j]=state[4+j];


/* F_4 performs 4 AES rounds                                         */

      roundAESkeyfirst(input,output,rk+32*i);
      for (j=0;j<4;j++)
	 input[j]=output[j];
      roundAESkeyfirst(input,output,rk+32*i+4);
      for (j=0;j<4;j++)
	 input[j]=output[j];
      roundAESkeyfirst(input,output,rk+32*i+8);
      for (j=0;j<4;j++)
	 input[j]=output[j];
      roundAESkeyfirst(input,output,rk+32*i+12);


/* XORing the output of the F4 to the next 128-bit word 	     */

      for (j=0;j<4;j++)
	 state[j]^=output[j];


/* Apply F_4 again (to the third 128-bit word)                       */

      for(j=0;j<4;j++) 
         input[j]=state[12+j];


/* F_4 performs 4 AES rounds                                         */

      roundAESkeyfirst(input,output,rk+32*i+16);
      for(j=0;j<4;j++)
	 input[j]=output[j];
      roundAESkeyfirst(input,output,rk+32*i+20);
      for(j=0;j<4;j++)
	 input[j]=output[j];
      roundAESkeyfirst(input,output,rk+32*i+24);
      for(j=0;j<4;j++)
	 input[j]=output[j];
      roundAESkeyfirst(input,output,rk+32*i+28);


/* XORing the output of the F4 to the next 128-bit word 	     */

      for (j=0;j<4;j++)
	 state[8+j]^=output[j];


/* Rotating the four words 					     */

      for (j=0;j<4;j++) 
      {
	 temp = state[j+12];
	 state[j+12] = state[j+8];
	 state[j+8] = state[j+4];
	 state[j+4] = state[j];
	 state[j] = temp;
      }
   }


/* Copying the ciphertext to the output                              */

   for (i=0;i<16;i++) 
      ct[i]=state[i]; 

   return;
}

/* The actual compression function C_{512}                           */

void Compress512(const u8 *message_block, u8 *chaining_value, u64 counter,
	      const u8 salt[64])
{    
   u32 pt[16],ct[16];
   u32 msg_u32[32];
   u32 salt_u32[16];
   u32 cnt[4];
   int i;

/* Translating all the inputs to 32-bit words                        */

   for (i=0;i<16;i++)
      pt[i]=U8TO32_LITTLE(chaining_value+4*i);

   for (i=0;i<32;i++)
      msg_u32[i]=U8TO32_LITTLE(message_block+4*i);

   for (i=0;i<16;i++)
      salt_u32[i]=U8TO32_LITTLE(salt+4*i);

   cnt[1]=(u32)(counter>>32);
   cnt[0]=(u32)(counter & 0xFFFFFFFFULL);

/* Due to NIST specifications, there are no messages of length       */
/* longer than 2^64 that are expected				     */

   cnt[2]=0;
   cnt[3]=0;

/* Computing the encryption function                                 */

   E512(pt, ct, msg_u32, salt_u32, cnt);


/* Davies-Meyer transformation                                       */

   for (i=0;i<16;i++) 
       pt[i]^=ct[i]; 


/* Translating the output to 8-bit words                             */

   for(i=0; i<16; i++)
       U32TO8_LITTLE(chaining_value+i*4, pt[i]); 

   return;
}
