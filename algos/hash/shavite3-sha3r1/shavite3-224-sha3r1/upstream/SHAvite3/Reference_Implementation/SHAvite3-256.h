#include "portable.h"
#include "AESround.h"
#include "SHA3api_ref.h"

#define InternalRounds256 3
#define ExternalRounds256 12
#define ExpandedMessageSize256 (ExternalRounds256*4*(InternalRounds256))

/* The message expansion takes a 16 words (stored in rk[0,.,15]) and */
/* the salt/counter values to produce the full expanded message      */

int MessageExpansion256 (u32 rk[ExpandedMessageSize256], u32 salt[8],
			 u32 counter[2])
{
   int i,j,k;
   u32 input[4],output[4];

/* There are four iterations of the message expansion steps          */
   for (k=0;k<4;k++) 
   {

/* The nonlinear expansion step  				     */

      for (i=16+32*k;i<32+32*k;)
      {
         input[0]=rk[i-15];
         input[1]=rk[i-14];
         input[2]=rk[i-13];
         input[3]=rk[i-16];

/* Round of AES using salt[0..3] as the masking subkey               */
         roundAESkeyfirst(input,output,salt);

         for (j=0;j<4;j++)
            rk[i+j] = output[j] ^ rk[i+j-4];

/* Mixing the counter 						     */

	 if (i==16) 
         {
	    rk[16] ^= counter[0];
	    rk[17] ^= counter[1];
         }
	 if (i==56) 
	 {
	    rk[57] ^= counter[1];
	    rk[58] ^= counter[0];
         }

         i += 4;

         input[0]=rk[i-15];
         input[1]=rk[i-14];
         input[2]=rk[i-13];
         input[3]=rk[i-16];

/* Round of AES using salt[4..7] as the masking subkey               */
         roundAESkeyfirst(input,output,salt+4);

         for (j=0;j<4;j++)
            rk[i+j] = output[j] ^ rk[i+j-4];

/* Mixing the counter 						     */
	 if (i==84) 
	 {
	    rk[86] ^= counter[1];
	    rk[87] ^= counter[0];
         }
	 if (i==124) 
	 {
	    rk[124] ^= counter[0];
	    rk[127] ^= counter[1];
         }
         i += 4;
      }

/* The linear expansion step      				     */

      for (i=32+32*k;i<48+32*k;i++)
         rk[i] = rk[i-16]^rk[i-3];
   }

   return;
}

/* Encrypts the plaintext pt[] using the key message[], salt[],      */
/* and counter[], to produce the ciphertext ct[]                     */

void E256(u32 pt[8], u32 ct[8], u32 message[16], u32 salt[8], u32 counter[2])
{
   u32 state[8],i,j;
   u32 input[4],output[4],temp;
   u32 rk[ExpandedMessageSize256];

/* Setting the internal state 					     */

   for (i=0;i<8;i++)
      state[i]=pt[i]; 

  
/* Initializing the rk[] array with the message words		     */

   for (i=0;i<16;i++) 
      rk[i]=message[i];

   
/* Expanding the message 					     */

   MessageExpansion256(rk,salt,counter);
  

/* Repeat the round function 12 times 				     */

   for (i=0;i<ExternalRounds256;i++)
   {

     
/* setting the round function input                                  */

      for (j=0;j<4;j++) 
         input[j]=state[4+j];

/* F_3 performs 3 AES rounds 					     */
      roundAESkeyfirst(input,output,rk+12*i);
      for (j=0;j<4;j++)
	 input[j]=output[j];
      roundAESkeyfirst(input,output,rk+12*i+4);
      for (j=0;j<4;j++)
	 input[j]=output[j];
      roundAESkeyfirst(input,output,rk+12*i+8);

/* XORing the output of the F3 to the left half                      */

      for (j=0;j<4;j++)
	 state[j]^=output[j];


/* Swapping the two halves 					     */

      for (j=0;j<4;j++) {
	 temp = state[j];
	 state[j] = state[j+4];
	 state[j+4] = temp;
      }

   }


/* Copying the ciphertext to the output				     */

   for (i=0;i<8;i++) 
      ct[i]=state[i]; 
   
   return;
}

/* The actual compression function C_{256}                           */

void Compress256(const u8 *message_block, u8 *chaining_value, u64 counter,
	      const u8 salt[32])
{    
   u32 pt[8],ct[8];
   u32 msg_u32[16];
   u32 salt_u32[8];
   u32 cnt[2];
   int i;

/* Translating all the inputs to 32-bit words			     */

   for (i=0;i<8;i++)
      pt[i]=U8TO32_LITTLE(chaining_value+4*i);

   for (i=0;i<16;i++)
      msg_u32[i]=U8TO32_LITTLE(message_block+4*i);

   for (i=0;i<8;i++)
      salt_u32[i]=U8TO32_LITTLE(salt+4*i);
   
   cnt[1]=(u32)(counter>>32);
   cnt[0]=(u32)(counter & 0xFFFFFFFFULL);


/* Computing the encryption function				     */

   E256(pt, ct, msg_u32, salt_u32, cnt);


/* Davies-Meyer transformation 					     */
   
   for (i=0; i<8; i++)
       pt[i]^=ct[i];


/* Translating the output to 8-bit words			     */

   for (i=0; i<8; i++)
       U32TO8_LITTLE(chaining_value+i*4, pt[i]);

   return;
}
