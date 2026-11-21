/**
 * \file
 *         Implmentation of Compact-LWE puiblic key encryption scheme developed in CSIRO
 *         09-11-2017
 *         Dongxi Liu <dongxi.liu@csiro.au>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "compact-lwe.h"

//key pair generation with parameters specified in compact-lwe.h
int crypto_encrypt_keypair(unsigned char *pk_str, unsigned char *sk_str){
	
	int len, j;

	struct SK sk;
	//generate the private key sk
 	len = sk_gen(&sk); 
	if(len==-1)
		return -1;

	//convert sk into a byte array sk_str
  	len = sk_out_str(&sk, sk_str, CRYPTO_SECRETKEYBYTES); 

	//generate the public key pk_str from the private key sk
	len = pk_gen(&sk, pk_str); 

	//free space used by sk
	mpz_clear (sk.wPos);
	mpz_clear (sk.wNeg);		
	mpz_clear (sk.p);	
	mpz_clear (sk.q);	
        mpz_clear (sk.r);	
        mpz_clear (sk.t);	
	mpz_clear (sk.bv);

	for(j=0; j< F; j++){
		mpz_clear (sk.kInv[j]);
        }

	 mpz_clear (sk.ckInv);
 	
	if(len>0)
		len=0;	

	return len;
}

//encrypt plaintext m1 into ciphertext c with public key pk_str
int crypto_encrypt(
 unsigned char *c, unsigned long long *clen,
 const unsigned char *m1, unsigned long long mlen1,
 const unsigned char *pk_str
 ){

	unsigned char *m;
	unsigned long extra=0, group_size;

	//calculate the number of extra padding bytes, such that the length
    //of padded messages are aligned with T_BYTES 
	if((mlen1+L+3)%T_BYTES!=0)
		extra = T_BYTES - ((mlen1+L+3)%T_BYTES);

	group_size = (mlen1+L+3+extra)/T_BYTES;
	m = malloc(mlen1+L+3+extra);

	//encode message m1 into m with the encode algorithm as described in Section 2.3.2 of the specification
	encode(m1, mlen1, m, mlen1+L+3+extra);
		
	
	int c_pos=0;
	int i, j;
	
	unsigned long single_clen = F*Q_BYTES+2*(N-1)+T_BYTES; //the length of a ciphertext from basic encryption


	struct PK* pk;
	pk = pk_in_str(pk_str, CRYPTO_PUBLICKEYBYTES);
	if(pk==NULL){
		#ifdef debug
			printf("failed to load public key \n");			
		#endif
		return -1;
	}

	struct Cipher D; 

	//encrypt each message block of lenght T_BYTES
	//convert each ciphertext block into a byte array
	for(i=0; i < group_size; i++){
		enc(pk, m+i*T_BYTES, &D);

			
 		int cipher_len = cipher_out_str(&D, c+c_pos, (*clen)-c_pos);
		if(cipher_len!=single_clen){
			#ifdef debug
				printf("something wrong in cipher_out_str \n");			
			#endif		
			return -1;
		}

		c_pos = c_pos + cipher_len;
		clearCipher(&D);
	}

	*clen = c_pos;

	clearPK(pk);
	free(pk);
	free(m);

	return 0;

}

//decrypt c into plaintext m1 with private key sk_str 
int crypto_encrypt_open(
 unsigned char *m1, unsigned long long *mlen,
 const unsigned char *c, unsigned long long clen,
 const unsigned char *sk_str
 ){

	unsigned long single_clen = F*Q_BYTES+2*(N-1)+T_BYTES; //the length of a ciphertext from basic encryption
	unsigned long group_size = clen/single_clen;
	if(clen%single_clen!=0){
		printf("Incorrect length ciphertext buffer\n");		
		return -1;
	}

	unsigned long real_mlen = group_size*(T_BYTES);


	unsigned char *m = malloc(real_mlen);

	struct SK* sk;
	//convert the private key sk_str from a byte array to sk of type struct SK
	sk = sk_in_str(sk_str, CRYPTO_SECRETKEYBYTES);
	if(sk==NULL){
		#ifdef debug
			printf("failed to load private key \n");			
		#endif
		return -1;
	}

	int pos, i;
	struct Cipher D;

	int m_pos =0;
	//call basic decryption algorithm dec to decrypt eack ciphertext block D
	//the decrypted message is appended to m
	for(i=0; i < group_size; i++){
		//convert a cipertext block in bytes into a data type struct Cipher
		cipher_in_str(c+i*single_clen, &pos, &D);

		if(pos!=single_clen){
			#ifdef debug
				printf("Error: something worng with cipher_in_str \n");		
			#endif
			*mlen = 0;
			return -1;
		}
		dec(sk, &D, m+i*T_BYTES);
		clearCipher(&D);
	}
	
	//decode m into m1 with the decode algrithm described in section 2.4.2 of the specification
	i = decode(m1, mlen, m, real_mlen);
	
	free(sk);
	free(m);
	return i;
}
