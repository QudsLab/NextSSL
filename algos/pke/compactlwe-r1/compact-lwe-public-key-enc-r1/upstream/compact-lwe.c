/**
 * \file
 *         Implmentation of Compact-LWE puiblic key encryption scheme developed in CSIRO
 *         09-11-2017
 *         Dongxi Liu <dongxi.liu@csiro.au>
 */

#include "compact-lwe.h"
#include "rng.h"
#include <stdio.h> 
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

//gnerate the private key sk
int sk_gen(struct SK* sk){


	int i, j, l;
	sk->n = N;
	sk->m = M;
	sk->t_bytes = T_BYTES;
	sk->q_bytes = Q_BYTES;

	mpz_init (sk->wPos);
	mpz_init (sk->wNeg);		
	mpz_init (sk->p);	
	mpz_init (sk->q);	
	mpz_init (sk->r);	
	mpz_init (sk->t);	
	mpz_init (sk->bv);

	for(j=0; j< F; j++){
		mpz_init (sk->kInv[j]);
     }

	mpz_init (sk->ckInv);
	mpz_set_ui(sk->wPos,W_POS);
	mpz_set_ui(sk->wNeg,W_NEG); 

	//init sk->bv with B, corresponding to b' in specification  
	mpz_set_str(sk->bv, B, 10); 

	//calculate q
   	mpz_set_ui(sk->q,1); 
	mpz_mul_2exp(sk->q, sk->q, sk->q_bytes*8); 	

	//calculate t
	mpz_set_ui(sk->t,1); 
	mpz_mul_2exp(sk->t, sk->t, sk->t_bytes*8); 	


   	mpz_t a, b, c, d, qDivW, peMax, sk_max, sckInv;
    mpz_init (a);
    mpz_init (b); 
	mpz_init (c);	
    mpz_init (d);
	mpz_init (qDivW);	
	mpz_init (peMax);
	mpz_init (sk_max);
	mpz_init (sckInv);


	randomMPZ(sk->q_bytes, a);
	mpz_set_str (c, pSIZE, 10);	
	mpz_mod(a, a, c);

        
	mpz_add(c, sk->wPos, sk->wNeg);
    mpz_mul(b, sk->bv, c);
    
	//p is W+W' plus a random number bounded by pSIZE	    
	mpz_add(sk->p, b, a);


    //ensure p is co-prime with q which is even
	mpz_mod_ui(d, sk->p, 2);
	if(mpz_get_ui(d)==0){ 
		mpz_add_ui(sk->p, sk->p, 1);
		if(mpz_cmp(sk->p,sk->q)>=0){
			mpz_sub_ui(sk->p, sk->p, 2);
		}
	}

    //a = W + W';
	mpz_add(a, sk->wPos, sk->wNeg);
    //qDivW = q/(W+W');
	mpz_fdiv_q (qDivW, sk->q, a);	 
    //qDivW = q/(W+W') - p; 
	mpz_sub(qDivW, qDivW, sk->p);

	//sk->r = e_max
	mpz_set_str(sk->r, eMax, 10);

	//peMax = e_Max*p
	mpz_mul(peMax, sk->p, sk->r);

    //ensure q/(W+W') - p > e_Max*p
	if(mpz_cmp(qDivW, peMax) <= 0){
		printf("Too big error: %s\n", eMax);
		return -1;
	}


	//(q/(W+W') - p - e_Max*p)/sk->bv = sk_max
    //ensuring the condition sk_max*b' + p + p*e_max < q/(W+W')  in specification
	mpz_sub(a, qDivW, peMax);
	mpz_fdiv_q(sk_max, a, sk->bv);	

	//generate k and k', which needs to be odd so as to be co-prime with q 
	for(j=0; j<F; j++){
		randomMPZ(sk->q_bytes, sk->k[j]);
		mpz_mod(sk->k[j], sk->k[j], sk->q);

		mpz_mod_ui(d, sk->k[j], 2);
		if(mpz_get_ui(d)==0){ 
			mpz_add_ui(sk->k[j], sk->k[j], 1);
		}

		mpz_invert(sk->kInv[j], sk->k[j],sk->q);
	}

	//generate s and s' in sepcification
	for(j=0; j<F; j++){
		for(i=1; i< sk->n; i++){	                
			randomMPZ(sk->q_bytes, sk->s[j][i]);
			mpz_mod(sk->s[j][i], sk->s[j][i], sk->q);
		}
	}

	//generate ck and ck', with ck' co-prime with p 
	for(j=0; j<F; j++){
		randomMPZ(sk->q_bytes, sk->ck[j]);
		mpz_mod(sk->ck[j], sk->ck[j], sk->p);

		if(j==F-1){
			
			mpz_invert(sk->ckInv, sk->ck[j], sk->p);
			mpz_mul(a, sk->ckInv, sk->ck[j]);
			mpz_mod(a, a, sk->p);

			if(mpz_get_ui(a)==1){
			}
			else{

				j--;
			}

		}
   }

	//generate sk, ensuring sk*ck + sk*ck' is co-prime with p 
	do{
		for(j=0; j<F; j++){
			randomMPZ(sk->q_bytes, sk->s[j][0]);  
			mpz_mod(sk->s[j][0], sk->s[j][0], sk_max);
		}

		mpz_set_ui(a, 0);		
		for(j=0; j<F; j++){
			mpz_mul(b, sk->s[j][0], sk->ck[j]);
			mpz_mod(b, b, sk->p);

			mpz_add(a, a, b);
			mpz_mod(a, a, sk->p);
		}

		mpz_invert(sckInv, a, sk->p);

		mpz_mul(b, sckInv, a);
		mpz_mod(b, b, sk->p);
		if(mpz_get_ui(b)==1)
			break;

	}while(1);


	//pre-calcuale the values of ck*sckInv and ck'*sckInv
	for(j=0; j<F; j++){
		mpz_mul(sk->ck[j], sk->ck[j], sckInv);
		mpz_mod(sk->ck[j], sk->ck[j], sk->p);
	}

	//pre-calcuate the multiplicate inverse of ck' mod p 
	mpz_invert(sk->ckInv, sk->ck[F-1], sk->p);


    mpz_clear (a);
    mpz_clear (b); 
	mpz_clear (c);	
    mpz_clear (d);
	mpz_clear (qDivW);	
	mpz_clear (peMax);
	mpz_clear (sk_max);
	
        
	return 0;
}

//generate the public key pk_str from the private key sk
int pk_gen(struct SK* sk, unsigned char *pk_str){


	struct PK pk1; 
	struct PK* pk = &pk1;   

	mpz_init (pk->q);	
	mpz_init (pk->t);
	mpz_init (pk->wPos);
	mpz_init (pk->wNeg);
	mpz_init (pk->bv);
	unsigned int i,j, l;
	for(j=0; j <F; j++){
		for(i=0; i < sk->m; i++)
			mpz_init (pk->element[j][i]);
	}

	

	mpz_add_ui (pk->wPos, sk->wPos, 0);
	mpz_add_ui (pk->wNeg, sk->wNeg, 0);
	mpz_add_ui (pk->bv, sk->bv, 0);

	pk->q_bytes = sk->q_bytes;
	pk->t_bytes = sk->t_bytes;
	
    mpz_set_ui(pk->q,1); 
	mpz_mul_2exp(pk->q, pk->q, pk->q_bytes*8); 

	
    mpz_set_ui(pk->t,1); 
	mpz_mul_2exp(pk->t, pk->t, pk->t_bytes*8); 

	pk->m = sk->m;
	pk->n = sk->n;

    mpz_t skInvQ, leftSum, a, b, e, pSum, pTemp, e_min;
    mpz_init (skInvQ);
    mpz_init (leftSum);
    mpz_init (a);
	mpz_init (b);
    mpz_init (e);
	mpz_init (pSum);
	mpz_init (pTemp);
	mpz_init (e_min);

	//sk->r = e_max
	//determine e_min by using the condition e_min*W > W'*e_max + W'	
	mpz_mul(a, sk->r, pk->wNeg);
	mpz_add(a, a, pk->wNeg);
	mpz_fdiv_q (e_min, a, pk->wPos);

	//printf("e_min: %s \n", mpz_get_str(NULL, 10, e_min));

	//ensure e_max > e_min
	if(mpz_cmp(sk->r, e_min)<=0){
		printf("Incorrect: e_min %s is bigger than e_max %s\n", mpz_get_str(NULL, 10, e_min), mpz_get_str(NULL, 10, sk->r));
		return -1;
	}	
	
	//sk->r = e_max - e_min
	mpz_sub(sk->r, sk->r, e_min);

	//generate m samples
	for(i=0; i < pk->m; i++){

		mpz_set_ui(pSum, 0);	
	    for(l=0; l<F; l++){
			if(l<F-1){
				//generate r_{i}
				randomMPZ(Q_BYTES, pTemp);
				mpz_mod(pTemp, pTemp, sk->p);

				mpz_mul(a, pTemp, sk->ck[l]);
				mpz_add(pSum, a, pSum);
				mpz_mod(pSum, pSum, sk->p);

			}
			else{
				//generate r_{i}', ensuring ck*r_{i} * ck'*r_{i}' = e*p for random e 
				randomMPZ(Q_BYTES, e);
				mpz_mod(e, e, sk->p);
				mpz_mul(e, e, sk->p);

				mpz_sub(e, e, pSum);
				mpz_mul(pTemp, sk->ckInv, e);
				mpz_mod(pTemp, pTemp, sk->p);

				#ifdef debug
					mpz_mul(a, sk->ck[l], pTemp);
					mpz_add(a, a, pSum);
					mpz_mod(a, a, sk->p);
					if(mpz_get_ui(a)!=0){			
						printf("Incorect: not zero \n");
						return -1;
					}
				#endif
			}


	        mpz_set_ui(leftSum, 0);
               
			//calculate <s, a_{i}> in the specification
			//elements of a_{i} is extracted from I and 4-bit long (i.e., parameter b is hard-coded)   	
			for(j=1; j<pk->n;j++){
				mpz_mul_ui(a, sk->s[l][j], (I[(i+j)%256]&0x0F));
				mpz_add(leftSum, leftSum, a);
				mpz_mod(leftSum, leftSum, sk->q);
			}

			
			if(i==0)
				mpz_set_ui(b, I[0]);
			else
				mpz_xor(b, pk->element[0][i-1], pk->element[1][i-1]);

			//value of u_{i}
			mpz_mod(b, b, pk->bv);

			//calculate sk*u_{i} + r_{i} or sk'*u_{i} + r_{i}' 
			mpz_mul(a, sk->s[l][0], b);
			mpz_add(b, a, pTemp);
			
			//generate e_{i} or e_{i}'
			randomMPZ(Q_BYTES, e);
			mpz_mod(e, e, sk->r);
			
			mpz_add(e, e, e_min);
						
			
			mpz_mul(a, sk->p, e);
			mpz_add(a, b, a);
			mpz_mul(a, sk->kInv[l], a);
			mpz_mod(a, a, sk->q);
			
			mpz_add(leftSum, leftSum, a);
			//generate pk or pk'
			mpz_mod(pk->element[l][i], leftSum, sk->q);

		} 

	}


    mpz_clear (skInvQ);
    mpz_clear (a);
	mpz_clear (b);
    mpz_clear (e);
	mpz_clear (pSum);
	mpz_clear (pTemp);
	mpz_clear (leftSum);
	mpz_clear (e_min);

	int len  = pk_out_str(pk, pk_str, CRYPTO_PUBLICKEYBYTES); 

	mpz_clear (pk->q);	
	mpz_clear (pk->t);
	mpz_clear (pk->wPos);
	mpz_clear (pk->wNeg);
	mpz_clear (pk->bv);
	for(j=0; j <F; j++){
		for(i=0; i < sk->m; i++)
			mpz_clear (pk->element[j][i]);
	}

	return len;


}

//release the memory used by each mpz_t field in the ciphertext D by calling mpz_clear
void clearCipher(struct Cipher* D){
	unsigned int i, j;
	for(j=0; j < F; j++)
		mpz_clear(D->tail[j]);
        for(i=0; i<N-1; i++){
		mpz_init(D->head[i]);
	}
}

//basic encryption algorithm; 
//encrypt plaintext block v of length T_BYTES with public key pk, generating the ciphertext block D
int enc(struct PK* pk, const unsigned char* v, struct Cipher* D){
        //mpz_mod(v, v, pk->t);

	unsigned int i,j;

	for(i=0; i<pk->n-1; i++){	
		mpz_init(D->head[i]);
		mpz_set_si(D->head[i], 0);
	}	
	for(j=0; j < F; j++){
		mpz_init(D->tail[j]);
		mpz_set_si(D->tail[j], 0);	
	}

	unsigned int sel, nsel;

	unsigned char buf[512];
	//generate all needed random numbers;  
	randombytes(buf, mpz_get_ui(pk->wPos)+mpz_get_ui(pk->wNeg)*2+2);

	//the sum of positive entries in l will be sel
    //the sum of negative entries in l will be -nsel
	if(mpz_get_ui(pk->wNeg)>0){
		sel = mpz_get_ui(pk->wPos)+(buf[0]%mpz_get_ui(pk->wNeg));	
		nsel = buf[1]%mpz_get_ui(pk->wNeg);
	}
	else{
		sel = mpz_get_ui(pk->wPos);	
		nsel = 0;
	}

    char* l=malloc(pk->m);
	
    mpz_t randV, a, b;
    mpz_init(randV);
	mpz_init(a);
	mpz_init(b);
	mpz_set_si(randV, 0);

	memset(l, 0x00, M);

	int posc = 0, negc=0;
	int count = nsel==0?sel:(sel/nsel+1);  
	//generate l 
	for(i=0; i<sel+nsel; i++){
		unsigned short slot = buf[i+2]%M;
		if(count>0&&posc<sel){
			while(l[slot]<0)  //move away from a negative entry	
				slot = (slot+1)%M;		
			l[slot] = l[slot] + 1; //one entry can be selected multiple times			
			count--;
			posc++;
		}
		else{
			while(l[slot]>0)	
				slot = (slot+1)%M; //move away from a positive entry		
			l[slot] = l[slot] - 1;			
			count = nsel==0?sel:(sel/nsel+1);
			negc++;
		}

  	}

	#ifdef debug
		printf("\n selection (%d, %d, %d): ", sel, posc, negc);
        	for(i=0; i<pk->m; i++){
			printf("l%u=%d, ", i, l[i]);
  		}
		printf("\n ");
	#endif

	//generate ciphertext D partially (i.e., D->head and D->tail[] generated)
	for(i=0; i<M; i++){		
		if(i==0)
			mpz_set_ui(b, I[0]);
		else
			mpz_xor(b, pk->element[0][i-1], pk->element[1][i-1]);

		mpz_mod(b, b, pk->bv);

		mpz_mul_si(b, b, l[i]);

		mpz_add(randV, randV, b);
	}

	//ensure the third condition on l
	while(mpz_sgn(randV)<0||mpz_sgn(randV)==0){
		for(i=0; i<M; i++){		
			if(l[i]<0){

				if(i==0)
					mpz_set_ui(b, I[0]);
				else
					mpz_xor(b, pk->element[0][i-1], pk->element[1][i-1]);

				mpz_mod(b, b, pk->bv);

				mpz_add(randV, randV, b);

				l[i] = l[i]+1;

				if(mpz_sgn(randV)>0)
					break;

			}		
		}		
	}

	for(i=0; i<M; i++){		
		for(j=0; j < F; j++){
			mpz_mul_si(b, pk->element[j][i], l[i]);
			mpz_add(D->tail[j], D->tail[j], b);
		}

		long elementV;

		for(j=1; j<pk->n; j++){			
			elementV=(I[(i+j)%256]&0x0f)*l[i];
			mpz_set_si(b, elementV);
	        	mpz_add(D->head[j-1], D->head[j-1], b);      	
		} 
		
	}

	

	for(j=0; j < F; j++)
		mpz_mod(D->tail[j], D->tail[j], pk->q);
	       

	unsigned long len;
	for(i=0; i < pk->t_bytes; i++){
		buf[i] = 0x00;				
	}

	mpz_mod(a, randV, pk->t);	
	mpz_fdiv_q (b, randV, pk->t);	

	//ensure b coprime with pk->t
	mpz_mod_ui(randV, b, 2);
	if(mpz_get_ui(randV)==0){
		mpz_add_ui(b, b, 1);
	}

	mpz_export (buf, &len, -1, 1, 1, 0, a);
	

	//generate the rest of ciphertext D
	for(i=0; i < pk->t_bytes; i++){
		D->cval[i] = buf[(i+pk->t_bytes/2)%pk->t_bytes]^v[i]; //circular shift of buf
	}


	mpz_import (a, pk->t_bytes, -1, 1, 1, 0,  D->cval);
	mpz_mul(randV, a, b);
	mpz_mod(a, randV, pk->t);

	
	for(i=0; i < pk->t_bytes; i++){
		D->cval[i] = 0x00;			
	}

	mpz_export (D->cval, &len, -1, 1, 1, 0, a);	

	mpz_clear(randV);
	mpz_clear(a);
	mpz_clear(b);


	free(l);
	return 1;
}

//basic decryption algorithm; 
//decrypt ciphertext block D into plaintext block v of length T_BYTES with the private key sk
int dec(struct SK* sk, struct Cipher* D, unsigned char* v){
	//printf("decryption \n"); 
	int i, j, l; 

	mpz_t leftsum[F], a, b, randV;
	for(i=0; i< F; i++){
		mpz_init(leftsum[i]);					
		mpz_set_ui(leftsum[i], 0);
	}

	mpz_init(a);
	mpz_init(b);
	mpz_init(randV);
	mpz_set_ui(randV, 0);

	//calcuate d1, d2, d3 in specification; d3 = randV
	for(l=0; l < F; l++){
		
		for(j=1;j < sk->n; j++){
			mpz_mul(a, sk->s[l][j], D->head[j-1]);
			mpz_mod(a, a, sk->q);
			mpz_add(leftsum[l], leftsum[l], a);
		}

		mpz_sub(leftsum[l], D->tail[l], leftsum[l]);
		mpz_mod(leftsum[l], leftsum[l], sk->q);		
		mpz_mul(leftsum[l], leftsum[l],sk->k[l]);
		mpz_mod(leftsum[l], leftsum[l], sk->q);
		mpz_mod(leftsum[l], leftsum[l], sk->p);
		mpz_mul(leftsum[l], leftsum[l],sk->ck[l]);
		mpz_mod(leftsum[l], leftsum[l], sk->p);
		
		
		mpz_add(randV, randV, leftsum[l]);
	
	}

	mpz_mod(randV, randV, sk->p);


	unsigned char buf[Q_BYTES];
	unsigned long len;
	for(i=0; i < sk->t_bytes; i++){
		buf[i] = 0x00;				
	}

	//the last step in specification
	mpz_mod(a, randV, sk->t);	
	mpz_fdiv_q (b, randV, sk->t);	
	mpz_mod_ui(randV, b, 2);
	if(mpz_get_ui(randV)==0){//ensure b coprime with sk->t
		mpz_add_ui(b, b, 1);
	}

	mpz_export (buf, &len, -1, 1, 1, 0, a);

   	mpz_import (a, sk->t_bytes, -1, 1, 1, 0,  D->cval);
	

	mpz_invert (b, b, sk->t);	

	mpz_mul(randV, a, b);
	mpz_mod(a, randV, sk->t);

	for(i=0; i < sk->t_bytes; i++){
		D->cval[i] = 0x00;			
	}
	mpz_export (D->cval, &len, -1, 1, 1, 0, a);	 

	for(i=0; i < sk->t_bytes; i++){
		v[i] = D->cval[i] ^ buf[(i+sk->t_bytes/2)%sk->t_bytes];

	}

	
    for(i=0; i< F; i++){
		mpz_clear(leftsum[i]);					
	}
    
	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(randV);

	return 1;
}

//convert the private key from a byte array (buf)
//to the data type struct SK
struct SK* sk_in_str(const unsigned char* buf, int buf_len){
	int i, pos=0, j, l;

	struct SK* sk = malloc(sizeof(struct SK)); 

        sk->m = buf[pos];
	pos++;
        sk->n = buf[pos];
	pos++;
	sk->t_bytes = buf[pos];
	pos++;
	sk->q_bytes = buf[pos];
	pos++;

	mpz_init (sk->wPos);
	mpz_init (sk->wNeg);		
	mpz_init (sk->p);	
	mpz_init (sk->q);	
        mpz_init (sk->r);	
        mpz_init (sk->t);
	mpz_init (sk->bv);	
	
	for(j=0; j< F; j++){
		mpz_init (sk->kInv[j]);
		mpz_init (sk->k[j]);
		mpz_init (sk->ck[j]);

		for(i=0; i< sk->n ; i++){
			mpz_init (sk->s[j][i]);
		}	
        }

	mpz_init (sk->ckInv);



        int len = sk->q_bytes+sk->q_bytes+ F*sk->q_bytes+sk->q_bytes+F*sk->n*sk->q_bytes+2*F*sk->q_bytes+ 2+2+1+1+1+1+sk->q_bytes; //224
	if(buf_len < len){
		printf("The buf for sk is too small: expected %d, actual %d\n", len, buf_len);	
		return NULL;
	}

	//convert each field in the private key
    mpz_set_ui(sk->q,1); 
	mpz_mul_2exp(sk->q, sk->q, sk->q_bytes*8); 	


	mpz_set_ui(sk->t,1); 
	mpz_mul_2exp(sk->t, sk->t, sk->t_bytes*8); 
	
	mpz_import (sk->wPos, 2, -1, 1, 1, 0, buf+pos); 
	pos = pos+2;

	mpz_import (sk->wNeg, 2, -1, 1, 1, 0, buf+pos); 
	pos = pos+2;

	mpz_import (sk->p, sk->q_bytes, -1, 1, 1, 0, buf+pos); 
	pos = pos+sk->q_bytes;

	mpz_import (sk->r, sk->q_bytes, -1, 1, 1, 0, buf+pos); 
	pos = pos+sk->q_bytes;

	for(j=0; j < F ; j++){
	      	mpz_import (sk->ck[j], sk->q_bytes, -1, 1, 1, 0, buf+pos); 
		pos = pos+sk->q_bytes;
	}

	mpz_import (sk->ckInv, sk->q_bytes, -1, 1, 1, 0, buf+pos); 
	pos = pos+sk->q_bytes;

	for(i=0; i< sk->n; i++){
		for(j=0; j < F ; j++){
	      		mpz_import (sk->s[j][i], sk->q_bytes, -1, 1, 1, 0,  buf+pos); 
			pos = pos+sk->q_bytes;
		}		
	}

	for(j=0; j < F ; j++){
	      	mpz_import (sk->k[j], sk->q_bytes, -1, 1, 1, 0,  buf+pos); 
		pos = pos+sk->q_bytes;
	}

	for(j=0; j < F ; j++){
	      	mpz_import (sk->kInv[j], sk->q_bytes, -1, 1, 1, 0, buf+pos); 
		pos = pos+sk->q_bytes;
	}
 

	mpz_import (sk->bv, sk->q_bytes, -1, 1, 1, 0, buf+pos); 
	pos = pos+sk->q_bytes;

	if(pos!=len){
		printf("Something wrong in sk input");
		return NULL;
	}

	return sk;

}

//convert the private key sk from the data type struct SK 
//to a byte array buf, returning its length
int sk_out_str(struct SK* sk, unsigned char* buf, int buf_len){
	int i, pos=0, j, l;

        int len = sk->q_bytes+sk->q_bytes+ F*sk->q_bytes+sk->q_bytes+F*N*sk->q_bytes+2*F*sk->q_bytes+ 2+2+1+1+1+1+sk->q_bytes; //224
	if(buf_len < len){
		printf("The buf for sk is too small: expected %d, actual %d\n", len, buf_len);	
		return -1;
	}

        buf[pos]  = sk->m;
	pos++;
        buf[pos]  = sk->n;
	pos++;
	buf[pos]  = sk->t_bytes;
	pos++;
	buf[pos]  = sk->q_bytes;
	pos++;
	
	size_t tempbuflen;
	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->wPos); 
	for(l=tempbuflen; l<2; l++){
			buf[pos+l]=0x00;
	}
	pos = pos+2;

	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->wNeg); 
	for(l=tempbuflen; l<2; l++){
			buf[pos+l]=0x00;
	}
	pos = pos+2;

	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->p); 
	for(l=tempbuflen; l<sk->q_bytes; l++){
		buf[pos+l]=0x00;
	}
	pos = pos+sk->q_bytes;

	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->r); 
	for(l=tempbuflen; l<sk->q_bytes; l++){
		buf[pos+l]=0x00;
	}
	pos = pos+sk->q_bytes;


	for(j=0; j < F ; j++){
	      	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->ck[j]); 
		for(l=tempbuflen; l<sk->q_bytes; l++){
			buf[pos+l]=0x00;
		}
		pos = pos+sk->q_bytes;
	}
	
	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->ckInv); 
	for(l=tempbuflen; l<sk->q_bytes; l++){
		buf[pos+l]=0x00;
	}
	pos = pos+sk->q_bytes;

	for(i=0; i< sk->n; i++){
		for(j=0; j < F ; j++){
	      		mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->s[j][i]); 
			for(l=tempbuflen; l<sk->q_bytes; l++){
				buf[pos+l]=0x00;
			}
			pos = pos+sk->q_bytes;
		}		
	}


	for(j=0; j < F ; j++){
	      	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->k[j]); 
		for(l=tempbuflen; l<sk->q_bytes; l++){
			buf[pos+l]=0x00;
		}
		pos = pos+sk->q_bytes;
	}

	for(j=0; j < F ; j++){
	      	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->kInv[j]); 
		for(l=tempbuflen; l<sk->q_bytes; l++){
			buf[pos+l]=0x00;
		}
		pos = pos+sk->q_bytes;
	}
 

	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, sk->bv); 
	for(l=tempbuflen; l<sk->q_bytes; l++){
		buf[pos+l]=0x00;
	}
	pos = pos+sk->q_bytes;

	if(pos!=len)
		printf("Something wrong in sk output");
	
	return pos;


}

//convert the public key pk from the data type struct PK 
//into a byte array buf, returning its length
int pk_out_str(struct PK* pk, unsigned char* buf, int buf_len){
	int i, pos=0, j, l;

        int len = pk->m*F*pk->q_bytes + 2+2+1+1+1+1+pk->q_bytes; 
	if(buf_len < len){
		printf("The buf for pk is too small: expected %d, actual %d\n", len, buf_len);	
		return -1;
	}

        buf[pos]  = pk->m;
	pos++;
        buf[pos]  = pk->n;
	pos++;
	buf[pos]  = pk->t_bytes;
	pos++;
	buf[pos]  = pk->q_bytes;
	pos++;
	
	size_t tempbuflen;
	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, pk->wPos); 
	for(l=tempbuflen; l<2; l++){
			buf[pos+l]=0x00;
	}
	pos = pos+2;

	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, pk->wNeg); 
	for(l=tempbuflen; l<2; l++){
			buf[pos+l]=0x00;
	}
	pos = pos+2;

	
	for(i=0; i< pk->m; i++){
		for(j=0; j < F ; j++){
	      		mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, pk->element[j][i]); 
			for(l=tempbuflen; l<pk->q_bytes; l++){
				buf[pos+l]=0x00;
			}
			pos = pos+pk->q_bytes;
		}		
	}


	mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, pk->bv); 
	for(l=tempbuflen; l<pk->q_bytes; l++){
		buf[pos+l]=0x00;
	}
	pos = pos+pk->q_bytes;
 

	if(pos!=len)
		printf("Something wrong in pk output");
	
	return pos;

}

//release the memory used by the fields of type mpz_t in the public key pk
void clearPK(struct PK* pk){
	mpz_clear (pk->q);	
	mpz_clear (pk->t);
	mpz_clear (pk->wPos);
	mpz_clear (pk->wNeg);
	mpz_clear (pk->bv);
	int i, pos=0, j, l;
	for(j=0; j <F; j++){
		for(i=0; i < M; i++)
			mpz_clear (pk->element[j][i]);
	}
}

//convert the public key from a byte array (buf)
//to the data type struct PK
struct PK* pk_in_str(const unsigned char *buf, int buf_len){

	struct PK* pk = malloc(sizeof(struct PK));   

	mpz_init (pk->q);	
	mpz_init (pk->t);
	mpz_init (pk->wPos);
	mpz_init (pk->wNeg);
	mpz_init (pk->bv);
	int i, pos=0, j, l;
	for(j=0; j <F; j++){
		for(i=0; i < M; i++)
			mpz_init (pk->element[j][i]);
	}

        pk->m = buf[pos];
	pos++;
        pk->n = buf[pos];
	pos++;
	pk->t_bytes = buf[pos];
	pos++;
	pk->q_bytes = buf[pos];
	pos++;


	int len = pk->m*F*pk->q_bytes + 2+2+1+1+1+1+pk->q_bytes; 
	if(buf_len < len){
		printf("The buf for pk is too small: expected %d, actual %d\n", len, buf_len);	
		return NULL;
	}

        mpz_set_ui(pk->q,1); 
	mpz_mul_2exp(pk->q, pk->q, pk->q_bytes*8); 

	
        mpz_set_ui(pk->t,1); 
	mpz_mul_2exp(pk->t, pk->t, pk->t_bytes*8); 

	mpz_import (pk->wPos, 2, -1, 1, 1, 0, buf+pos);  
	pos=pos+2;

	mpz_import (pk->wNeg, 2, -1, 1, 1, 0, buf+pos);  
	pos=pos+2;

	size_t tempbuflen;
	for(i=0; i< M; i++){
		for(j=0; j < F ; j++){
			mpz_import (pk->element[j][i], pk->q_bytes, -1, 1, 1, 0, buf+pos);
			pos = pos+pk->q_bytes;
		}		
	}
	
	mpz_import (pk->bv, pk->q_bytes, -1, 1, 1, 0, buf+pos); 
	pos = pos+pk->q_bytes;

	return pk;
	
}

//convert the ciphertext (D) from the data type struct Cipher 
//to a byte array (buf), returning its length
int cipher_out_str(struct Cipher* D, unsigned char* buf, int buf_len){
	int i, pos=0, j;

	for(i=0; i< N-1; i++){
		size_t tempbuflen;
      		mpz_export (buf+pos, &tempbuflen, 1, 1, 1, 0, D->head[i]); 
		if(tempbuflen==1){
			buf[pos+1]=buf[pos+0];
			buf[pos+0]=0x00;
		}
		pos=pos+2;

        }

	size_t tempbuflen;

	for(j=0; j < F ; j++){
	    mpz_export (buf+pos, &tempbuflen, -1, 1, 1, 0, D->tail[j]); 
		for(i=tempbuflen; i<(Q_BYTES); i++){
			buf[pos+i]=0x00;
		}
		pos = pos+Q_BYTES;
	}

	memcpy(buf+pos, D->cval, T_BYTES);  
	
	pos = pos + T_BYTES;
	return pos;
}


//convert the ciphertext from a byte array (buf)
//to the data type struct Cipher (D)
void cipher_in_str(const unsigned char* buf, int* last, struct Cipher* D){  

	int i, pos=0, j;
	for(j=0; j < F; j++)
		mpz_init(D->tail[j]);
        for(i=0; i<N; i++){
		mpz_init(D->head[i]);
	}

	for(i=0; i< N-1; i++){
      		mpz_import (D->head[i], 2, 1, 1, 1, 0, buf+pos);  
		pos=pos+2;
        }

	for(j=0; j < F; j++){
		mpz_import (D->tail[j], Q_BYTES, -1, 1, 1, 0, buf+pos);  
		pos=pos+Q_BYTES;
	}
	memcpy(D->cval, buf+pos, T_BYTES); 
	pos=pos+T_BYTES;

	*last = pos;
		
	return;
}

//calculate the multiplicative inverse of a with repsect to b
unsigned long mul_inv( long a, long b)
{
	long b0 = b, t, q;
	long x0 = 0, x1 = 1;
	if (b == 1) return 1;
	while (a > 1) {
		q = a / b;
		t = b, b = a % b, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0) x1 += b0;
	return (unsigned long) x1;
}


//generate the random number a of type mpz_t, which has the length of len bytes  
void randomMPZ(int len, mpz_t a){

	int l = sizeof(unsigned long), i;
	int count=0;
	
	mpz_init(a);

	unsigned long buf;
	while(count<len){
		randombytes((unsigned char*)&buf, l);

		if(len-count>=l){
			mpz_mul_2exp(a, a, 8*l);
			mpz_add_ui(a, a, buf);
			count = count + l;
		}
		else{
			mpz_mul_2exp(a, a, 8*(len-count));

			for(i=0; i < len-count; i++){
				unsigned long temp =0;
				temp = *((unsigned char*)buf+i);
				temp = temp << (i*8);
				mpz_add_ui(a, a, temp);
			}
			
		}

		
	}

	return;
}

//implement the encode algorithm described in Section 2.3.2 of the specification;
//buf is encoded into res
int encode(const unsigned char* buf, unsigned long long buf_len, unsigned char* res, unsigned long long res_len){

	if(buf_len+3>res_len)
		return -1;
	
	unsigned char extra = 0;

	if((buf_len+L+3)%T_BYTES!=0)
		extra = T_BYTES - ((buf_len+L+3)%T_BYTES);


	if(extra==0xff)
		return -1;

	unsigned long i, l=res_len-2;

	unsigned char x, or, y;
	unsigned short r;

		randombytes((unsigned char*)&r, 2);
		res[res_len-2] = *((unsigned char*)&r+0); //r0
		res[res_len-1] = *((unsigned char*)&r+1); //r1

		#ifdef debug
                	printf("r1= 0x%02x \n", res[res_len-1]);
			printf("r0= 0x%02x \n", res[res_len-2]);
		#endif

		or=res[res_len-2];
		x = I[or];
	        for(i=0; i < l; i++){
			if(i<buf_len)
				res[i] = buf[i]^x;
			else if(i==buf_len)
				res[i] = 0xFF^x;
			else
				res[i] = (L+extra)^x; 
			x= x^I[(res[i]+or)%256];
			res[res_len-2] = res[res_len-2]^((res[i]*res[res_len-1])%256); 
		}
	

		or = res[res_len-1];
		x = I[or];
	        for(i=0; i < l; i++){
			res[l-i-1] = res[l-i-1]^x; 
			x = x^I[(res[l-i-1]+or)%256]; 
			res[res_len-1] = res[res_len-1]^((res[l-i-1]*res[res_len-2])%256);
		}

	return 0;
}


//implement the decode algorithm described in Section 2.4.2 of the specification;
//res is decoded into buf
int decode(unsigned char* buf, unsigned long long *buf_len, const unsigned char* res, unsigned long long res_len){

	unsigned long i, k;

	unsigned char r0, r1;
	unsigned char x, y;

	 
	unsigned long l=res_len-2; 

	r1 = res[res_len-1];
	r0 = res[res_len-2];

	for(i=0; i<l; i++){
		k = l-1-i;
		r1 = r1^((res[k]*r0)%256);
	}
	
	#ifdef debug
		printf("r1= 0x%02x \n", r1);
	#endif		

	x = I[r1];	
	for(i=0; i<l; i++){
		k = l-1-i;
		y=res[k];
		buf[k] = res[k]^x; 
		x = x^I[(y+r1)%256];
	}

	for(i=0; i<l; i++){
		r0 = r0^((buf[i]*r1)%256);
	}	
	#ifdef debug
		printf("r0= 0x%02x \n", r0);
	#endif

	x = I[r0];
	for(i=0; i<l; i++){
		k =i;
		y = buf [k];
		buf[k] = buf [k]^x; 
		x = x^I[(y+r0)%256];	
	}

	int temp=0;
	unsigned char extra = buf[l-0-1];


	if(extra==0xFF){
		if(L!=0){
			#ifdef debug
				printf("Error: zero L from decoding not expected\n");
			#endif
			*buf_len = 0;
			return -1;
		}
		else{
			*buf_len = l-1;
			return 0;
		}
	}

	for(i=0; i<l; i++){
		if(buf[l-i-1]==extra){
			temp++;
			continue;
		}
		
		if(buf[l-i-1]==0xFF){
			temp++;
			break;
		}
		else{
			#ifdef debug
				printf("Error: no 0xFF found \n");
			#endif
			*buf_len = 0;		
			return -1;
		}				
	}

	if( i==l){
		#ifdef debug
			printf("Error: no 0xFF found \n");
		#endif
		*buf_len = 0;		
		return -1;
	}

	if(temp!=extra+1){
		#ifdef debug
			printf("Error: L from decoding not expected\n");
		#endif
		*buf_len = 0;
		return -1;
	}

	*buf_len = l - temp;

	return 0;
}


