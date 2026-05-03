#ifndef AES_EAX_H
#define AES_EAX_H

#include <stddef.h>
#include <stdint.h>

/* EAX Prime support via macro or separate function? 
   Original code used #if EAXP. 
   I will provide standard EAX here. EAX' can be a separate file if needed or integrated.
   For now, standard EAX. */

void AES_EAX_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* pntxt, const size_t ptextLen, void* crtxt);
char AES_EAX_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
