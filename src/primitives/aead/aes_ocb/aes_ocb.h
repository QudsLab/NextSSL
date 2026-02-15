#ifndef AES_OCB_H
#define AES_OCB_H

#include <stddef.h>
#include <stdint.h>

void AES_OCB_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* pntxt, const size_t ptextLen, void* crtxt);
char AES_OCB_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
