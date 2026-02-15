#ifndef AES_GCM_H
#define AES_GCM_H

#include <stddef.h>
#include <stdint.h>

void AES_GCM_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* pntxt, const size_t ptextLen, void* crtxt);
char AES_GCM_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
