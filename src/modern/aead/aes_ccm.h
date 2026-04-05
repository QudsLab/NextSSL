#ifndef AES_CCM_H
#define AES_CCM_H

#include <stddef.h>
#include <stdint.h>

void AES_CCM_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* pntxt, const size_t ptextLen, void* crtxt);
char AES_CCM_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
