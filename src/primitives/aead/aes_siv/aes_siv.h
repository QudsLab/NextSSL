#ifndef AES_SIV_H
#define AES_SIV_H

#include <stddef.h>
#include <stdint.h>
#include "../../cipher/aes_core/aes_internal.h"

void AES_SIV_encrypt(const uint8_t* keys, const void* aData, const size_t aDataLen, const void* pntxt, const size_t ptextLen, block_t iv, void* crtxt);
char AES_SIV_decrypt(const uint8_t* keys, const block_t iv, const void* aData, const size_t aDataLen, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
