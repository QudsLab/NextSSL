#ifndef AES_CFB_H
#define AES_CFB_H

#include <stddef.h>
#include <stdint.h>
#include "../../cipher/aes_core/aes_internal.h"

void AES_CFB_encrypt(const uint8_t* key, const block_t iVec, const void* pntxt, const size_t ptextLen, void* crtxt);
void AES_CFB_decrypt(const uint8_t* key, const block_t iVec, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
