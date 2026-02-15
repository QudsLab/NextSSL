#ifndef AES_OFB_H
#define AES_OFB_H

#include <stddef.h>
#include <stdint.h>
#include "../../cipher/aes_core/aes_internal.h"

void AES_OFB_encrypt(const uint8_t* key, const block_t iVec, const void* pntxt, const size_t ptextLen, void* crtxt);
void AES_OFB_decrypt(const uint8_t* key, const block_t iVec, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
