#ifndef AES_ECB_H
#define AES_ECB_H

#include <stddef.h>
#include <stdint.h>

void AES_ECB_encrypt(const uint8_t* key, const void* pntxt, const size_t ptextLen, void* crtxt);
char AES_ECB_decrypt(const uint8_t* key, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
