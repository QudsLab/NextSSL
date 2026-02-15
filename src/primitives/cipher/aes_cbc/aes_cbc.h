#ifndef AES_CBC_H
#define AES_CBC_H

#include <stddef.h>
#include <stdint.h>

char AES_CBC_encrypt(const uint8_t* key, const uint8_t iVec[16], const void* pntxt, const size_t ptextLen, void* crtxt);
char AES_CBC_decrypt(const uint8_t* key, const uint8_t iVec[16], const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
