#ifndef AES_XTS_H
#define AES_XTS_H

#include <stddef.h>
#include <stdint.h>

char AES_XTS_encrypt(const uint8_t* keys, const uint8_t* tweak, const void* pntxt, const size_t ptextLen, void* crtxt);
char AES_XTS_decrypt(const uint8_t* keys, const uint8_t* tweak, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
