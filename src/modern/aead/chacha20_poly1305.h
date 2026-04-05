#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stddef.h>
#include <stdint.h>

void ChaCha20_Poly1305_encrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* pntxt, const size_t ptextLen, void* crtxt);
char ChaCha20_Poly1305_decrypt(const uint8_t* key, const uint8_t* nonce, const void* aData, const size_t aDataLen, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
