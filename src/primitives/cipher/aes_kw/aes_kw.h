#ifndef AES_KW_H
#define AES_KW_H

#include <stddef.h>
#include <stdint.h>

char AES_KEY_wrap(const uint8_t* kek, const void* secret, const size_t secretLen, void* wrapped);
char AES_KEY_unwrap(const uint8_t* kek, const void* wrapped, const size_t wrapLen, void* secret);

#endif
