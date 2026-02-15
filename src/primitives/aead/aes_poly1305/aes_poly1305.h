#ifndef AES_POLY1305_H
#define AES_POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include "../../cipher/aes_core/aes_internal.h"

void AES_Poly1305(const uint8_t* keys, const block_t nonce, const void* data, const size_t dataSize, block_t mac);

#endif
