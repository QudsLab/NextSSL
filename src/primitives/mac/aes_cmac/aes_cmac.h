#ifndef AES_CMAC_H
#define AES_CMAC_H

#include <stddef.h>
#include <stdint.h>
#include "../../cipher/aes_core/aes_internal.h"

void AES_CMAC(const uint8_t* key, const void* data, const size_t dataSize, block_t mac);

#endif
