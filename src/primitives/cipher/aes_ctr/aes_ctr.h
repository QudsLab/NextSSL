#ifndef AES_CTR_H
#define AES_CTR_H

#include <stddef.h>
#include <stdint.h>
#include "../../cipher/aes_core/aes_internal.h" /* For block_t */

enum ctr_based_modes
{
    CTR_DEFAULT,
    SIV_CTR    = 5,
    SIVGCM_CTR = 8,
    CCM_GCM    = 2
};

void AES_CTR_encrypt(const uint8_t* key, const uint8_t* iv, const void* pntxt, const size_t ptextLen, void* crtxt);
void AES_CTR_decrypt(const uint8_t* key, const uint8_t* iv, const void* crtxt, const size_t crtxtLen, void* pntxt);

/* Internal shared for GCM/CCM/SIV */
void CTR_cipher(const block_t iCtr, const char mode, const void* input, const size_t dataSize, void* output);

#endif
