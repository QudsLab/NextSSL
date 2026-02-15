#ifndef AES_COMMON_H
#define AES_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Constants */
#define AES___     128     /* Default to AES-128 (matches original micro-AES default) */

#if AES___ != 256 && AES___ != 192
#define AES_KEYLENGTH    16
#else
#define AES_KEYLENGTH    (AES___ / 8)
#endif

/* Error Codes */
enum function_result_codes
{
    M_ENCRYPTION_ERROR     = 0x1E,
    M_DECRYPTION_ERROR     = 0x1D,
    M_AUTHENTICATION_ERROR = 0x1A,
    M_DATALENGTH_ERROR     = 0x1L,
    M_RESULT_SUCCESS       = 0
};

#endif /* AES_COMMON_H */
