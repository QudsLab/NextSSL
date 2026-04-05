#ifndef AES_FPE_H
#define AES_FPE_H

#include <stddef.h>
#include <stdint.h>

/* Tweak params macros need to be defined or handled. 
   Original code used TWEAK_PARAMS macro.
   I will expand it for clarity or define it if needed for FF1/FF3 selection. 
   Assuming standard FF1 by default unless FF_X is defined externally. */

#ifndef FF_X
#define FF_X 1 /* Default to FF1 */
#endif

#if FF_X == 3
#define TWEAK_PARAMS_DEF   uint8_t* tweak
#else
#define TWEAK_PARAMS_DEF   uint8_t* tweak, const size_t tweakLen
#endif

char AES_FPE_encrypt(const uint8_t* key, const TWEAK_PARAMS_DEF, const void* pntxt, const size_t ptextLen, void* crtxt);
char AES_FPE_decrypt(const uint8_t* key, const TWEAK_PARAMS_DEF, const void* crtxt, const size_t crtxtLen, void* pntxt);

#endif
