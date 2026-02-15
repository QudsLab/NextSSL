#include <stdio.h>
#include <stdint.h>
#include "primitives/cipher/aes_core/aes_common.h"
#include "legacy/alive/aes_ecb/aes_ecb.h"
#include "primitives/cipher/aes_cbc/aes_cbc.h"
#include "primitives/cipher/aes_ctr/aes_ctr.h"
#include "primitives/aead/AES_GCM/aes_gcm.h"
#include "primitives/aead/AES_CCM/aes_ccm.h"
#include "primitives/aead/AES_OCB/aes_ocb.h"
#include "primitives/aead/AES_EAX/aes_eax.h"
#include "primitives/aead/AES_SIV/aes_siv.h"
#include "primitives/aead/AES_GCM_SIV/aes_gcm_siv.h"
#include "primitives/cipher/aes_xts/aes_xts.h"
#include "primitives/cipher/aes_kw/aes_kw.h"
#include "primitives/cipher/aes_fpe/aes_fpe.h"
#include "primitives/mac/aes_cmac/aes_cmac.h"
#include "primitives/aead/AES_Poly1305/aes_poly1305.h"

/* 
 * Base Encryption Exporter
 * This file serves as the root entry point for Base Encryption algorithms.
 * It includes all the modularized headers for AES modes.
 */

void base_encryption_info(void) {
    printf("Base Encryption Module Initialized.\n");
    printf("Supported Modes: ECB, CBC, CTR, GCM, CCM, OCB, EAX, SIV, GCM-SIV, XTS, KW, FPE, CMAC, Poly1305.\n");
    printf("Default AES Key Size: %d bits\n", AES___);
}
