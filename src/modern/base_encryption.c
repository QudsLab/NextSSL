#include <stdio.h>
#include <stdint.h>
#include "aes_common.h"
#include "symmetric/aes_ecb.h"
#include "symmetric/aes_cbc.h"
#include "symmetric/aes_ctr.h"
#include "aead/aes_gcm.h"
#include "aead/aes_ccm.h"
#include "aead/aes_ocb.h"
#include "aead/aes_eax.h"
#include "aead/aes_siv.h"
#include "aead/aes_gcm_siv.h"
#include "symmetric/aes_xts.h"
#include "symmetric/aes_kw.h"
#include "symmetric/aes_fpe.h"
#include "mac/aes_cmac.h"
#include "aead/aes_poly1305.h"

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
