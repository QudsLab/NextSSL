#include <stdio.h>
#include <stdint.h>
#include "aes_common.h"
#include "aes_ecb.h"
#include "aes_cbc.h"
#include "aes_ctr.h"
#include "aes_gcm.h"
#include "aes_ccm.h"
#include "aes_ocb.h"
#include "aes_eax.h"
#include "aes_siv.h"
#include "aes_gcm_siv.h"
#include "aes_xts.h"
#include "aes_kw.h"
#include "aes_fpe.h"
#include "aes_cmac.h"
#include "aes_poly1305.h"

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
