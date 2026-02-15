#include <stdio.h>
#include "primitives/hash/memory_hard/utils/argon2.h"
#include "primitives/hash/memory_hard/Argon2d/argon2d.h"
#include "primitives/hash/memory_hard/Argon2i/argon2i.h"
#include "primitives/hash/memory_hard/Argon2id/argon2id.h"

/* 
 * Advanced Hash Exporter (Argon2)
 * This file serves as the root entry point for Advanced Hashing algorithms.
 * It includes all the modularized headers for Argon2 variants.
 */

void ahs_argon_info(void) {
    printf("Advanced Hash Module (Argon2) Initialized.\n");
    printf("Supported Variants: Argon2d, Argon2i, Argon2id.\n");
    printf("Core Version: 0x%x\n", ARGON2_VERSION_NUMBER);
}
