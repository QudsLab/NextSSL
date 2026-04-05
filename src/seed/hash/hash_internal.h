/* hash_internal.h — Internal Constants for TIER 2 Seed System
 *
 * Private constants and utilities for seed derivation.
 */
#ifndef SEED_HASH_INTERNAL_H
#define SEED_HASH_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/* -------------------------------------------------------------------------
 * Internal CTR-mode constants
 * -------------------------------------------------------------------------*/

/* CTR mode flag — indicates using counter-based expansion */
#define SEED_CTR_MODE  1

/* Maximum output length supported by CTR mode (1 MB) */
#define SEED_MAX_OUTPUT_LEN    (1u << 20)

/* Maximum context label length (256 bytes) */
#define SEED_MAX_LABEL_LEN     256

/* Default counter starting value */
#define SEED_CTR_START         1

/* Counter size in bytes (32-bit big-endian) */
#define SEED_CTR_SIZE          4

#endif /* SEED_HASH_INTERNAL_H */
