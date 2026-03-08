/**
 * @file balloon.h
 * @brief Layer 2 (Core) - Balloon Hashing Interface
 * @visibility HIDDEN (NEXTSSL_CORE_API)
 * @layer 2
 * @category pow
 * @subcategory balloon
 * Thread safety: Thread-safe.
 */

#ifndef NEXTSSL_CORE_PRIMITIVE_SLOW_BALLOON_H
#define NEXTSSL_CORE_PRIMITIVE_SLOW_BALLOON_H

#include <stddef.h>
#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

NEXTSSL_CORE_API int
nextssl_partial_pow_balloon(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *salt,
    size_t salt_len,
    uint64_t space_cost,
    uint32_t time_cost,
    uint8_t *output,
    size_t output_len
);

NEXTSSL_CORE_API int
nextssl_partial_pow_balloon_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_CORE_PRIMITIVE_SLOW_BALLOON_H */