#ifndef NEXTSSL_INTERFACES_UTILS_PARAM_CHECK_H
#define NEXTSSL_INTERFACES_UTILS_PARAM_CHECK_H

/*
 * param_check.h — API boundary parameter validators (Task 105)
 *
 * Inline helpers for validating pointers, buffer lengths, and key sizes
 * at public API entry-points. Use at system boundaries only — not for
 * internal trusted-code paths.
 *
 * All functions return 0 (valid) or -1 (invalid).
 */

#include <stddef.h>
#include <stdint.h>

/**
 * param_check_buffer — verify a (buf, len) pair is non-NULL and in range.
 *
 * @buf  Pointer to check (non-NULL required).
 * @len  Actual length.
 * @min  Minimum allowed length (inclusive).
 * @max  Maximum allowed length (inclusive, 0 = no ceiling).
 *
 * @return 0 if valid, -1 if invalid.
 */
static inline int param_check_buffer(const void *buf, size_t len,
                                     size_t min,  size_t max)
{
    if (!buf) return -1;
    if (len < min) return -1;
    if (max > 0 && len > max) return -1;
    return 0;
}

/**
 * param_check_key — verify a key pointer is non-NULL and exactly the
 * expected length.
 *
 * @key           Key buffer pointer.
 * @actual_len    Actual key buffer length.
 * @expected_len  Required exact length.
 *
 * @return 0 if valid, -1 if invalid.
 */
static inline int param_check_key(const uint8_t *key,
                                  size_t actual_len,
                                  size_t expected_len)
{
    if (!key) return -1;
    if (actual_len != expected_len) return -1;
    return 0;
}

#endif /* NEXTSSL_INTERFACES_UTILS_PARAM_CHECK_H */
