/* udbf.h — Test Vector Override System (TIER 3)
 *
 * User-Defined Byte Feed (UDBF) allows injecting known-answer test (KAT) vectors
 * into the seed system for testing purposes. When active, seed_hash_derive()
 * returns UDBF-provided values instead of performing normal derivation.
 *
 * WARNING: This is test-mode only. Do NOT use in production.
 *
 * API (Plan 404):
 *   udbf_feed()         — load test vector data
 *   udbf_read()         — extract labeled output
 *   seed_udbf_is_active() — check if active (used by seed_core)
 *   udbf_wipe()         — clear and reset
 */
#ifndef SEED_UDBF_H
#define SEED_UDBF_H

#include <stdint.h>
#include <stddef.h>
#include "udbf_errors.h"

/* -------------------------------------------------------------------------
 * udbf_feed — Load test vector data into UDBF
 * -------------------------------------------------------------------------
 * Loads raw UDBF data (binary format with label-based entries).
 *
 * Format: [uint32_le:total_len][entries...]
 * Each entry: [uint8:label_len][label_bytes...][uint32_le:value_len][value_bytes...]
 *
 * Args:
 *   data — UDBF binary data
 *   len  — length of data (must be > 0 and <= 1 MB)
 *
 * Returns:
 *   UDBF_OK on success, UDBF_ERR_* on error
 *
 * Notes:
 *   - Can only load once; subsequent calls return UDBF_ERR_ALREADY_LOADED
 *   - Call udbf_wipe() to reset and allow reloading
 */
int udbf_feed(const uint8_t *data, size_t len);

/* -------------------------------------------------------------------------
 * udbf_read — Extract labeled output from UDBF
 * -------------------------------------------------------------------------
 * Retrieves the bytes stored under a given label.
 *
 * Args:
 *   label — label string (e.g., "aes-256-cbc-account-7")
 *   out   — caller-allocated output buffer, at least olen bytes
 *   olen  — number of bytes requested (must be > 0)
 *
 * Returns:
 *   (int)olen on success, UDBF_ERR_* on error
 *
 * Notes:
 *   - Returns UDBF_ERR_LABEL_NOT_FOUND if label absent
 *   - Returns UDBF_ERR_TOO_LARGE if stored value is shorter than olen
 */
int udbf_read(const char *label, uint8_t *out, size_t olen);

/* -------------------------------------------------------------------------
 * seed_udbf_is_active — Check if UDBF is currently loaded
 * -------------------------------------------------------------------------
 * Used by seed_core before performing normal derivation.
 *
 * Returns:
 *   1 — UDBF loaded; seed_hash_derive() will use udbf_read() instead
 *   0 — Not active; normal CTR-mode derivation proceeds
 */
int seed_udbf_is_active(void);

/* -------------------------------------------------------------------------
 * udbf_wipe — Clear UDBF and reset to inactive state
 * -------------------------------------------------------------------------
 * Securely erases stored UDBF data, frees memory, and allows udbf_feed()
 * to be called again.
 */
void udbf_wipe(void);

/* Compatibility alias — PQC randombytes.c uses the short name */
#define udbf_is_active() seed_udbf_is_active()

#endif /* SEED_UDBF_H */
