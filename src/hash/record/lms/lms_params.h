/* lms_params.h — LMS / LM-OTS parameter set definitions (SP 800-208)
 *
 * LMS (Leighton-Micali Signatures) is a stateful hash-based signature scheme.
 *
 * WARNING — STATEFUL SCHEME:
 *   Each LMS private key can sign at most 2^h messages (where h is the tree
 *   height).  Reusing a one-time signature (OTS) key index COMPLETELY
 *   BREAKS SECURITY.  The caller MUST persist the current leaf index and
 *   MUST NOT clone or roll back the private key state.
 */
#ifndef NEXTSSL_LMS_PARAMS_H
#define NEXTSSL_LMS_PARAMS_H

#include <stdint.h>
#include <stddef.h>

/* ── LM-OTS typecodes (RFC 8554 §4.1) ─────────────────────────────────── */
typedef enum {
    LMOTS_SHA256_N32_W1 = 1,
    LMOTS_SHA256_N32_W2 = 2,
    LMOTS_SHA256_N32_W4 = 3,
    LMOTS_SHA256_N32_W8 = 4
} lmots_type_t;

/* ── LMS typecodes (RFC 8554 §5.1) ─────────────────────────────────────── */
typedef enum {
    LMS_SHA256_M32_H5  = 5,
    LMS_SHA256_M32_H10 = 6,
    LMS_SHA256_M32_H15 = 7,
    LMS_SHA256_M32_H20 = 8,
    LMS_SHA256_M32_H25 = 9
} lms_type_t;

/* ── LM-OTS parameter set ──────────────────────────────────────────────── */
typedef struct {
    lmots_type_t type;
    uint32_t     n;      /* hash output length in bytes (32 for SHA-256) */
    uint32_t     w;      /* Winternitz window width (1, 2, 4, or 8) */
    uint32_t     p;      /* number of n-byte hash chains */
    uint32_t     ls;     /* left-shift for checksum */
} lmots_params_t;

/* ── LMS parameter set ─────────────────────────────────────────────────── */
typedef struct {
    lms_type_t   type;
    uint32_t     m;      /* hash output length in bytes (32 for SHA-256) */
    uint32_t     h;      /* tree height */
} lms_params_t;

/* Look up LM-OTS parameters.  Returns NULL on unknown type. */
const lmots_params_t *lmots_params_get(lmots_type_t type);

/* Look up LMS parameters.  Returns NULL on unknown type. */
const lms_params_t   *lms_params_get(lms_type_t type);

#endif /* NEXTSSL_LMS_PARAMS_H */
