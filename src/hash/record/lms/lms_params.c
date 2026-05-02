/* lms_params.c — LMS / LM-OTS parameter tables (SP 800-208) */
#include "lms_params.h"
#include <stddef.h>

/* LM-OTS: p values computed per RFC 8554 §4.1
 *   n=32, w=1 → p=265, ls=7
 *   n=32, w=2 → p=133, ls=6
 *   n=32, w=4 → p=67,  ls=4
 *   n=32, w=8 → p=34,  ls=0
 */
static const lmots_params_t LMOTS_TABLE[] = {
    { LMOTS_SHA256_N32_W1, 32, 1, 265, 7 },
    { LMOTS_SHA256_N32_W2, 32, 2, 133, 6 },
    { LMOTS_SHA256_N32_W4, 32, 4,  67, 4 },
    { LMOTS_SHA256_N32_W8, 32, 8,  34, 0 }
};
#define LMOTS_TABLE_LEN (sizeof(LMOTS_TABLE) / sizeof(LMOTS_TABLE[0]))

static const lms_params_t LMS_TABLE[] = {
    { LMS_SHA256_M32_H5,  32,  5 },
    { LMS_SHA256_M32_H10, 32, 10 },
    { LMS_SHA256_M32_H15, 32, 15 },
    { LMS_SHA256_M32_H20, 32, 20 },
    { LMS_SHA256_M32_H25, 32, 25 }
};
#define LMS_TABLE_LEN (sizeof(LMS_TABLE) / sizeof(LMS_TABLE[0]))

const lmots_params_t *lmots_params_get(lmots_type_t type)
{
    for (size_t i = 0; i < LMOTS_TABLE_LEN; i++)
        if (LMOTS_TABLE[i].type == type) return &LMOTS_TABLE[i];
    return NULL;
}

const lms_params_t *lms_params_get(lms_type_t type)
{
    for (size_t i = 0; i < LMS_TABLE_LEN; i++)
        if (LMS_TABLE[i].type == type) return &LMS_TABLE[i];
    return NULL;
}
