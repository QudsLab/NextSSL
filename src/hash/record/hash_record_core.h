#ifndef HASH_RECORD_CORE_H
#define HASH_RECORD_CORE_H

#include <stddef.h>
#include <stdint.h>
#include "../generic/nextssl_hash.h"

int nextssl_record_format_plain_internal(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    char          *record_out,
    size_t         record_cap,
    size_t        *record_len);

int nextssl_record_verify_plain_internal(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    const char    *record,
    int           *out_match);

int nextssl_record_format_kdf_internal(
    const char                *algo,
    const uint8_t             *data,
    size_t                     data_len,
    const nextssl_hash_config_t *config,
    char                      *record_out,
    size_t                     record_cap,
    size_t                    *record_len);

int nextssl_record_verify_kdf_internal(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    const char    *record,
    int           *out_match);

#endif
