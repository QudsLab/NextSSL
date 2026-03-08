/**
 * @file profiles.h
 * @brief Profile definitions for NextSSL
 * 
 * Profiles map user intent to safe algorithm combinations.
 * Each profile is immutable and auditable.
 * 
 * @version 0.0.1-beta
 * @date 2026-02-28
 */

#ifndef NEXTSSL_PROFILES_H
#define NEXTSSL_PROFILES_H

#include "../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Load profile configuration into config structure
 * 
 * @param profile Profile to load
 * @param config Config structure to populate
 * @return 0 on success, negative on error
 */
int nextssl_profile_load(nextssl_profile_t profile, nextssl_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_PROFILES_H */
