#ifndef NEXTSSL_INTERFACES_UTILS_PROFILE_VERIFY_H
#define NEXTSSL_INTERFACES_UTILS_PROFILE_VERIFY_H

/*
 * profile_verify.h — Profile validation utility (Task 105)
 *
 * Validates that a runtime config struct is consistent with a compiled
 * profile's algorithm requirements. Called at library init-time in
 * production builds to catch misconfiguration early.
 */

#include <stdint.h>
#include "../config/config.h"

/**
 * nextssl_profile_verify — validate config against a profile.
 *
 * @config   Pointer to a populated nextssl_config_t.
 * @profile  The target profile to validate against.
 *
 * @return  0  all requirements satisfied.
 *          -1 config is NULL.
 *          -2 algorithm selection does not meet profile requirements.
 *          -3 key-size or parameter out of range for profile.
 */
int nextssl_profile_verify(const nextssl_config_t   *config,
                           nextssl_profile_t          profile);

#endif /* NEXTSSL_INTERFACES_UTILS_PROFILE_VERIFY_H */
