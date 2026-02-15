#include "argon2i.h"
#include "../utils/argon2.h"

int argon2i_hash_encoded(const uint32_t t_cost, const uint32_t m_cost,
                         const uint32_t parallelism, const void *pwd,
                         const size_t pwdlen, const void *salt,
                         const size_t saltlen, const size_t hashlen,
                         char *encoded, const size_t encodedlen) {

    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                       NULL, hashlen, encoded, encodedlen, Argon2_i,
                       ARGON2_VERSION_NUMBER);
}

int argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                     const uint32_t parallelism, const void *pwd,
                     const size_t pwdlen, const void *salt,
                     const size_t saltlen, void *hash, const size_t hashlen) {

    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                       hash, hashlen, NULL, 0, Argon2_i, ARGON2_VERSION_NUMBER);
}

int argon2i_verify(const char *encoded, const void *pwd, const size_t pwdlen) {
    return argon2_verify(encoded, pwd, pwdlen, Argon2_i);
}
