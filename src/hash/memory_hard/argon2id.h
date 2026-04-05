#ifndef ARGON2ID_H
#define ARGON2ID_H

#include <stddef.h>
#include <stdint.h>

int argon2id_hash_encoded(const uint32_t t_cost, const uint32_t m_cost,
                          const uint32_t parallelism, const void *pwd,
                          const size_t pwdlen, const void *salt,
                          const size_t saltlen, const size_t hashlen,
                          char *encoded, const size_t encodedlen);

int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                      const uint32_t parallelism, const void *pwd,
                      const size_t pwdlen, const void *salt,
                      const size_t saltlen, void *hash, const size_t hashlen);

int argon2id_verify(const char *encoded, const void *pwd, const size_t pwdlen);

#endif
