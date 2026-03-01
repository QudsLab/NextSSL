#ifndef nextssl_PRIMITIVE_MEMORY_HARD_H
#define nextssl_PRIMITIVE_MEMORY_HARD_H

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Argon2 Parameters
typedef struct {
    uint32_t t_cost;
    uint32_t m_cost_kb;
    uint32_t parallelism;
} LeylineArgon2Params;

// --- Argon2 Family ---
EXPORT int nextssl_argon2id(const uint8_t *pwd, size_t pwd_len, 
                            const uint8_t *salt, size_t salt_len,
                            const LeylineArgon2Params *params,
                            uint8_t *out, size_t out_len);

EXPORT int nextssl_argon2i(const uint8_t *pwd, size_t pwd_len, 
                           const uint8_t *salt, size_t salt_len,
                           const LeylineArgon2Params *params,
                           uint8_t *out, size_t out_len);

EXPORT int nextssl_argon2d(const uint8_t *pwd, size_t pwd_len, 
                           const uint8_t *salt, size_t salt_len,
                           const LeylineArgon2Params *params,
                           uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif // nextssl_PRIMITIVE_MEMORY_HARD_H
