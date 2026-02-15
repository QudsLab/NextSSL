#ifndef LEYLINE_LEGACY_ALIVE_H
#define LEYLINE_LEGACY_ALIVE_H

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

// --- Legacy (Alive) ---
EXPORT int leyline_md5(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_sha1(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_ripemd160(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_whirlpool(const uint8_t *msg, size_t len, uint8_t *out);
EXPORT int leyline_nt_hash(const char *password, uint8_t *out);
// AES-ECB is usually an encryption function, not a hash. 
// But TASK_HASH.md lists it under "Legacy Alive Hashes" in 3.4.
// Wrapper exposed: `leyline_md5`, `leyline_sha1`... it DOES NOT list AES-ECB in 3.4 exposed functions.
// But 9.4.4 has "Legacy Alive" tests. It does NOT list AES-ECB tests. 
// Wait, 507: `legacy_alive.py # Tests: MD5, SHA-1, RIPEMD-160, Whirlpool, NT Hash, AES-ECB`
// So it IS tested.
// I will verify signature in 4.1 or similar?
// 1.4: `void AES_ECB_encrypt(const uint8_t* key, const void* pntxt, size_t ptextLen, void* crtxt);`
// I'll expose it as `leyline_aes_ecb_encrypt`.
EXPORT int leyline_aes_ecb_encrypt(const uint8_t* key, const uint8_t* pntxt, size_t ptextLen, uint8_t* crtxt);

#ifdef __cplusplus
}
#endif

#endif // LEYLINE_LEGACY_ALIVE_H
