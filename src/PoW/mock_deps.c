#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Mock implementation of DHCM functions to allow PoW to build
// independently of DHCM DLL exports issues.

// --- DHCM Primitive Fast ---

uint64_t dhcm_sha256_wu(size_t input_size) {
    return 1000 + (input_size * 10);
}

uint64_t dhcm_sha512_wu(size_t input_size) {
    return 1400 + (input_size * 14);
}

uint64_t dhcm_blake3_wu(size_t input_size) {
    return 800 + (input_size * 8); // Faster than SHA256
}

uint64_t dhcm_blake2b_wu(size_t input_size) {
    return 900 + (input_size * 9);
}

uint64_t dhcm_blake2s_wu(size_t input_size) {
    return 850 + (input_size * 8);
}

// --- DHCM Primitive Memory Hard ---

uint64_t dhcm_argon2id_wu(uint32_t t, uint32_t m, uint32_t p) {
    return (uint64_t)t * m * p * 100;
}

uint64_t dhcm_argon2id_mu(uint32_t m) {
    return (uint64_t)m * 1024; // KiB to bytes
}

uint64_t dhcm_argon2i_wu(uint32_t t, uint32_t m, uint32_t p) {
    return (uint64_t)t * m * p * 100;
}

uint64_t dhcm_argon2i_mu(uint32_t m) {
    return (uint64_t)m * 1024;
}

uint64_t dhcm_argon2d_wu(uint32_t t, uint32_t m, uint32_t p) {
    return (uint64_t)t * m * p * 90; // Slightly faster
}

uint64_t dhcm_argon2d_mu(uint32_t m) {
    return (uint64_t)m * 1024;
}

// --- DHCM Primitive Sponge XOF ---

uint64_t dhcm_sha3_256_wu(size_t input_size) {
    return 1200 + (input_size * 12);
}

uint64_t dhcm_sha3_512_wu(size_t input_size) {
    return 1500 + (input_size * 15);
}

uint64_t dhcm_keccak_256_wu(size_t input_size) {
    return 1200 + (input_size * 12);
}

uint64_t dhcm_shake128_wu(size_t input_size) {
    return 1000 + (input_size * 10);
}

uint64_t dhcm_shake256_wu(size_t input_size) {
    return 1200 + (input_size * 12);
}

// --- DHCM Legacy Alive ---

uint64_t dhcm_md5_wu(size_t input_size) {
    return 500 + (input_size * 5);
}

uint64_t dhcm_sha1_wu(size_t input_size) {
    return 600 + (input_size * 6);
}

uint64_t dhcm_ripemd160_wu(size_t input_size) {
    return 700 + (input_size * 7);
}

uint64_t dhcm_whirlpool_wu(size_t input_size) {
    return 1000 + (input_size * 10);
}

uint64_t dhcm_nt_wu(size_t input_size) {
    return 500 + (input_size * 5);
}

// --- DHCM Legacy Unsafe ---

uint64_t dhcm_md2_wu(size_t input_size) {
    return 2000 + (input_size * 20); // Slow
}

uint64_t dhcm_md4_wu(size_t input_size) {
    return 400 + (input_size * 4); // Fast
}

uint64_t dhcm_sha0_wu(size_t input_size) {
    return 600 + (input_size * 6);
}

uint64_t dhcm_has160_wu(size_t input_size) {
    return 650 + (input_size * 6);
}

uint64_t dhcm_ripemd128_wu(size_t input_size) {
    return 600 + (input_size * 6);
}

uint64_t dhcm_ripemd256_wu(size_t input_size) {
    return 800 + (input_size * 8);
}

uint64_t dhcm_ripemd320_wu(size_t input_size) {
    return 900 + (input_size * 9);
}

// =========================================================================
// Hash Primitive Implementations (Mock for PoW)
// In a real build, these would be exported from Hash DLLs
// =========================================================================

// --- Hash Primitive Fast ---

int leyline_sha256(const uint8_t* input, size_t len, uint8_t* output) {
    // Just copy first 32 bytes of input to output, or zero it
    // This is a dummy implementation for testing PoW logic (not crypto)
    memset(output, 0, 32);
    // Simple mixing to make it vary with input
    for (size_t i = 0; i < len; i++) {
        output[i % 32] ^= input[i];
    }
    return 0;
}

int leyline_blake3(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 32);
    for (size_t i = 0; i < len; i++) {
        output[i % 32] ^= input[i];
        output[(i + 1) % 32] += 1;
    }
    return 0;
}

// --- Hash Primitive Memory Hard ---

#ifndef POW_ENABLE_PRIMITIVE_MEMORY_HARD
int leyline_argon2id(const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, 
                    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism, 
                    void* output, size_t outlen) {
    // Dummy Argon2
    memset(output, 0, outlen);
    // Mix input into output
    const uint8_t* p = (const uint8_t*)pwd;
    for (size_t i = 0; i < pwdlen; i++) {
        ((uint8_t*)output)[i % outlen] ^= p[i];
    }
    return 0;
}

int leyline_argon2i(const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, 
                    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism, 
                    void* output, size_t outlen) {
    return leyline_argon2id(pwd, pwdlen, salt, saltlen, t_cost, m_cost, parallelism, output, outlen);
}

int leyline_argon2d(const void* pwd, size_t pwdlen, const void* salt, size_t saltlen, 
                    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism, 
                    void* output, size_t outlen) {
    return leyline_argon2id(pwd, pwdlen, salt, saltlen, t_cost, m_cost, parallelism, output, outlen);
}
#endif

// --- Hash Primitive Sponge XOF ---

int leyline_sha3_256(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 32);
    for (size_t i = 0; i < len; i++) {
        output[i % 32] ^= input[i];
    }
    return 0;
}

int leyline_sha3_512(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 64);
    for (size_t i = 0; i < len; i++) {
        output[i % 64] ^= input[i];
    }
    return 0;
}

int leyline_keccak_256(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 32);
    for (size_t i = 0; i < len; i++) {
        output[i % 32] ^= input[i];
    }
    return 0;
}

int leyline_shake128(const uint8_t* input, size_t len, uint8_t* output, size_t out_len) {
    memset(output, 0, out_len);
    for (size_t i = 0; i < len; i++) {
        output[i % out_len] ^= input[i];
    }
    return 0;
}

int leyline_shake256(const uint8_t* input, size_t len, uint8_t* output, size_t out_len) {
    memset(output, 0, out_len);
    for (size_t i = 0; i < len; i++) {
        output[i % out_len] ^= input[i];
    }
    return 0;
}

// --- Hash Legacy Alive ---

int leyline_md5(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 16);
    for (size_t i = 0; i < len; i++) {
        output[i % 16] ^= input[i];
    }
    return 0;
}

int leyline_sha1(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 20);
    for (size_t i = 0; i < len; i++) {
        output[i % 20] ^= input[i];
    }
    return 0;
}

int leyline_ripemd160(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 20);
    for (size_t i = 0; i < len; i++) {
        output[i % 20] ^= input[i];
    }
    return 0;
}

int leyline_whirlpool(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 64);
    for (size_t i = 0; i < len; i++) {
        output[i % 64] ^= input[i];
    }
    return 0;
}

int leyline_nt(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 16);
    for (size_t i = 0; i < len; i++) {
        output[i % 16] ^= input[i];
    }
    return 0;
}

// --- Hash Legacy Unsafe ---

int leyline_md2(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 16);
    for (size_t i = 0; i < len; i++) {
        output[i % 16] ^= input[i];
    }
    return 0;
}

int leyline_md4(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 16);
    for (size_t i = 0; i < len; i++) {
        output[i % 16] ^= input[i];
    }
    return 0;
}

int leyline_sha0(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 20);
    for (size_t i = 0; i < len; i++) {
        output[i % 20] ^= input[i];
    }
    return 0;
}

int leyline_has160(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 20);
    for (size_t i = 0; i < len; i++) {
        output[i % 20] ^= input[i];
    }
    return 0;
}

int leyline_ripemd128(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 16);
    for (size_t i = 0; i < len; i++) {
        output[i % 16] ^= input[i];
    }
    return 0;
}

int leyline_ripemd256(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 32);
    for (size_t i = 0; i < len; i++) {
        output[i % 32] ^= input[i];
    }
    return 0;
}

int leyline_ripemd320(const uint8_t* input, size_t len, uint8_t* output) {
    memset(output, 0, 40);
    for (size_t i = 0; i < len; i++) {
        output[i % 40] ^= input[i];
    }
    return 0;
}
