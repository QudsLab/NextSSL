#ifndef ROOT_HASH_RECORD_H
#define ROOT_HASH_RECORD_H

#include <stddef.h>
#include <stdint.h>
#include "../nextssl_export.h"

#ifdef __cplusplus
extern "C" {
#endif

NEXTSSL_API int nextssl_blake2b_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_blake2b_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_blake2s_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_blake2s_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_blake3_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_blake3_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha224_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha224_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha384_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha384_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha512_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha512_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha512_224_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha512_224_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha512_256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha512_256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sm3_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sm3_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_has160_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_has160_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_md2_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_md2_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_md4_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_md4_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_md5_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_md5_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_nt_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_nt_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_ripemd128_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_ripemd128_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_ripemd160_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_ripemd160_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_ripemd256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_ripemd256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_ripemd320_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_ripemd320_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha0_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha0_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha1_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha1_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_whirlpool_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_whirlpool_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_keccak256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_keccak256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha3_224_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha3_224_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha3_256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha3_256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha3_384_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha3_384_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_sha3_512_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_sha3_512_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_shake128_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_shake128_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_shake256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_shake256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_skein256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_skein256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_skein512_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_skein512_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_skein1024_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_skein1024_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_kmac128_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_kmac128_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_kmac256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_kmac256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);

NEXTSSL_API int nextssl_argon2d_format_record(const uint8_t *data, size_t data_len, uint32_t memory, uint32_t iterations, uint32_t parallelism, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_argon2d_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_argon2i_format_record(const uint8_t *data, size_t data_len, uint32_t memory, uint32_t iterations, uint32_t parallelism, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_argon2i_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_argon2id_format_record(const uint8_t *data, size_t data_len, uint32_t memory, uint32_t iterations, uint32_t parallelism, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_argon2id_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_scrypt_format_record(const uint8_t *data, size_t data_len, uint64_t N, uint32_t r, uint32_t p, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_scrypt_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_yescrypt_format_record(const uint8_t *data, size_t data_len, uint64_t N, uint32_t r, uint32_t p, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_yescrypt_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_bcrypt_format_record(const uint8_t *data, size_t data_len, uint32_t work_factor, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_bcrypt_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_catena_format_record(const uint8_t *data, size_t data_len, uint8_t lambda, uint8_t garlic, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_catena_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_lyra2_format_record(const uint8_t *data, size_t data_len, uint64_t t_cost, uint32_t nrows, uint32_t ncols, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_lyra2_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_balloon_format_record(const uint8_t *data, size_t data_len, uint32_t s_cost, uint32_t t_cost, uint32_t n_threads, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_balloon_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_pomelo_format_record(const uint8_t *data, size_t data_len, unsigned int t_cost, unsigned int m_cost, size_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_pomelo_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);
NEXTSSL_API int nextssl_makwa_format_record(const uint8_t *data, size_t data_len, uint32_t work_factor, size_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len);
NEXTSSL_API int nextssl_makwa_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match);

#ifdef __cplusplus
}
#endif

#endif
