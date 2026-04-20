#include "root_hash_record.h"

#include "../../hash/record/hash_record_core.h"
#include <string.h>

int nextssl_blake2b_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("blake2b", data, data_len, record_out, record_cap, record_len); }
int nextssl_blake2b_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("blake2b", data, data_len, record, out_match); }
int nextssl_blake2s_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("blake2s", data, data_len, record_out, record_cap, record_len); }
int nextssl_blake2s_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("blake2s", data, data_len, record, out_match); }
int nextssl_blake3_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("blake3", data, data_len, record_out, record_cap, record_len); }
int nextssl_blake3_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("blake3", data, data_len, record, out_match); }
int nextssl_sha224_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha224", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha224_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha224", data, data_len, record, out_match); }
int nextssl_sha256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha256", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha256", data, data_len, record, out_match); }
int nextssl_sha384_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha384", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha384_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha384", data, data_len, record, out_match); }
int nextssl_sha512_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha512", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha512_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha512", data, data_len, record, out_match); }
int nextssl_sha512_224_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha512-224", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha512_224_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha512-224", data, data_len, record, out_match); }
int nextssl_sha512_256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha512-256", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha512_256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha512-256", data, data_len, record, out_match); }
int nextssl_sm3_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sm3", data, data_len, record_out, record_cap, record_len); }
int nextssl_sm3_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sm3", data, data_len, record, out_match); }
int nextssl_has160_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("has160", data, data_len, record_out, record_cap, record_len); }
int nextssl_has160_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("has160", data, data_len, record, out_match); }
int nextssl_md2_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("md2", data, data_len, record_out, record_cap, record_len); }
int nextssl_md2_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("md2", data, data_len, record, out_match); }
int nextssl_md4_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("md4", data, data_len, record_out, record_cap, record_len); }
int nextssl_md4_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("md4", data, data_len, record, out_match); }
int nextssl_md5_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("md5", data, data_len, record_out, record_cap, record_len); }
int nextssl_md5_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("md5", data, data_len, record, out_match); }
int nextssl_nt_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("nt", data, data_len, record_out, record_cap, record_len); }
int nextssl_nt_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("nt", data, data_len, record, out_match); }
int nextssl_ripemd128_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("ripemd128", data, data_len, record_out, record_cap, record_len); }
int nextssl_ripemd128_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("ripemd128", data, data_len, record, out_match); }
int nextssl_ripemd160_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("ripemd160", data, data_len, record_out, record_cap, record_len); }
int nextssl_ripemd160_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("ripemd160", data, data_len, record, out_match); }
int nextssl_ripemd256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("ripemd256", data, data_len, record_out, record_cap, record_len); }
int nextssl_ripemd256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("ripemd256", data, data_len, record, out_match); }
int nextssl_ripemd320_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("ripemd320", data, data_len, record_out, record_cap, record_len); }
int nextssl_ripemd320_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("ripemd320", data, data_len, record, out_match); }
int nextssl_sha0_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha0", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha0_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha0", data, data_len, record, out_match); }
int nextssl_sha1_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha1", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha1_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha1", data, data_len, record, out_match); }
int nextssl_whirlpool_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("whirlpool", data, data_len, record_out, record_cap, record_len); }
int nextssl_whirlpool_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("whirlpool", data, data_len, record, out_match); }
int nextssl_keccak256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("keccak256", data, data_len, record_out, record_cap, record_len); }
int nextssl_keccak256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("keccak256", data, data_len, record, out_match); }
int nextssl_sha3_224_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha3-224", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha3_224_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha3-224", data, data_len, record, out_match); }
int nextssl_sha3_256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha3-256", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha3_256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha3-256", data, data_len, record, out_match); }
int nextssl_sha3_384_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha3-384", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha3_384_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha3-384", data, data_len, record, out_match); }
int nextssl_sha3_512_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("sha3-512", data, data_len, record_out, record_cap, record_len); }
int nextssl_sha3_512_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("sha3-512", data, data_len, record, out_match); }
int nextssl_shake128_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("shake128", data, data_len, record_out, record_cap, record_len); }
int nextssl_shake128_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("shake128", data, data_len, record, out_match); }
int nextssl_shake256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("shake256", data, data_len, record_out, record_cap, record_len); }
int nextssl_shake256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("shake256", data, data_len, record, out_match); }
int nextssl_skein256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("skein256", data, data_len, record_out, record_cap, record_len); }
int nextssl_skein256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("skein256", data, data_len, record, out_match); }
int nextssl_skein512_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("skein512", data, data_len, record_out, record_cap, record_len); }
int nextssl_skein512_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("skein512", data, data_len, record, out_match); }
int nextssl_skein1024_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("skein1024", data, data_len, record_out, record_cap, record_len); }
int nextssl_skein1024_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("skein1024", data, data_len, record, out_match); }
int nextssl_kmac128_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("kmac128", data, data_len, record_out, record_cap, record_len); }
int nextssl_kmac128_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("kmac128", data, data_len, record, out_match); }
int nextssl_kmac256_format_record(const uint8_t *data, size_t data_len, char *record_out, size_t record_cap, size_t *record_len)
{ return nextssl_record_format_plain_internal("kmac256", data, data_len, record_out, record_cap, record_len); }
int nextssl_kmac256_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_plain_internal("kmac256", data, data_len, record, out_match); }

int nextssl_argon2d_format_record(const uint8_t *data, size_t data_len, uint32_t memory, uint32_t iterations, uint32_t parallelism, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.memory = memory; cfg.iterations = iterations; cfg.parallelism = parallelism; cfg.key_length = key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("argon2d", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_argon2d_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("argon2d", data, data_len, record, out_match); }
int nextssl_argon2i_format_record(const uint8_t *data, size_t data_len, uint32_t memory, uint32_t iterations, uint32_t parallelism, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.memory = memory; cfg.iterations = iterations; cfg.parallelism = parallelism; cfg.key_length = key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("argon2i", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_argon2i_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("argon2i", data, data_len, record, out_match); }
int nextssl_argon2id_format_record(const uint8_t *data, size_t data_len, uint32_t memory, uint32_t iterations, uint32_t parallelism, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.memory = memory; cfg.iterations = iterations; cfg.parallelism = parallelism; cfg.key_length = key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("argon2id", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_argon2id_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("argon2id", data, data_len, record, out_match); }
int nextssl_scrypt_format_record(const uint8_t *data, size_t data_len, uint64_t N, uint32_t r, uint32_t p, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.N = N; cfg.r = r; cfg.p = p; cfg.key_length = key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("scrypt", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_scrypt_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("scrypt", data, data_len, record, out_match); }
int nextssl_yescrypt_format_record(const uint8_t *data, size_t data_len, uint64_t N, uint32_t r, uint32_t p, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.N = N; cfg.r = r; cfg.p = p; cfg.key_length = key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("yescrypt", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_yescrypt_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("yescrypt", data, data_len, record, out_match); }
int nextssl_bcrypt_format_record(const uint8_t *data, size_t data_len, uint32_t work_factor, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.work_factor = work_factor; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("bcrypt", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_bcrypt_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("bcrypt", data, data_len, record, out_match); }
int nextssl_catena_format_record(const uint8_t *data, size_t data_len, uint8_t lambda, uint8_t garlic, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.lambda = lambda; cfg.garlic = garlic; cfg.key_length = key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("catena", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_catena_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("catena", data, data_len, record, out_match); }
int nextssl_lyra2_format_record(const uint8_t *data, size_t data_len, uint64_t t_cost, uint32_t nrows, uint32_t ncols, uint32_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.t_cost = t_cost; cfg.nrows = nrows; cfg.ncols = ncols; cfg.key_length = key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("lyra2", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_lyra2_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("lyra2", data, data_len, record, out_match); }
int nextssl_balloon_format_record(const uint8_t *data, size_t data_len, uint32_t s_cost, uint32_t t_cost, uint32_t n_threads, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.s_cost = s_cost; cfg.iterations = t_cost; cfg.n_threads = n_threads; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("balloon", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_balloon_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("balloon", data, data_len, record, out_match); }
int nextssl_pomelo_format_record(const uint8_t *data, size_t data_len, unsigned int t_cost, unsigned int m_cost, size_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.t_cost_u = t_cost; cfg.m_cost_u = m_cost; cfg.key_length = (uint32_t)key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("pomelo", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_pomelo_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("pomelo", data, data_len, record, out_match); }
int nextssl_makwa_format_record(const uint8_t *data, size_t data_len, uint32_t work_factor, size_t key_length, const uint8_t *salt, size_t salt_len, char *record_out, size_t record_cap, size_t *record_len)
{ nextssl_hash_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.work_factor = work_factor; cfg.key_length = (uint32_t)key_length; cfg.salt = salt; cfg.salt_len = salt_len; return nextssl_record_format_kdf_internal("makwa", data, data_len, &cfg, record_out, record_cap, record_len); }
int nextssl_makwa_verify_record(const uint8_t *data, size_t data_len, const char *record, int *out_match)
{ return nextssl_record_verify_kdf_internal("makwa", data, data_len, record, out_match); }
