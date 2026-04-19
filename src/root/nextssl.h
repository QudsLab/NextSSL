/* nextssl.h — Master Public Header for the NextSSL Library
 *
 * This is the ONLY header external consumers need to include.
 * Call nextssl_init() ONCE before any other nextssl_* function.
 *
 * Rule (Plan 40006):
 *   - All NEXTSSL_API symbols live exclusively under src/root/
 *   - Subsystem inits are chained through nextssl_init() only
 *   - New exports require a root_<name>.h + root_<name>.c entry
 *
 * ═══════════════════════════════════════════════════════════════
 * MASTER EXPORTED SYMBOL INDEX
 * ═══════════════════════════════════════════════════════════════
 *
 * ── Startup ────────────────────────────────────────────────────
 *   nextssl_init()                 initialise all subsystems (call first)
 *
 * ── Hash ───────────────────────────────────────────────────────
 *   nextssl_hash_compute()         one-shot hash of a buffer
 *   nextssl_hash_digest_size()     digest size in bytes for named algo
 *   nextssl_hash_block_size()      block size in bytes for named algo
 *   nextssl_hash_list()            NULL-terminated list of all algo names
 *
 * ── Seed / Key Derivation ──────────────────────────────────────
 *   nextssl_seed_random()          PATH 1: OS RNG bytes
 *   nextssl_seed_derive()          PATH 2: deterministic CTR-mode derivation
 *   nextssl_seed_udbf_feed()       TIER 3: load test vector
 *   nextssl_seed_udbf_wipe()       TIER 3: clear test vector
 *
 * ── Modern Cryptography ────────────────────────────────────────
 *   nextssl_sym_aes_cbc_encrypt()
 *   nextssl_sym_aes_cbc_decrypt()
 *   nextssl_aead_aes_gcm_encrypt()
 *   nextssl_aead_aes_gcm_decrypt()
 *   nextssl_aead_chacha20poly1305_encrypt()
 *   nextssl_aead_chacha20poly1305_decrypt()
 *   nextssl_mac_hmac_compute()
 *   nextssl_mac_poly1305_compute()
 *   nextssl_kdf_hkdf_extract()
 *   nextssl_kdf_hkdf_expand()
 *   nextssl_kdf_pbkdf2()
 *   nextssl_modern_seed_key()
 *   nextssl_modern_seed_nonce()
 *   nextssl_asym_ed25519_keygen()
 *   nextssl_asym_ed25519_keygen_derand()
 *   nextssl_asym_ed25519_sign()
 *   nextssl_asym_ed25519_verify()
 *   nextssl_asym_x25519_keygen()
 *   nextssl_asym_x25519_keygen_derand()
 *   nextssl_asym_x25519_exchange()
 *   nextssl_asym_rsa_keygen_derand()
 *   nextssl_asym_ecdh_p256_*()
 *   nextssl_asym_ecdh_p384_*()
 *   nextssl_asym_ecdh_p521_*()
 *
 * ── Proof-of-Work ──────────────────────────────────────────────
 *   nextssl_pow_server_generate_challenge()
 *   nextssl_pow_server_verify_solution()
 *   nextssl_pow_client_parse_challenge()
 *   nextssl_pow_client_solve()
 *   nextssl_pow_client_check_limits()
 *   nextssl_pow_challenge_encode()
 *   nextssl_pow_solution_encode()
 *   nextssl_pow_solution_decode()
 *   nextssl_pow_algo_name_normalise()
 *   nextssl_cost_compute()         formula cost (Plan 40005) — all 8 dims
 *   nextssl_cost_probe()           live benchmark + formula (Plan 40005)
 *   nextssl_cost_probe_print()     print probe result summary to stdout
 *
 * ── Post-Quantum Cryptography ──────────────────────────────────
 *   nextssl_pqc_randombytes*()
 *   nextssl_pqc_drbg_*()
 *   nextssl_pqc_mlkem512/768/1024_keypair/encaps/decaps()
 *   nextssl_pqc_mldsa44/65/87_keypair/sign/verify()
 *   nextssl_pqc_falcon512/1024_keypair/sign/verify()
 *   nextssl_pqc_sphincs_*()
 *   nextssl_pqc_hqc128/192/256_*()
 *   nextssl_pqc_mceliece_*()
 *
 * ═══════════════════════════════════════════════════════════════
 */
#ifndef NEXTSSL_H
#define NEXTSSL_H

#include "nextssl_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Startup ────────────────────────────────────────────────────────────────
 * nextssl_init — initialise ALL subsystems in the correct order.
 *
 * MUST be called once before any other nextssl_* function.
 * Safe to call multiple times (idempotent).
 * Returns 0 on success, -1 if any subsystem init fails.
 * --------------------------------------------------------------------------*/
NEXTSSL_API int nextssl_init(void);

#ifdef __cplusplus
}
#endif

/* ── Subsystem headers ──────────────────────────────────────────────────────
 * Each root_*.h provides NEXTSSL_API-decorated declarations for one subsystem.
 * Do NOT include these individually in consumer code — include nextssl.h only.
 * --------------------------------------------------------------------------*/
#include "hash/root_hash.h"
#include "seed/root_seed.h"
#include "modern/root_modern.h"
#include "pow/root_pow.h"
#include "pqc/root_pqc.h"

#endif /* NEXTSSL_H */
