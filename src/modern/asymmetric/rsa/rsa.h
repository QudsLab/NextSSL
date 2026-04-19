/* rsa.h — RSA operations (BearSSL backend, NEXTSSL_HAS_BEARSSL)
 *
 * Supports key sizes 2048, 3072, and 4096 bits.
 *
 * Key management:
 *   Allocate an rsa_keypair_t on the heap or as a long-lived static.
 *   NEVER copy this struct by value — the BearSSL key structs contain
 *   pointers into the included flat buffers and will become dangling.
 *   Use rsa_keypair_dup() to safely duplicate a keypair.
 *
 * Memory safety:
 *   Call rsa_keypair_wipe() to securely zero private key material before
 *   freeing or going out of scope.
 *
 * Thread safety:
 *   Keygen seeds from the OS CSPRNG (BCryptGenRandom / getrandom / arc4random).
 *   All sign/encrypt/decrypt functions are read-only on the key struct and
 *   are safe to call concurrently after keygen.
 *
 * Usage (sign + verify example):
 *   rsa_keypair_t *kp = rsa_keypair_alloc();
 *   rsa_keygen(kp, 2048);
 *   uint8_t sig[256]; size_t siglen = sizeof sig;
 *   rsa_pss_sign(kp, &br_sha256_vtable, &br_sha256_vtable, hash_buf, 32, 32, sig, &siglen);
 *   int ok = rsa_pss_verify(&kp->pk, &br_sha256_vtable, &br_sha256_vtable, hash_buf, 32, 32, sig, siglen);
 *   rsa_keypair_free(kp);
 */
#ifndef RSA_H
#define RSA_H

#ifdef NEXTSSL_HAS_BEARSSL

#include <stddef.h>
#include <stdint.h>
#include <bearssl_rsa.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Size constants ------------------------------------------------------ */

#define RSA_MIN_BITS       2048u
#define RSA_MAX_BITS       4096u

/* Buffer sizes for maximum 4096-bit RSA keys */
#define RSA_KBUF_PRIV_MAX  BR_RSA_KBUF_PRIV_SIZE(4096)  /* 1280 bytes */
#define RSA_KBUF_PUB_MAX   BR_RSA_KBUF_PUB_SIZE(4096)   /*  516 bytes */

/* Standard public exponent: 65537 */
#define RSA_DEFAULT_PUBEXP  65537u

/* ---- Key pair struct ----------------------------------------------------- */

/**
 * RSA key pair.  The BearSSL key structs (sk, pk) contain pointers into the
 * flat buffers (priv_buf, pub_buf) stored in this struct.  The struct MUST
 * NOT be copied by value — use rsa_keypair_dup().
 */
typedef struct rsa_keypair_t {
    uint8_t            priv_buf[RSA_KBUF_PRIV_MAX];
    uint8_t            pub_buf [RSA_KBUF_PUB_MAX];
    br_rsa_private_key sk;
    br_rsa_public_key  pk;
    unsigned           key_bits;
} rsa_keypair_t;

/* ---- Lifecycle ----------------------------------------------------------- */

/** Allocate and zero-initialise an rsa_keypair_t on the heap.
 *  Returns NULL on allocation failure. */
rsa_keypair_t *rsa_keypair_alloc(void);

/** Securely wipe private key material then free the heap block. */
void           rsa_keypair_free(rsa_keypair_t *kp);

/** Wipe private key material in-place without freeing.
 *  Call this when the keypair is stack- or statically-allocated. */
void           rsa_keypair_wipe(rsa_keypair_t *kp);

/**
 * Deep-copy |src| into a freshly heap-allocated keypair, fixing up
 * all internal pointers.
 * Returns NULL on allocation failure.
 */
rsa_keypair_t *rsa_keypair_dup(const rsa_keypair_t *src);

/* ---- Key generation ------------------------------------------------------ */

/**
 * Generate a new RSA key pair.
 *
 * @param kp    Pre-allocated keypair struct (rsa_keypair_alloc() or static).
 * @param bits  Key size in bits: 2048, 3072, or 4096.
 * @return 0 on success, -1 on error (invalid bits or PRNG failure).
 */
int rsa_keygen(rsa_keypair_t *kp, unsigned bits);
int rsa_keygen_seeded(rsa_keypair_t *kp, unsigned bits,
                      const uint8_t *seed, size_t seed_len);

/* ---- PKCS#1 v1.5 sign / verify ------------------------------------------ */

/**
 * Sign |hash_len| bytes in |hash| with PKCS#1 v1.5.
 *
 * @param kp       Keypair (private key used).
 * @param hash_oid DER-encoded hash OID (e.g. BR_HASH_OID_SHA256).
 * @param hash     Hash value to sign (must match hash_oid's output length).
 * @param hash_len Length of |hash|.
 * @param sig      Output buffer; must hold at least key_bits/8 bytes.
 * @param sig_len  In: capacity of sig.  Out: bytes written.
 * @return 1 on success, 0 on error.
 */
uint32_t rsa_pkcs1_sign(const rsa_keypair_t *kp,
                        const unsigned char *hash_oid,
                        const uint8_t *hash, size_t hash_len,
                        uint8_t *sig, size_t *sig_len);

/**
 * Verify a PKCS#1 v1.5 signature.
 *
 * @param pk       Public key.
 * @param hash_oid DER-encoded hash OID.
 * @param hash     Expected hash value.
 * @param hash_len Length of |hash|.
 * @param sig      Input signature bytes.
 * @param sig_len  Length of |sig|.
 * @return 1 if valid, 0 if invalid.
 */
uint32_t rsa_pkcs1_verify(const br_rsa_public_key *pk,
                          const unsigned char *hash_oid,
                          const uint8_t *hash, size_t hash_len,
                          const uint8_t *sig, size_t sig_len);

/* ---- PSS sign / verify --------------------------------------------------- */

/**
 * Sign with RSA-PSS.
 *
 * @param kp        Keypair.
 * @param hf_data   Hash function used to hash the message (e.g. &br_sha256_vtable).
 * @param hf_mgf1   Hash function for the MGF1 mask; usually identical to hf_data.
 * @param hash      Pre-computed hash of the message (length == hf_data->desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK).
 * @param hash_len  Length of |hash|.
 * @param salt_len  PSS salt length in bytes (typically == hash_len).
 * @param sig       Output buffer; must hold at least key_bits/8 bytes.
 * @param sig_len   In: capacity.  Out: bytes written.
 * @return 1 on success, 0 on error.
 */
uint32_t rsa_pss_sign(const rsa_keypair_t *kp,
                      const br_hash_class *hf_data,
                      const br_hash_class *hf_mgf1,
                      const uint8_t *hash, size_t hash_len,
                      size_t salt_len,
                      uint8_t *sig, size_t *sig_len);

/**
 * Verify an RSA-PSS signature.
 *
 * @param pk        Public key.
 * @param hf_data   Hash function used when the message was hashed.
 * @param hf_mgf1   Hash function for the MGF1 mask; usually identical to hf_data.
 * @param hash      Pre-computed hash of the message.
 * @param hash_len  Length of |hash|.
 * @param salt_len  Expected PSS salt length.
 * @param sig       Signature bytes.
 * @param sig_len   Signature length.
 * @return 1 if valid, 0 if invalid.
 */
uint32_t rsa_pss_verify(const br_rsa_public_key *pk,
                        const br_hash_class *hf_data,
                        const br_hash_class *hf_mgf1,
                        const uint8_t *hash, size_t hash_len,
                        size_t salt_len,
                        const uint8_t *sig, size_t sig_len);

/* ---- OAEP encrypt / decrypt ---------------------------------------------- */

/**
 * RSA-OAEP encrypt.
 *
 * @param pk        Public key.
 * @param hash_id   Hash function for MGF1 (e.g. &br_sha256_vtable).
 * @param label     Optional label (may be NULL with label_len == 0).
 * @param label_len Length of label.
 * @param msg       Plaintext message.
 * @param msg_len   Plaintext length (must satisfy OAEP padding constraints).
 * @param out       Output ciphertext; must hold key_bits/8 bytes.
 * @param out_len   In: capacity.  Out: bytes written.
 * @return 1 on success, 0 on error (invalid parameters or message too long).
 */
uint32_t rsa_oaep_encrypt(const br_rsa_public_key *pk,
                          const br_hash_class *hash_id,
                          const void *label, size_t label_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t *out, size_t *out_len);

/**
 * RSA-OAEP decrypt.
 *
 * @param kp        Keypair (private key used).
 * @param hash_id   Hash function for MGF1.
 * @param label     Optional label (must match what was used during encrypt).
 * @param label_len Length of label.
 * @param data      In: ciphertext (key_bits/8 bytes).  Out: decrypted plaintext.
 * @param data_len  In: ciphertext length.  Out: plaintext length.
 * @return 1 on success, 0 on error (decryption failure or padding error).
 */
uint32_t rsa_oaep_decrypt(const rsa_keypair_t *kp,
                          const br_hash_class *hash_id,
                          const void *label, size_t label_len,
                          uint8_t *data, size_t *data_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_HAS_BEARSSL */
#endif /* RSA_H */
