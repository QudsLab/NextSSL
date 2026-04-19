/* rsa.c — RSA operations (BearSSL backend)
 *
 * Link against the BearSSL static library (-lbearssl).
 * Compile with -DNEXTSSL_HAS_BEARSSL and -I<path-to-bearssl/inc>.
 */
#ifdef NEXTSSL_HAS_BEARSSL

#include "rsa.h"
#include <stdlib.h>
#include <string.h>

/* ---- PRNG seeding -------------------------------------------------------- */

/*
 * Seed a BearSSL HMAC-DRBG (SHA-256) from the OS entropy source.
 * Returns 0 on success.
 */
static int seed_drbg(br_hmac_drbg_context *rng)
{
    /* br_prng_seeder_system returns a seeder function that fills the DRBG
     * context from the OS CSPRNG.  We call it with a tiny initial seed to
     * prime the state, then the seeder re-seeds it. */
    br_hmac_drbg_init(rng, &br_sha256_vtable, NULL, 0);

    br_prng_seeder seeder = br_prng_seeder_system(NULL);
    if (!seeder) return -1;
    if (!seeder((const br_prng_class **)rng)) return -1;
    return 0;
}

static int seed_drbg_seeded(br_hmac_drbg_context *rng,
                            const uint8_t *seed,
                            size_t seed_len)
{
    if (!rng || !seed || seed_len == 0) return -1;
    br_hmac_drbg_init(rng, &br_sha256_vtable, seed, seed_len);
    return 0;
}

/* ---- Lifecycle ----------------------------------------------------------- */

rsa_keypair_t *rsa_keypair_alloc(void)
{
    rsa_keypair_t *kp = (rsa_keypair_t *)calloc(1, sizeof(rsa_keypair_t));
    return kp;
}

void rsa_keypair_wipe(rsa_keypair_t *kp)
{
    if (!kp) return;
    /* Zero the private key buffer (contains p, q, dp, dq, iq) */
    memset(kp->priv_buf, 0, sizeof(kp->priv_buf));
    memset(&kp->sk, 0, sizeof(kp->sk));
    /* Public buffer and struct are not confidential but wipe for hygiene */
    memset(kp->pub_buf, 0, sizeof(kp->pub_buf));
    memset(&kp->pk, 0, sizeof(kp->pk));
    kp->key_bits = 0;
}

void rsa_keypair_free(rsa_keypair_t *kp)
{
    if (!kp) return;
    rsa_keypair_wipe(kp);
    free(kp);
}

/*
 * After a memcpy the BearSSL key pointers still point into the original
 * struct's buffers.  Rebase them to point into |dst|'s own buffers.
 */
static void rebase_sk(br_rsa_private_key *sk_dst,
                      const br_rsa_private_key *sk_src,
                      const uint8_t *old_buf, uint8_t *new_buf)
{
    /* All BearSSL sk field pointers live in the same flat priv_buf */
#define REBASE(field) \
    sk_dst->field = new_buf + (sk_src->field - old_buf)
    REBASE(p); REBASE(q); REBASE(dp); REBASE(dq); REBASE(iq);
#undef REBASE
    sk_dst->n_bitlen = sk_src->n_bitlen;
    sk_dst->plen  = sk_src->plen;
    sk_dst->qlen  = sk_src->qlen;
    sk_dst->dplen = sk_src->dplen;
    sk_dst->dqlen = sk_src->dqlen;
    sk_dst->iqlen = sk_src->iqlen;
}

static void rebase_pk(br_rsa_public_key *pk_dst,
                      const br_rsa_public_key *pk_src,
                      const uint8_t *old_buf, uint8_t *new_buf)
{
    pk_dst->n    = new_buf + (pk_src->n - old_buf);
    pk_dst->e    = new_buf + (pk_src->e - old_buf);
    pk_dst->nlen = pk_src->nlen;
    pk_dst->elen = pk_src->elen;
}

rsa_keypair_t *rsa_keypair_dup(const rsa_keypair_t *src)
{
    if (!src) return NULL;
    rsa_keypair_t *dst = rsa_keypair_alloc();
    if (!dst) return NULL;

    memcpy(dst->priv_buf, src->priv_buf, sizeof(dst->priv_buf));
    memcpy(dst->pub_buf,  src->pub_buf,  sizeof(dst->pub_buf));
    dst->key_bits = src->key_bits;

    rebase_sk(&dst->sk, &src->sk, src->priv_buf, dst->priv_buf);
    rebase_pk(&dst->pk, &src->pk, src->pub_buf,  dst->pub_buf);
    return dst;
}

/* ---- Key generation ------------------------------------------------------ */

int rsa_keygen(rsa_keypair_t *kp, unsigned bits)
{
    if (!kp) return -1;
    if (bits < RSA_MIN_BITS || bits > RSA_MAX_BITS) return -1;
    /* Only commonly-used key sizes to avoid extremely slow keygen */
    if (bits != 2048 && bits != 3072 && bits != 4096) return -1;

    br_hmac_drbg_context rng;
    if (seed_drbg(&rng) != 0) return -1;

    memset(kp, 0, sizeof(*kp));

    br_rsa_keygen gen = br_rsa_keygen_get_default();
    uint32_t ok = gen(
        (const br_prng_class **)&rng,
        &kp->sk, kp->priv_buf,
        &kp->pk,  kp->pub_buf,
        bits, RSA_DEFAULT_PUBEXP
    );

    /* Wipe PRNG state — it contains entropy and derived key data */
    memset(&rng, 0, sizeof(rng));

    if (!ok) { rsa_keypair_wipe(kp); return -1; }
    kp->key_bits = bits;
    return 0;
}

int rsa_keygen_seeded(rsa_keypair_t *kp, unsigned bits,
                      const uint8_t *seed, size_t seed_len)
{
    if (!kp) return -1;
    if (!seed || seed_len == 0) return -1;
    if (bits < RSA_MIN_BITS || bits > RSA_MAX_BITS) return -1;
    if (bits != 2048 && bits != 3072 && bits != 4096) return -1;

    br_hmac_drbg_context rng;
    if (seed_drbg_seeded(&rng, seed, seed_len) != 0) return -1;

    memset(kp, 0, sizeof(*kp));

    br_rsa_keygen gen = br_rsa_keygen_get_default();
    uint32_t ok = gen(
        (const br_prng_class **)&rng,
        &kp->sk, kp->priv_buf,
        &kp->pk,  kp->pub_buf,
        bits, RSA_DEFAULT_PUBEXP
    );

    memset(&rng, 0, sizeof(rng));

    if (!ok) { rsa_keypair_wipe(kp); return -1; }
    kp->key_bits = bits;
    return 0;
}

/* ---- PKCS#1 v1.5 -------------------------------------------------------- */

uint32_t rsa_pkcs1_sign(const rsa_keypair_t *kp,
                        const unsigned char *hash_oid,
                        const uint8_t *hash, size_t hash_len,
                        uint8_t *sig, size_t *sig_len)
{
    if (!kp || !hash || !sig || !sig_len) return 0;
    size_t mod_len = (kp->key_bits + 7) / 8;
    if (*sig_len < mod_len) return 0;
    uint32_t ok = br_rsa_pkcs1_sign_get_default()(hash_oid, hash, hash_len, &kp->sk, sig);
    if (ok) *sig_len = mod_len;
    return ok;
}

uint32_t rsa_pkcs1_verify(const br_rsa_public_key *pk,
                          const unsigned char *hash_oid,
                          const uint8_t *hash, size_t hash_len,
                          const uint8_t *sig, size_t sig_len)
{
    if (!pk || !hash || !sig) return 0;
    uint8_t hash_out[64]; /* max hash output */
    if (hash_len > sizeof(hash_out)) return 0;
    return br_rsa_pkcs1_vrfy_get_default()(
        sig, sig_len, hash_oid, hash_len, pk, hash_out)
        && (memcmp(hash_out, hash, hash_len) == 0) ? 1 : 0;
}

/* ---- PSS ----------------------------------------------------------------- */

uint32_t rsa_pss_sign(const rsa_keypair_t *kp,
                      const br_hash_class *hf_data,
                      const br_hash_class *hf_mgf1,
                      const uint8_t *hash, size_t hash_len,
                      size_t salt_len,
                      uint8_t *sig, size_t *sig_len)
{
    if (!kp || !hf_data || !hf_mgf1 || !hash || !sig || !sig_len) return 0;
    size_t mod_len = (kp->key_bits + 7) / 8;
    if (*sig_len < mod_len) return 0;

    br_hmac_drbg_context rng;
    if (seed_drbg(&rng) != 0) return 0;

    uint32_t ok = br_rsa_pss_sign_get_default()(
        (const br_prng_class **)&rng,
        hf_data, hf_mgf1,
        hash, salt_len,
        &kp->sk, sig
    );
    memset(&rng, 0, sizeof(rng));
    if (ok) *sig_len = mod_len;
    return ok;
}

uint32_t rsa_pss_verify(const br_rsa_public_key *pk,
                        const br_hash_class *hf_data,
                        const br_hash_class *hf_mgf1,
                        const uint8_t *hash, size_t hash_len,
                        size_t salt_len,
                        const uint8_t *sig, size_t sig_len)
{
    if (!pk || !hf_data || !hf_mgf1 || !hash || !sig) return 0;
    return br_rsa_pss_vrfy_get_default()(
        sig, sig_len, hf_data, hf_mgf1, hash, salt_len, pk
    );
}

/* ---- OAEP ---------------------------------------------------------------- */

uint32_t rsa_oaep_encrypt(const br_rsa_public_key *pk,
                          const br_hash_class *hash_id,
                          const void *label, size_t label_len,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t *out, size_t *out_len)
{
    if (!pk || !hash_id || !msg || !out || !out_len) return 0;

    br_hmac_drbg_context rng;
    if (seed_drbg(&rng) != 0) return 0;

    size_t ct_len = br_rsa_oaep_encrypt_get_default()(
        (const br_prng_class **)&rng,
        hash_id, label, label_len,
        pk, out, *out_len,
        msg, msg_len
    );
    memset(&rng, 0, sizeof(rng));
    if (!ct_len) return 0;
    *out_len = ct_len;
    return 1;
}

uint32_t rsa_oaep_decrypt(const rsa_keypair_t *kp,
                          const br_hash_class *hash_id,
                          const void *label, size_t label_len,
                          uint8_t *data, size_t *data_len)
{
    if (!kp || !hash_id || !data || !data_len) return 0;
    return br_rsa_oaep_decrypt_get_default()(
        hash_id, label, label_len,
        &kp->sk, data, data_len
    );
}

#endif /* NEXTSSL_HAS_BEARSSL */
