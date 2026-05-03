/* lms.c — LMS stateful hash-based signatures (SP 800-208 / RFC 8554 §5)
 *
 * Builds a single-level Merkle tree over 2^h LM-OTS public keys.
 * Tree storage layout (1-indexed, root = node 1):
 *   T[1]         = root (the public key)
 *   T[2]..T[3]   = level h-1 nodes
 *   ...
 *   T[2^h]..T[2^(h+1)-1] = leaf nodes (LM-OTS public keys K[q])
 */
#include "lms.h"
#include "sha256.h"
#include <string.h>
#include <stdlib.h>

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static void be32(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16);
    b[2]=(uint8_t)(v>>8);  b[3]=(uint8_t)v;
}

static uint32_t rd32(const uint8_t *b) {
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|(uint32_t)b[3];
}

/* Compute leaf K[q]: the LM-OTS public key for leaf index q */
static int compute_leaf(const lms_params_t *lp, const lmots_params_t *op,
                         const uint8_t I[16], uint32_t q,
                         const uint8_t seed[32], uint8_t *K)
{
    uint8_t *priv = (uint8_t *)malloc(op->p * op->n);
    if (!priv) return -1;
    if (lmots_keygen(op, I, q, seed, 32, priv) != 0) { free(priv); return -1; }
    int r = lmots_pubkey_from_privkey(op, I, q, priv, K);
    free(priv);
    return r;
    (void)lp;
}

/* Hash an internal node: H(I || u32(r) || D_INTR || left || right) */
static void hash_internal(const uint8_t I[16], uint32_t r,
                           const uint8_t *left, const uint8_t *right, uint32_t m,
                           uint8_t *out)
{
    uint8_t buf[16 + 4 + 2 + 64];
    memcpy(buf, I, 16);
    be32(buf + 16, r);
    buf[20] = 0x80; buf[21] = 0x01; /* D_INTR = 0x8001 */
    memcpy(buf + 22, left,  m);
    memcpy(buf + 22 + m, right, m);
    sha256(buf, 22 + 2 * m, out);
}

/* ── Key generation ──────────────────────────────────────────────────────── */

int lms_keygen(lms_type_t lms_type, lmots_type_t lmots_type,
               const uint8_t I[16], const uint8_t seed[32],
               lms_private_key_t *priv,
               uint8_t *pub, size_t *pub_len)
{
    const lms_params_t   *lp = lms_params_get(lms_type);
    const lmots_params_t *op = lmots_params_get(lmots_type);
    if (!lp || !op || !I || !seed || !priv || !pub || !pub_len) return -1;

    uint32_t num_leaves = 1u << lp->h;
    uint32_t num_nodes  = 2 * num_leaves; /* 1-indexed: nodes 1..2*num_leaves-1 */
    uint8_t *T = (uint8_t *)calloc(num_nodes * lp->m, 1);
    if (!T) return -1;

    /* Compute leaves: T[num_leaves + q] = K[q], 0-indexed as T[(num_leaves+q)*m] */
    for (uint32_t q = 0; q < num_leaves; q++) {
        if (compute_leaf(lp, op, I, q, seed, T + (num_leaves + q) * lp->m) != 0) {
            free(T); return -1;
        }
    }
    /* Compute internal nodes bottom-up */
    for (int32_t r = (int32_t)num_leaves - 1; r >= 1; r--) {
        hash_internal(I, (uint32_t)r,
                      T + (uint32_t)(2*r)   * lp->m,
                      T + (uint32_t)(2*r+1) * lp->m,
                      lp->m,
                      T + (uint32_t)r       * lp->m);
    }

    priv->lms_type   = lms_type;
    priv->lmots_type = lmots_type;
    memcpy(priv->I, I, 16);
    priv->q = 0;
    memcpy(priv->seed, seed, 32);
    priv->T = T;

    /* Public key: u32(lms_type) || u32(lmots_type) || I[16] || T[1] */
    size_t needed = 4 + 4 + 16 + lp->m;
    if (*pub_len < needed) { free(T); return -1; }
    be32(pub,       (uint32_t)lms_type);
    be32(pub + 4,   (uint32_t)lmots_type);
    memcpy(pub + 8,  I, 16);
    memcpy(pub + 24, T + lp->m, lp->m);   /* T[1] is at offset 1*m */
    *pub_len = needed;
    return 0;
}

void lms_private_key_free(lms_private_key_t *priv)
{
    if (priv && priv->T) { free(priv->T); priv->T = NULL; }
}

/* ── Sign ────────────────────────────────────────────────────────────────── */

int lms_sign(lms_private_key_t *priv,
             const uint8_t *msg, size_t msglen,
             uint8_t *sig, size_t *sig_len)
{
    if (!priv || !msg || !sig || !sig_len) return -1;
    const lms_params_t   *lp = lms_params_get(priv->lms_type);
    const lmots_params_t *op = lmots_params_get(priv->lmots_type);
    if (!lp || !op) return -1;

    uint32_t num_leaves = 1u << lp->h;
    if (priv->q >= num_leaves) return -1; /* key exhausted */

    uint32_t q = priv->q;

    /* Generate OTS private key for this leaf */
    uint8_t *ots_priv = (uint8_t *)malloc(op->p * op->n);
    if (!ots_priv) return -1;
    if (lmots_keygen(op, priv->I, q, priv->seed, 32, ots_priv) != 0) {
        free(ots_priv); return -1;
    }

    uint8_t *p = sig;
    /* u32(q) */
    be32(p, q); p += 4;
    /* u32(lmots_type) */
    be32(p, (uint32_t)priv->lmots_type); p += 4;

    /* OTS signature */
    size_t ots_sig_len = 0;
    if (lmots_sign(op, priv->I, q, ots_priv, msg, msglen,
                   p + 4, &ots_sig_len) != 0) {
        free(ots_priv); return -1;
    }
    /* Rewrite: lmots_sign already wrote typecode at p+4; we skip the outer
     * 4-byte type field for OTS sig inside LMS sig per RFC 8554 §5.4 */
    memmove(p, p + 4, ots_sig_len);
    p += ots_sig_len;
    free(ots_priv);

    /* u32(lms_type) */
    be32(p, (uint32_t)priv->lms_type); p += 4;

    /* Authentication path: sibling of leaf, ..., sibling of root child */
    uint32_t node_num = num_leaves + q;
    for (uint32_t i = 0; i < lp->h; i++) {
        uint32_t sibling = (node_num & 1) ? node_num - 1 : node_num + 1;
        memcpy(p, priv->T + sibling * lp->m, lp->m);
        p += lp->m;
        node_num >>= 1;
    }

    *sig_len = (size_t)(p - sig);
    priv->q++;  /* MUST increment after signature is complete */
    return 0;
}

/* ── Verify ──────────────────────────────────────────────────────────────── */

int lms_verify(const uint8_t *pub,  size_t pub_len,
               const uint8_t *msg,  size_t msglen,
               const uint8_t *sig,  size_t sig_len)
{
    if (!pub || !msg || !sig) return -1;
    if (pub_len < 4 + 4 + 16 + 32) return -1;
    if (sig_len < 4 + 4) return -1;

    lms_type_t   lms_type   = (lms_type_t)  rd32(pub);
    lmots_type_t lmots_type = (lmots_type_t)rd32(pub + 4);
    const uint8_t *I        = pub + 8;

    const lms_params_t   *lp = lms_params_get(lms_type);
    const lmots_params_t *op = lmots_params_get(lmots_type);
    if (!lp || !op) return -1;

    const uint8_t *root = pub + 24;

    const uint8_t *sp = sig;
    uint32_t q = rd32(sp); sp += 4;

    uint32_t num_leaves = 1u << lp->h;
    if (q >= num_leaves) return -1;

    /* Skip OTS typecode in sig */
    sp += 4;  /* lmots type in LMS sig */

    /* Recover OTS public key candidate Kc */
    uint8_t Kc[32];
    size_t ots_sig_len = 4 + 32 + op->p * op->n;
    /* lmots_verify expects sig to start with typecode */
    uint8_t *ots_sig = (uint8_t *)malloc(ots_sig_len);
    if (!ots_sig) return -1;
    be32(ots_sig, (uint32_t)lmots_type);
    memcpy(ots_sig + 4, sp, ots_sig_len - 4);
    int r = lmots_verify(op, I, q, ots_sig, ots_sig_len, msg, msglen, Kc);
    free(ots_sig);
    if (r != 0) return -1;
    sp += ots_sig_len - 4;

    /* Skip LMS type in sig */
    sp += 4;

    /* Recompute root from Kc + auth path */
    /* Leaf node: T[num_leaves+q] = H(I || u32(num_leaves+q) || D_LEAF || Kc) */
    uint8_t node[32];
    {
        uint8_t buf[16 + 4 + 2 + 32];
        memcpy(buf, I, 16);
        be32(buf + 16, num_leaves + q);
        buf[20] = 0x80; buf[21] = 0x82; /* D_LEAF = 0x8082 */
        memcpy(buf + 22, Kc, 32);
        sha256(buf, 22 + 32, node);
    }

    uint32_t node_num = num_leaves + q;
    for (uint32_t i = 0; i < lp->h; i++) {
        const uint8_t *sib = sp + i * lp->m;
        uint32_t parent = node_num >> 1;
        if (node_num & 1) {
            hash_internal(I, parent, sib, node, lp->m, node);
        } else {
            hash_internal(I, parent, node, sib, lp->m, node);
        }
        node_num >>= 1;
    }

    /* Compare computed root with stored root */
    return (memcmp(node, root, lp->m) == 0) ? 0 : -1;
}
