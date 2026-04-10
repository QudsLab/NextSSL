/* plain_hash_adapter.c — Generic plain hash adapter implementation (Plan 40002)
 *
 * All 34 plain hash algorithms share one implementation.
 * The per-algorithm constructors are single-line wrappers.
 *
 * impl layout:
 *   plain_hash_impl_t {
 *       const hash_ops_t *ops;          ← points to shared vtable (not owned)
 *       uint8_t ctx[HASH_OPS_CTX_MAX];  ← per-instance streaming context
 *   }
 */
#include "plain_hash_adapter.h"
#include "../interface/hash_registry.h"   /* all extern hash_ops_t instances */
#include "../../common/secure_zero.h"
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal impl struct
 * -------------------------------------------------------------------------*/
typedef struct {
    const hash_ops_t *ops;
    uint8_t           ctx[HASH_OPS_CTX_MAX];
} plain_hash_impl_t;

/* -------------------------------------------------------------------------
 * Function pointer implementations
 * -------------------------------------------------------------------------*/
static int plain_hash_fn(void *impl,
                         const uint8_t *data, size_t data_len,
                         uint8_t *out, size_t out_len)
{
    plain_hash_impl_t *p = (plain_hash_impl_t *)impl;
    (void)out_len;  /* output buffer must be >= ops->digest_size */
    p->ops->init(p->ctx);
    p->ops->update(p->ctx, data, data_len);
    p->ops->final(p->ctx, out);
    return 0;
}

static void plain_init_fn(void *impl)
{
    plain_hash_impl_t *p = (plain_hash_impl_t *)impl;
    p->ops->init(p->ctx);
}

static void plain_update_fn(void *impl, const uint8_t *data, size_t len)
{
    plain_hash_impl_t *p = (plain_hash_impl_t *)impl;
    p->ops->update(p->ctx, data, len);
}

static void plain_final_fn(void *impl, uint8_t *out, size_t out_len)
{
    plain_hash_impl_t *p = (plain_hash_impl_t *)impl;
    (void)out_len;
    p->ops->final(p->ctx, out);
    /* wipe context state after extraction */
    secure_zero(p->ctx, sizeof(p->ctx));
}

static void plain_destroy_fn(void *impl)
{
    plain_hash_impl_t *p = (plain_hash_impl_t *)impl;
    secure_zero(p->ctx, sizeof(p->ctx));
    free(p);
}

/* -------------------------------------------------------------------------
 * Generic constructor
 * -------------------------------------------------------------------------*/
hash_adapter_t *plain_hash_adapter_create(const hash_ops_t *ops)
{
    if (!ops) return NULL;

    hash_adapter_t *a = (hash_adapter_t *)malloc(sizeof(hash_adapter_t));
    if (!a) return NULL;

    plain_hash_impl_t *impl = (plain_hash_impl_t *)malloc(sizeof(plain_hash_impl_t));
    if (!impl) { free(a); return NULL; }

    impl->ops = ops;
    memset(impl->ctx, 0, sizeof(impl->ctx));

    a->impl        = impl;
    a->digest_size = ops->digest_size;
    a->block_size  = ops->block_size;
    a->hash_fn     = plain_hash_fn;
    a->init_fn     = plain_init_fn;
    a->update_fn   = plain_update_fn;
    a->final_fn    = plain_final_fn;
    a->destroy_fn  = plain_destroy_fn;
    return a;
}

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Blake (3)
 * -------------------------------------------------------------------------*/
hash_adapter_t *blake2b_adapter_create(void)  { return plain_hash_adapter_create(&blake2b_ops); }
hash_adapter_t *blake2s_adapter_create(void)  { return plain_hash_adapter_create(&blake2s_ops); }
hash_adapter_t *blake3_adapter_create(void)   { return plain_hash_adapter_create(&blake3_ops);  }

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Fast / SHA-2 (7)
 * -------------------------------------------------------------------------*/
hash_adapter_t *sha224_adapter_create(void)     { return plain_hash_adapter_create(&sha224_ops);     }
hash_adapter_t *sha256_adapter_create(void)     { return plain_hash_adapter_create(&sha256_ops);     }
hash_adapter_t *sha384_adapter_create(void)     { return plain_hash_adapter_create(&sha384_ops);     }
hash_adapter_t *sha512_adapter_create(void)     { return plain_hash_adapter_create(&sha512_ops);     }
hash_adapter_t *sha512_224_adapter_create(void) { return plain_hash_adapter_create(&sha512_224_ops); }
hash_adapter_t *sha512_256_adapter_create(void) { return plain_hash_adapter_create(&sha512_256_ops); }
hash_adapter_t *sm3_adapter_create(void)        { return plain_hash_adapter_create(&sm3_ops);        }

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Sponge / SHA-3 (5)
 * -------------------------------------------------------------------------*/
hash_adapter_t *sha3_224_adapter_create(void)  { return plain_hash_adapter_create(&sha3_224_ops);  }
hash_adapter_t *sha3_256_adapter_create(void)  { return plain_hash_adapter_create(&sha3_256_ops);  }
hash_adapter_t *sha3_384_adapter_create(void)  { return plain_hash_adapter_create(&sha3_384_ops);  }
hash_adapter_t *sha3_512_adapter_create(void)  { return plain_hash_adapter_create(&sha3_512_ops);  }
hash_adapter_t *keccak256_adapter_create(void) { return plain_hash_adapter_create(&keccak256_ops); }

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — XOF (2)
 * -------------------------------------------------------------------------*/
hash_adapter_t *shake128_adapter_create(void) { return plain_hash_adapter_create(&shake128_ops); }
hash_adapter_t *shake256_adapter_create(void) { return plain_hash_adapter_create(&shake256_ops); }

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Skein (3)
 * -------------------------------------------------------------------------*/
hash_adapter_t *skein256_adapter_create(void)  { return plain_hash_adapter_create(&skein256_ops);  }
hash_adapter_t *skein512_adapter_create(void)  { return plain_hash_adapter_create(&skein512_ops);  }
hash_adapter_t *skein1024_adapter_create(void) { return plain_hash_adapter_create(&skein1024_ops); }

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — KMAC (2)
 * -------------------------------------------------------------------------*/
hash_adapter_t *kmac128_adapter_create(void) { return plain_hash_adapter_create(&kmac128_ops); }
hash_adapter_t *kmac256_adapter_create(void) { return plain_hash_adapter_create(&kmac256_ops); }

/* -------------------------------------------------------------------------
 * Per-algorithm typed constructors — Legacy / Weak ⚠️ (12)
 * -------------------------------------------------------------------------*/
hash_adapter_t *has160_adapter_create(void)    { return plain_hash_adapter_create(&has160_ops);    }
hash_adapter_t *md2_adapter_create(void)       { return plain_hash_adapter_create(&md2_ops);       }
hash_adapter_t *md4_adapter_create(void)       { return plain_hash_adapter_create(&md4_ops);       }
hash_adapter_t *md5_adapter_create(void)       { return plain_hash_adapter_create(&md5_ops);       }
hash_adapter_t *nt_adapter_create(void)        { return plain_hash_adapter_create(&nt_ops);        }
hash_adapter_t *ripemd128_adapter_create(void) { return plain_hash_adapter_create(&ripemd128_ops); }
hash_adapter_t *ripemd160_adapter_create(void) { return plain_hash_adapter_create(&ripemd160_ops); }
hash_adapter_t *ripemd256_adapter_create(void) { return plain_hash_adapter_create(&ripemd256_ops); }
hash_adapter_t *ripemd320_adapter_create(void) { return plain_hash_adapter_create(&ripemd320_ops); }
hash_adapter_t *sha0_adapter_create(void)      { return plain_hash_adapter_create(&sha0_ops);      }
hash_adapter_t *sha1_adapter_create(void)      { return plain_hash_adapter_create(&sha1_ops);      }
hash_adapter_t *whirlpool_adapter_create(void) { return plain_hash_adapter_create(&whirlpool_ops); }
