/* hash_registry.c — Seed Hash Registry Implementation (Plan 404)
 *
 * Flat table of all 41+ hash algorithm vtables available to the seed system.
 * Implements hash_lookup_by_name() by linear scan of HASH_REGISTRY[].
 *
 * The actual vtable objects (sha256_ops etc.) are defined in
 * src/hash/interface/hash_registry.c — linked once, referenced everywhere.
 */
#include "hash_registry.h"
#include "../../hash/interface/hash_registry.h"  /* hash_lookup() + all extern ops */
#include <string.h>

/* -------------------------------------------------------------------------
 * HASH_REGISTRY — all 41+ seed-usable algorithms indexed by name
 * -------------------------------------------------------------------------*/
const hash_registry_entry_t HASH_REGISTRY[] = {
    /* ---- Blake (3) ------------------------------------------ */
    { "blake2b",     &blake2b_ops,     HASH_CAT_BLAKE },
    { "blake2s",     &blake2s_ops,     HASH_CAT_BLAKE },
    { "blake3",      &blake3_ops,      HASH_CAT_BLAKE },

    /* ---- Fast / SHA-2 (7) ------------------------------------ */
    { "sha224",      &sha224_ops,      HASH_CAT_FAST  },
    { "sha256",      &sha256_ops,      HASH_CAT_FAST  },
    { "sha384",      &sha384_ops,      HASH_CAT_FAST  },
    { "sha512",      &sha512_ops,      HASH_CAT_FAST  },
    { "sha512-224",  &sha512_224_ops,  HASH_CAT_FAST  },
    { "sha512-256",  &sha512_256_ops,  HASH_CAT_FAST  },
    { "sm3",         &sm3_ops,         HASH_CAT_FAST  },

    /* ---- Legacy / Weak (12) ---------------------------------- */
    { "has160",      &has160_ops,      HASH_CAT_LEGACY },
    { "md2",         &md2_ops,         HASH_CAT_LEGACY },
    { "md4",         &md4_ops,         HASH_CAT_LEGACY },
    { "md5",         &md5_ops,         HASH_CAT_LEGACY },
    { "nt",          &nt_ops,          HASH_CAT_LEGACY },
    { "ripemd128",   &ripemd128_ops,   HASH_CAT_LEGACY },
    { "ripemd160",   &ripemd160_ops,   HASH_CAT_LEGACY },
    { "ripemd256",   &ripemd256_ops,   HASH_CAT_LEGACY },
    { "ripemd320",   &ripemd320_ops,   HASH_CAT_LEGACY },
    { "sha0",        &sha0_ops,        HASH_CAT_LEGACY },
    { "sha1",        &sha1_ops,        HASH_CAT_LEGACY },
    { "whirlpool",   &whirlpool_ops,   HASH_CAT_LEGACY },

    /* ---- Memory-Hard (8) ------------------------------------- */
    { "argon2",      &argon2_ops,      HASH_CAT_MEMORY_HARD },
    { "argon2d",     &argon2d_ops,     HASH_CAT_MEMORY_HARD },
    { "argon2i",     &argon2i_ops,     HASH_CAT_MEMORY_HARD },
    { "argon2id",    &argon2id_ops,    HASH_CAT_MEMORY_HARD },
    { "bcrypt",      &bcrypt_ops,      HASH_CAT_MEMORY_HARD },
    { "catena",      &catena_ops,      HASH_CAT_MEMORY_HARD },
    { "lyra2",       &lyra2_ops,       HASH_CAT_MEMORY_HARD },
    { "scrypt",      &scrypt_ops,      HASH_CAT_MEMORY_HARD },
    { "yescrypt",    &yescrypt_ops,    HASH_CAT_MEMORY_HARD },
    { "balloon",     &balloon_ops,     HASH_CAT_MEMORY_HARD },
    { "pomelo",      &pomelo_ops,      HASH_CAT_MEMORY_HARD },
    { "makwa",       &makwa_ops,       HASH_CAT_MEMORY_HARD },

    /* ---- Sponge / SHA-3 (5) ---------------------------------- */
    { "keccak256",   &keccak256_ops,   HASH_CAT_SPONGE },
    { "sha3-224",    &sha3_224_ops,    HASH_CAT_SPONGE },
    { "sha3-256",    &sha3_256_ops,    HASH_CAT_SPONGE },
    { "sha3-384",    &sha3_384_ops,    HASH_CAT_SPONGE },
    { "sha3-512",    &sha3_512_ops,    HASH_CAT_SPONGE },

    /* ---- XOF (2) --------------------------------------------- */
    { "shake128",    &shake128_ops,    HASH_CAT_XOF },
    { "shake256",    &shake256_ops,    HASH_CAT_XOF },

    /* ---- Skein / Threefish (3) ------------------------------- */
    { "skein256",    &skein256_ops,    HASH_CAT_SKEIN },
    { "skein512",    &skein512_ops,    HASH_CAT_SKEIN },
    { "skein1024",   &skein1024_ops,   HASH_CAT_SKEIN },

    /* ---- KMAC (2) -------------------------------------------- */
    { "kmac128",     &kmac128_ops,     HASH_CAT_KMAC },
    { "kmac256",     &kmac256_ops,     HASH_CAT_KMAC },
};

const size_t HASH_REGISTRY_SIZE =
    sizeof(HASH_REGISTRY) / sizeof(HASH_REGISTRY[0]);

/* -------------------------------------------------------------------------
 * hash_lookup_by_name — find algorithm by name
 * -------------------------------------------------------------------------*/
const hash_ops_t *hash_lookup_by_name(const char *algo_name)
{
    size_t i;

    if (!algo_name) {
        return NULL;
    }

    /* Linear scan — table is small enough that hashing adds no benefit */
    for (i = 0; i < HASH_REGISTRY_SIZE; i++) {
        if (strcmp(HASH_REGISTRY[i].name, algo_name) == 0) {
            return HASH_REGISTRY[i].ops;
        }
    }

    /* Fall back to the main hash registry for any algorithm registered
     * at runtime (e.g. via hash_register()) that isn't in the static table. */
    return hash_lookup(algo_name);
}
