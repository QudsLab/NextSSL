/* dispatcher.c — maps canonical algorithm names to pow_adapter_t instances.
 *
 * All 41 algorithms are registered unconditionally.
 * Names are in canonical hyphen-form matching the hash registry.
 */
#include "dispatcher.h"
#include <string.h>

/* -------------------------------------------------------------------------
 * Forward declarations — one getter per adapter file
 * ------------------------------------------------------------------------- */

/* fast/ */
const pow_adapter_t *pow_adapter_sha224(void);
const pow_adapter_t *pow_adapter_sha256(void);
const pow_adapter_t *pow_adapter_sha384(void);
const pow_adapter_t *pow_adapter_sha512(void);
const pow_adapter_t *pow_adapter_sha512_224(void);
const pow_adapter_t *pow_adapter_sha512_256(void);

/* blake/ */
const pow_adapter_t *pow_adapter_blake2b(void);
const pow_adapter_t *pow_adapter_blake2s(void);
const pow_adapter_t *pow_adapter_blake3(void);

/* sponge/ */
const pow_adapter_t *pow_adapter_sha3_224(void);
const pow_adapter_t *pow_adapter_sha3_256(void);
const pow_adapter_t *pow_adapter_sha3_384(void);
const pow_adapter_t *pow_adapter_sha3_512(void);
const pow_adapter_t *pow_adapter_keccak256(void);
const pow_adapter_t *pow_adapter_kmac128(void);
const pow_adapter_t *pow_adapter_kmac256(void);

/* sponge_xof/ */
const pow_adapter_t *pow_adapter_shake128(void);
const pow_adapter_t *pow_adapter_shake256(void);

/* memory_hard/ */
const pow_adapter_t *pow_adapter_argon2id(void);
const pow_adapter_t *pow_adapter_argon2i(void);
const pow_adapter_t *pow_adapter_argon2d(void);
const pow_adapter_t *pow_adapter_scrypt(void);
const pow_adapter_t *pow_adapter_yescrypt(void);
const pow_adapter_t *pow_adapter_catena(void);
const pow_adapter_t *pow_adapter_lyra2(void);
const pow_adapter_t *pow_adapter_bcrypt(void);

/* skein/ */
const pow_adapter_t *pow_adapter_skein256(void);
const pow_adapter_t *pow_adapter_skein512(void);
const pow_adapter_t *pow_adapter_skein1024(void);

/* legacy/ */
const pow_adapter_t *pow_adapter_sha1(void);
const pow_adapter_t *pow_adapter_sha0(void);
const pow_adapter_t *pow_adapter_md5(void);
const pow_adapter_t *pow_adapter_md4(void);
const pow_adapter_t *pow_adapter_md2(void);
const pow_adapter_t *pow_adapter_nt(void);
const pow_adapter_t *pow_adapter_ripemd128(void);
const pow_adapter_t *pow_adapter_ripemd160(void);
const pow_adapter_t *pow_adapter_ripemd256(void);
const pow_adapter_t *pow_adapter_ripemd320(void);
const pow_adapter_t *pow_adapter_whirlpool(void);
const pow_adapter_t *pow_adapter_has160(void);
const pow_adapter_t *pow_adapter_tiger(void);
const pow_adapter_t *pow_adapter_sm3(void);

/* -------------------------------------------------------------------------
 * Dispatch table — 41 entries
 * ------------------------------------------------------------------------- */
typedef const pow_adapter_t *(*adapter_getter_t)(void);

static const struct { const char *name; adapter_getter_t get; } s_table[] = {
    /* fast */
    { "sha224",      pow_adapter_sha224      },
    { "sha256",      pow_adapter_sha256      },
    { "sha384",      pow_adapter_sha384      },
    { "sha512",      pow_adapter_sha512      },
    { "sha512-224",  pow_adapter_sha512_224  },
    { "sha512-256",  pow_adapter_sha512_256  },
    /* blake */
    { "blake2b",     pow_adapter_blake2b     },
    { "blake2s",     pow_adapter_blake2s     },
    { "blake3",      pow_adapter_blake3      },
    /* sponge */
    { "sha3-224",    pow_adapter_sha3_224    },
    { "sha3-256",    pow_adapter_sha3_256    },
    { "sha3-384",    pow_adapter_sha3_384    },
    { "sha3-512",    pow_adapter_sha3_512    },
    { "keccak256",   pow_adapter_keccak256   },
    { "kmac128",     pow_adapter_kmac128     },
    { "kmac256",     pow_adapter_kmac256     },
    /* sponge_xof */
    { "shake128",    pow_adapter_shake128    },
    { "shake256",    pow_adapter_shake256    },
    /* memory_hard */
    { "argon2id",    pow_adapter_argon2id    },
    { "argon2i",     pow_adapter_argon2i     },
    { "argon2d",     pow_adapter_argon2d     },
    { "scrypt",      pow_adapter_scrypt      },
    { "yescrypt",    pow_adapter_yescrypt    },
    { "catena",      pow_adapter_catena      },
    { "lyra2",       pow_adapter_lyra2       },
    { "bcrypt",      pow_adapter_bcrypt      },
    /* skein */
    { "skein256",    pow_adapter_skein256    },
    { "skein512",    pow_adapter_skein512    },
    { "skein1024",   pow_adapter_skein1024   },
    /* legacy */
    { "sha1",        pow_adapter_sha1        },
    { "sha0",        pow_adapter_sha0        },
    { "md5",         pow_adapter_md5         },
    { "md4",         pow_adapter_md4         },
    { "md2",         pow_adapter_md2         },
    { "nt",          pow_adapter_nt          },
    { "ripemd128",   pow_adapter_ripemd128   },
    { "ripemd160",   pow_adapter_ripemd160   },
    { "ripemd256",   pow_adapter_ripemd256   },
    { "ripemd320",   pow_adapter_ripemd320   },
    { "whirlpool",   pow_adapter_whirlpool   },
    { "has160",      pow_adapter_has160      },
    { "tiger",       pow_adapter_tiger       },
    { "sm3",         pow_adapter_sm3         },
    /* aliases */
    { "nthash",      pow_adapter_nt          },
    { "sha512/224",  pow_adapter_sha512_224  },
    { "sha512/256",  pow_adapter_sha512_256  },
};

#define TABLE_SIZE (sizeof(s_table) / sizeof(s_table[0]))

/* -------------------------------------------------------------------------
 * pow_adapter_get — public API
 * ------------------------------------------------------------------------- */
const pow_adapter_t *pow_adapter_get(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < TABLE_SIZE; i++) {
        if (strcmp(s_table[i].name, name) == 0)
            return s_table[i].get();
    }
    return NULL;
}
