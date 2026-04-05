/*
 * Catena-local blake2.h — prefixes all blake2b symbols with catena_
 * to avoid linker conflicts with argon2's blake2b.
 */
#ifndef CATENA_BLAKE2_H
#define CATENA_BLAKE2_H

#include <stdint.h>
#include <limits.h>
#include <string.h>

/* Symbol prefixing to avoid clashing with argon2's blake2b */
#define blake2b_init        catena_blake2b_init
#define blake2b_init_key    catena_blake2b_init_key
#define blake2b_init_param  catena_blake2b_init_param
#define blake2b_update      catena_blake2b_update
#define blake2b_final       catena_blake2b_final
#define blake2b             catena_blake2b
#define blake2b_compress    catena_blake2b_compress

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES    = 128,
    BLAKE2B_OUTBYTES      = 64,
    BLAKE2B_KEYBYTES      = 64,
    BLAKE2B_SALTBYTES     = 16,
    BLAKE2B_PERSONALBYTES = 16
};

#pragma pack(push, 1)
typedef struct __catena_blake2b_param {
    uint8_t  digest_length;
    uint8_t  key_length;
    uint8_t  fanout;
    uint8_t  depth;
    uint32_t leaf_length;
    uint64_t node_offset;
    uint8_t  node_depth;
    uint8_t  inner_length;
    uint8_t  reserved[14];
    uint8_t  salt[BLAKE2B_SALTBYTES];
    uint8_t  personal[BLAKE2B_PERSONALBYTES];
} blake2b_param;
#pragma pack(pop)

typedef struct __catena_blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[2 * BLAKE2B_BLOCKBYTES];
    unsigned buflen;
    unsigned outlen;
    uint8_t  last_node;
} blake2b_state;

enum {
    catena_blake2_size_check_0 = 1 / !!(CHAR_BIT == 8),
    catena_blake2_size_check_2 =
        1 / !!(sizeof(blake2b_param) == sizeof(uint64_t) * CHAR_BIT)
};

int blake2b_init(blake2b_state *S, const uint8_t outlen);
int blake2b_init_key(blake2b_state *S, const uint8_t outlen,
                     const void *key, const uint8_t keylen);
int blake2b_init_param(blake2b_state *S, const blake2b_param *P);
int blake2b_update(blake2b_state *S, const uint8_t *in, uint64_t inlen);
int blake2b_final(blake2b_state *S, uint8_t *out, uint8_t outlen);
int blake2b(uint8_t *out, const void *in, const void *key,
            const uint8_t outlen, const uint64_t inlen, uint8_t keylen);

#endif /* CATENA_BLAKE2_H */
