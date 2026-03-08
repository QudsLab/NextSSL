/* pow_protocol.h — PoW algorithm identifier enum used by the server-side
 * complexity estimation layer (calc_interface.h / calc_*.c).
 */
#ifndef POW_PROTOCOL_H
#define POW_PROTOCOL_H

typedef enum {
    POW_ALGO_UNKNOWN    = 0,
    POW_ALGO_SHA224,
    POW_ALGO_SHA256,
    POW_ALGO_SHA512,
    POW_ALGO_BLAKE3,
    POW_ALGO_BLAKE2B,
    POW_ALGO_BLAKE2S,
    POW_ALGO_SHA3_224,
    POW_ALGO_SHA3_256,
    POW_ALGO_SHA3_384,
    POW_ALGO_SHA3_512,
    POW_ALGO_KECCAK_256,
    POW_ALGO_SHAKE128,
    POW_ALGO_SHAKE256,
    POW_ALGO_ARGON2ID,
    POW_ALGO_ARGON2I,
    POW_ALGO_ARGON2D,
    POW_ALGO_MD5,
    POW_ALGO_SHA1,
    POW_ALGO_RIPEMD160,
    POW_ALGO_WHIRLPOOL,
    POW_ALGO_NT,
    POW_ALGO_MD2,
    POW_ALGO_MD4,
    POW_ALGO_SHA0,
    POW_ALGO_HAS160,
    POW_ALGO_RIPEMD128,
    POW_ALGO_RIPEMD256,
    POW_ALGO_RIPEMD320,
} PoWAlgorithm;

#endif /* POW_PROTOCOL_H */
