#ifndef AES_INTERNAL_H
#define AES_INTERNAL_H

#include "aes_common.h"

/* Internal Constants */
#define BLOCKSIZE  16
#define KEYSIZE    AES_KEYLENGTH
#define Nb         (BLOCKSIZE / 4)
#define Nk         (KEYSIZE / 4)
#define ROUNDS     (Nk + 6)
#define HB         (BLOCKSIZE / 2)
#define LAST       (BLOCKSIZE - 1)
#define MIDST      (LAST / 2)

/* Internal Types */
typedef uint8_t block_t[BLOCKSIZE];
typedef uint8_t state_t[Nb][4];
typedef void (*fmix_t)( const block_t, block_t );
typedef void (*fdouble_t)( block_t );
typedef size_t  count_t;

/* Macros */
#define COPYDWORD(x, y)   *(int32_t*) &y  = *(int32_t*) &x
#define XOR32BITS(x, y)   *(int32_t*) &y ^= *(int32_t*) &x

#define AES_setkey(key)   KeyExpansion(key)

#define BURN(key)           memset( key, 0, sizeof(block_t) * (ROUNDS + 1) ) /* Approximation of RoundKey size clearing */
#define SABOTAGE(buf, len)  memset( buf, 0, len )

/* Helper function prototypes */
void KeyExpansion(const uint8_t* key);
void rijndaelEncrypt(const block_t input, block_t output);
void rijndaelDecrypt(const block_t input, block_t output);

void xorBlock(const block_t src, block_t dest);
void mixThenXor(fmix_t mix, const block_t B, block_t f, const uint8_t* X, uint8_t n, uint8_t* Y);
void xMac(const void* data, const size_t dataSize, const block_t seed, fmix_t mix, block_t result);
char padBlock(const uint8_t len, block_t block);

/* Endian-handling helpers */
void xorBEint(uint8_t* buff, size_t num, uint8_t pos);
void copyLint(block_t block, size_t num, uint8_t pos);
void incBlock(block_t block, uint8_t index);

/* GF(2^128) arithmetic */
void doubleBblock(block_t array);
void doubleLblock(block_t array);
void divideBblock(block_t array);
void divideLblock(block_t array);
void mulGF128(const block_t x, block_t y);
void dotGF128(const block_t x, block_t y);

/* CMAC/OMAC helpers */
void cMac(const block_t K1, const block_t K2, const void* data, const size_t dataSize, block_t mac);
void getSubkeys(fdouble_t gfdouble, const char quad, const uint8_t* key, block_t D, block_t Q);

/* Safe memory compare */
uint8_t memcmp_s(const void* src, const void* dest, const uint8_t len);

/* Accessor to burn RoundKey */
void AES_burn(void);

#endif /* AES_INTERNAL_H */
