/* shake256.h — SHAKE-256 XOF */
#ifndef SHAKE256_H
#define SHAKE256_H
#include "shake.h"
static inline void shake256_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t len) {
    shake_squeeze(ctx, out, len);
}
#endif /* SHAKE256_H */
