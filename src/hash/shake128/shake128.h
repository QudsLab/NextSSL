/* shake128.h — SHAKE-128 XOF */
#ifndef SHAKE128_H
#define SHAKE128_H
#include "shake.h"
static inline void shake128_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t len) {
    shake_squeeze(ctx, out, len);
}
#endif /* SHAKE128_H */
