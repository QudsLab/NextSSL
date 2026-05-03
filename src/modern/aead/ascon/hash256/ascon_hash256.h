/* ascon_hash256.h — Ascon-Hash256 (SP 800-232) */
#ifndef NEXTSSL_ASCON_HASH256_H
#define NEXTSSL_ASCON_HASH256_H

#include <stdint.h>
#include <stddef.h>

#define ASCON_HASH256_DIGEST_LEN 32

/* One-shot hash.  out must be ASCON_HASH256_DIGEST_LEN bytes. */
void ascon_hash256(const uint8_t *msg, size_t msglen, uint8_t out[ASCON_HASH256_DIGEST_LEN]);

#endif /* NEXTSSL_ASCON_HASH256_H */
