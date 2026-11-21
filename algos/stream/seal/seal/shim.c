/* Shim (not crypto): one-shot wrapper over seal_init() + seal(). Nonce = the 32 bit SEAL position index n (4 bytes, big endian).
 * Upstream seal() produces 1024 words (4096 bytes) for one n; the words are serialised little endian and XORed into data.
 * data may be at most 4096 bytes (one n). Key = the 160 bit SEAL key (20 bytes). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct SealKey;
int seal_init(unsigned char *key, struct SealKey **ks);
int seal(struct SealKey *key, unsigned int in, unsigned int *out);
#undef long

int shim_apply(const unsigned char *key, unsigned long keylen, const unsigned char *nonce, unsigned long noncelen,
               unsigned char *data, unsigned long len) {
    unsigned char kb[20];
    struct SealKey *ks = NULL;
    unsigned int w[1024];
    unsigned long i;
    unsigned int n;
    int rc = -1;
    if (keylen != 20 || noncelen != 4 || len > 4096) return -1;
    memcpy(kb, key, 20);
    n = ((unsigned int)nonce[0] << 24) | ((unsigned int)nonce[1] << 16) | ((unsigned int)nonce[2] << 8) | (unsigned int)nonce[3];
    if (seal_init(kb, &ks) != 0 || ks == NULL) goto done;
    if (seal(ks, n, w) != 0) goto done;
    for (i = 0; i < len; i++) data[i] ^= (unsigned char)(w[i / 4] >> (8 * (i % 4)));
    rc = 0;
done:
    if (ks != NULL) {
        memset(ks, 0, (520 + 265 + 20) * sizeof(unsigned int));
        free(ks);
    }
    memset(kb, 0, sizeof(kb));
    memset(w, 0, sizeof(w));
    return rc;
}
