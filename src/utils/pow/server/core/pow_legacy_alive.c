#include "pow_legacy_alive.h"
#include "../../../legacy/alive/md5/md5.h"
#include "../../../legacy/alive/sha1/sha1.h"

int pow_hash_md5(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < MD5_DIGEST_LENGTH) return -1;
    MD5_CTX md5;
    md5_init(&md5);
    md5_update(&md5, msg, msg_len);
    if (nonce && nonce_len > 0) {
        md5_update(&md5, nonce, nonce_len);
    }
    md5_final(out_hash, &md5);
    return 0;
}

int pow_hash_sha1(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < SHA1_DIGEST_LENGTH) return -1;
    SHA1_CTX sha1;
    sha1_init(&sha1);
    sha1_update(&sha1, msg, msg_len);
    if (nonce && nonce_len > 0) {
        sha1_update(&sha1, nonce, nonce_len);
    }
    sha1_final(out_hash, &sha1);
    return 0;
}
