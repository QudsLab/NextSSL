#include "pow_legacy_alive.h"
#include <stdlib.h>
#include <string.h>
#include "../../../legacy/alive/md5/md5.h"
#include "../../../legacy/alive/sha1/sha1.h"
#include "../../../legacy/alive/ripemd160/ripemd160.h"
#include "../../../legacy/alive/whirlpool/whirlpool.h"
#include "../../../legacy/alive/nt_hash/nt.h"

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

int pow_hash_ripemd160(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < RIPEMD160_DIGEST_LENGTH) return -1;
    RIPEMD160_CTX rmd;
    ripemd160_init(&rmd);
    ripemd160_update(&rmd, msg, msg_len);
    if (nonce && nonce_len > 0) {
        ripemd160_update(&rmd, nonce, nonce_len);
    }
    ripemd160_final(out_hash, &rmd);
    return 0;
}

int pow_hash_whirlpool(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < WHIRLPOOL_DIGEST_LENGTH) return -1;
    WHIRLPOOL_CTX wp;
    whirlpool_init(&wp);
    whirlpool_update(&wp, msg, msg_len);
    if (nonce && nonce_len > 0) {
        whirlpool_update(&wp, nonce, nonce_len);
    }
    whirlpool_final(out_hash, &wp);
    return 0;
}

int pow_hash_nt(const uint8_t *msg, size_t msg_len, const uint8_t *nonce, size_t nonce_len, uint8_t *out_hash, size_t out_len, void *ctx) {
    if (out_len < NT_HASH_LENGTH) return -1;
    // NT Hash (NTLM) typically hashes the password (UTF-16LE). 
    // Here we treat the input (msg + nonce) as the data to hash directly using the underlying MD4.
    // We use a temporary buffer to combine msg and nonce if needed, or update context if supported.
    // But nt_hash_unicode takes a single buffer.
    
    // Combine msg and nonce
    size_t total_len = msg_len + nonce_len;
    uint8_t *buffer = (uint8_t *)malloc(total_len);
    if (!buffer) return -1;
    
    memcpy(buffer, msg, msg_len);
    if (nonce && nonce_len > 0) {
        memcpy(buffer + msg_len, nonce, nonce_len);
    }
    
    nt_hash_unicode(buffer, total_len, out_hash);
    
    free(buffer);
    return 0;
}
