#include "legacy_alive.h"
#include "../../legacy/alive/md5/md5.h"
#include "../../legacy/alive/sha1/sha1.h"
#include "../../legacy/alive/ripemd160/ripemd160.h"
#include "../../legacy/alive/whirlpool/whirlpool.h"
#include "../../legacy/alive/nt_hash/nt.h"
#include "../../legacy/alive/aes_ecb/aes_ecb.h"

int leyline_md5(const uint8_t *msg, size_t len, uint8_t *out) {
    md5_hash(msg, len, out);
    return 0;
}

int leyline_sha1(const uint8_t *msg, size_t len, uint8_t *out) {
    sha1_hash(msg, len, out);
    return 0;
}

int leyline_ripemd160(const uint8_t *msg, size_t len, uint8_t *out) {
    ripemd160_hash(msg, len, out);
    return 0;
}

int leyline_whirlpool(const uint8_t *msg, size_t len, uint8_t *out) {
    whirlpool_hash(msg, len, out);
    return 0;
}

int leyline_nt_hash(const char *password, uint8_t *out) {
    nt_hash(password, out);
    return 0;
}

int leyline_aes_ecb_encrypt(const uint8_t* key, const uint8_t* pntxt, size_t ptextLen, uint8_t* crtxt) {
    AES_ECB_encrypt(key, pntxt, ptextLen, crtxt);
    return 0;
}
