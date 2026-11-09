/* Generated shim (not crypto): extern "C" keystream entry that only calls Crypto++ HC128. */
#include <string.h>
#include "hc128.h"

extern "C" int shim_stream(unsigned char *out, unsigned long long len, const unsigned char *nonce,
                           const unsigned char *key) {
    try {
        CryptoPP::HC128::Encryption e;
        e.SetKeyWithIV(key, 16, nonce, 16);
        memset(out, 0, (size_t)len);
        e.ProcessData(out, out, (size_t)len);
        return 0;
    } catch (...) {
        return -1;
    }
}
