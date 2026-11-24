/* NextSSL compat (not upstream): force-included in this crate's C++ build; see upstream.patches.
 * The upstream reports a wrong tag by throwing from MonkeyWrap::unwrap and catching it in
 * crypto_aead_decrypt. The wasi libc++ used for wasm32 has no exception support (a throw aborts),
 * so on wasm32 only, unwrap records the mismatch and returns, and crypto_aead_decrypt returns -1
 * before it copies any plaintext, as the catch does. Every other target keeps the throw unchanged. */
#ifndef NEXTSSL_KETJE_TAG_H
#define NEXTSSL_KETJE_TAG_H
#if defined(__wasm__)
inline bool &nextssl_ketje_tag_failed() {
    static bool failed = false;
    return failed;
}
#define NEXTSSL_KETJE_TAG_MISMATCH(e)              do {                                               nextssl_ketje_tag_failed() = true;             return BitString();                        } while (0)
#define NEXTSSL_KETJE_TAG_FAILED()     (nextssl_ketje_tag_failed() ? (nextssl_ketje_tag_failed() = false, true) : false)
#else
#define NEXTSSL_KETJE_TAG_MISMATCH(e) throw e
#define NEXTSSL_KETJE_TAG_FAILED() false
#endif
#endif
