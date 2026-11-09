# KAT provenance: siphash-2-4

Expected tags: the SipHash authors' own vectors `vectors_sip64` / `vectors_sip128` in `vectors.h` of veorq/SipHash @ 32d067603b93b47828700880649198e0bfbbcffa (sha256 108162d8cb5f9cad76ca8faba2bc1cecbb875b48880fc6e1116a88c1343c2581): key = 00..0f, message = 00..(n-1), n = 0..63, 8-byte and 16-byte tags. They were additionally cross-checked against OpenSSL 3.5 EVP_MAC SipHash (independent implementation): all 128 agree.
