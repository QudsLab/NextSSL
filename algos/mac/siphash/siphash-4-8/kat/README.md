# KAT provenance: siphash-4-8

The authors' repository ships vectors for SipHash-2-4 only. These 4-8 tags were produced with OpenSSL 3.5.7 `openssl mac -macopt c-rounds:4 -macopt d-rounds:8 -macopt size:N SipHash` (independent implementation, run in the nextssl-test image; key 00..0f, message 00..(n-1), n=0..63, 8 and 16 byte tags). The same OpenSSL procedure reproduces all 128 authors' SipHash-2-4 vectors, which validates the method. Script: kat_work/sip_ossl.sh.
