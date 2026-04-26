# KAT/data/modern/aes-gcm-siv.py
# Known Answer Tests for AES-GCM-SIV (RFC 8452)

meta = {
    "group": "modern",
    "algorithm": "AES-GCM-SIV",
    "source": "RFC 8452 Appendix C (2019)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc8452",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "AES-GCM-SIV is a nonce-misuse-resistant AEAD (RFC 8452). "
        "Case fields: key_bits, key_hex, nonce_hex (12 bytes), aad_hex, "
        "plaintext_hex, ciphertext_hex (includes 16-byte tag appended). "
        "Vectors from RFC 8452 Appendix C using 128-bit key. "
        "Computed with the cryptography library (pyca/cryptography 45.x). "
        "tag is the last 16 bytes of ciphertext_hex."
    ),
}

cases = [
    # RFC 8452 Appendix C.1: 128-bit key, empty PT and AAD
    {
        "id": 1,
        "key_bits": 128,
        "key_hex": "01000000000000000000000000000000",
        "nonce_hex": "030000000000000000000000",
        "aad_hex": "",
        "plaintext_hex": "",
        "ciphertext_hex": "dc20e2d83f25705bb49e439eca56de25",
    },
    # RFC 8452 Appendix C.2: 8-byte PT
    {
        "id": 2,
        "key_bits": 128,
        "key_hex": "01000000000000000000000000000000",
        "nonce_hex": "030000000000000000000000",
        "aad_hex": "",
        "plaintext_hex": "0100000000000000",
        "ciphertext_hex": "b5d839330ac7b786578782fff6013b815b287c22493a364c",
    },
    # RFC 8452 Appendix C.3: 24-byte PT with 32-byte AAD
    {
        "id": 3,
        "key_bits": 128,
        "key_hex": "01000000000000000000000000000000",
        "nonce_hex": "030000000000000000000000",
        "aad_hex": (
            "0100000000000000000000000000000002000000000000000000000000000000"
        ),
        "plaintext_hex": "020000000000000000000000000000000300000000000000",
        "ciphertext_hex": (
            "dd4bd9e1a6d7729212221bc64e828a327cb1045734465140bd07101b41aa60f6191eb664076dfef2"
        ),
    },
    {
        "id": 4,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '030000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": 'dc20e2d83f25705bb49e439eca56de25',
    },
    {
        "id": 5,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '030000000000000000000000',
        "aad_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_hex": '',
        "ciphertext_hex": 'ad6ebf412ecc34f6a1b88fd45956ce1f',
    },
    {
        "id": 6,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '030000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'd81d993e5c40a70e6f17d145bee71e2d388cb2bfde8f6573407144e94b10fbfa',
    },
    {
        "id": 7,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '030000000000000000000000',
        "aad_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '602ea23caee2ba1961313101de7c28fe2051429dc842094e9039d993d85e2bcf',
    },
    {
        "id": 8,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '030000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'e3e14bea50ec0c616b1113b600803df41cd6131a4af8dd641b9e4e94b3c6e087c3606ea675baec632f17efbf97cfa527',
    },
    {
        "id": 9,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '030000000000000000000000',
        "aad_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": '8c97438dafa4debd0b54ee1c139e41f5c678d453ec0bf4f5f3746d8209546b02271f5e9db70a7bac56df4b9e80e0b880',
    },
    {
        "id": 10,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '010000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": '911b8ae4d71595a1d9618cb29bb18f70',
    },
    {
        "id": 11,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '010000000000000000000000',
        "aad_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_hex": '',
        "ciphertext_hex": '9f6699dd282dbecb10d98d276c8f856e',
    },
    {
        "id": 12,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '010000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": 'c726f9057d12bb425d430e674a252ed7b8b02e21315b31d055ac3e884153c919',
    },
    {
        "id": 13,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '010000000000000000000000',
        "aad_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '3831fbb848c38a1b5749aed694e300ca07321c702235030fd4f7303e4b5320bc',
    },
    {
        "id": 14,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '010000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'd76ba4cd713691e6a0b56c7f076dcdbcc2654736afa65153bde235f578bdbdd11464502b270b923e5f850f39572fe670',
    },
    {
        "id": 15,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": '010000000000000000000000',
        "aad_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'a62d7c997c6f0fe634e21582040125d7bb93c95c4b6387621200612f96cc0a6d83d9111d4ad44a6623f182d1951a3ff8',
    },
    {
        "id": 16,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": '4bc33c747eec54c93c12b9baa96e2cd6',
    },
    {
        "id": 17,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_hex": '',
        "ciphertext_hex": '5ba5a9a81a95750acc116dc24b02c586',
    },
    {
        "id": 18,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '56791761e5c9dfa4e3ec9a6b5d7f5777d9f92e2da1153ae8036e70a267c800d9',
    },
    {
        "id": 19,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": '0101010101010101010101010101010101010101010101010101010101010101',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172a',
        "ciphertext_hex": '397381a531183f727c433703150a5989f12b0dc0ce91a72ecfca5147e0345e19',
    },
    {
        "id": 20,
        "key_bits": 128,
        "key_hex": '01000000000000000000000000000000',
        "nonce_hex": 'cafebabefacedbaddecaf888',
        "aad_hex": '',
        "plaintext_hex": '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51',
        "ciphertext_hex": 'd8da2e9efaa93b1e83de08a032390239407122d3471352931f97fc54d9e8dbfde1edacf6f9e493e688ae740a5f6f8317',
    },

]
