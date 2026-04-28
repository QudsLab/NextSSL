# KAT/data/modern/chacha20-poly1305.py
# Known Answer Tests for ChaCha20-Poly1305 AEAD

meta = {
    "group": "modern",
    "algorithm": "ChaCha20-Poly1305",
    "source": "RFC 8439 Section 2.8.2 (2018)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc8439",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "ChaCha20-Poly1305 AEAD construction (RFC 8439). "
        "Case fields: key_hex (32 bytes), nonce_hex (12 bytes), aad_hex, "
        "plaintext_ascii (UTF-8 text) or plaintext_hex, "
        "ciphertext_hex, tag_hex (16 bytes). "
        "Vector from RFC 8439 §2.8.2. "
        "Computed with pycryptodome 3.23."
    ),
}

cases = [
    # RFC 8439 §2.8.2 full AEAD test vector
    {
        "id": 1,
        "key_hex": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "nonce_hex": "070000004041424344454647",
        "aad_hex": "50515253c0c1c2c3c4c5c6c7",
        "plaintext_ascii": "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
        "ciphertext_hex": (
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116"
        ),
        "tag_hex": "1ae10b594f09e26a7e902ecbd0600691",
    },
    # RFC 8439 Appendix A.5 TC 1: empty PT and AAD
    {
        "id": 2,
        "key_hex": "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "nonce_hex": "000000000102030405060708",
        "aad_hex": "f33388860000000000004e91",
        "plaintext_hex": "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b",
        "ciphertext_hex": (
            "496e7465726e65742d4472616674732061726520647261667420"
            "646f63756d656e74732076616c696420666f722061206d6178"
            "696d756d206f6620736978206d6f6e74687320616e64206d61"
            "792062652075706461746564"
        ),
        "tag_hex": "eead9d67890cbb22392336fea1851f38",
    },
    {
        "id": 3,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": 'a0784d7a4716f3feb4f64e7f4b39bf04',
    },
    {
        "id": 4,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": 'e622e5647a38d967a7ecbcb46c7f675c',
    },
    {
        "id": 5,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '',
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f66207468652063',
        "ciphertext_hex": 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736',
        "tag_hex": '28f283489999f553a49bfdbb7bd6fcab',
    },
    {
        "id": 6,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f66207468652063',
        "ciphertext_hex": 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736',
        "tag_hex": '2e38b2c48ab5facf0dc3b5a8c8cd188e',
    },
    {
        "id": 7,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '',
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": '9f7be95d01fd40ba15e28ffb36810aaec1c0883f09016ededd8ad087558203a54e9ecb38ac8e5e2bb8dab20ffadb52e87504b26ebe696d4f60a485cf11b81b59',
        "tag_hex": 'ed2fba2fc1a6ebcf0ecff227ad20135c',
    },
    {
        "id": 8,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": '9f7be95d01fd40ba15e28ffb36810aaec1c0883f09016ededd8ad087558203a54e9ecb38ac8e5e2bb8dab20ffadb52e87504b26ebe696d4f60a485cf11b81b59',
        "tag_hex": '53dc94baf32a393d0c1ff952f2691778',
    },
    {
        "id": 9,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '000000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": '3ae5d3f2a376d317eaea5aef0215ba54',
    },
    {
        "id": 10,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '000000000000000000000000',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": '633c7dbf5d6cdc06460205249c2ef752',
    },
    {
        "id": 11,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '000000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f66207468652063',
        "ciphertext_hex": '663d7ec45b29ceaaa35505b8c1b3d94613a50fd7e315a748d35a378670',
        "tag_hex": '3d674c67ef58cd8a050b7482a8f2b4fe',
    },
    {
        "id": 12,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '000000000000000000000000',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f66207468652063',
        "ciphertext_hex": '663d7ec45b29ceaaa35505b8c1b3d94613a50fd7e315a748d35a378670',
        "tag_hex": 'e70611d929bf8879dd945b00bc443fe7',
    },
    {
        "id": 13,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '000000000000000000000000',
        "aad_hex": '',
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": '2a5c1aad3e5aeecbcd3125ffa4ddad2a76c86ab9c37ac168a73252a613180b8b148b5b62de5c4f6c83245f4d60c8b09097b2ede57bd714282fb00edf5a681829',
        "tag_hex": '17bf5c91e8515f36b322539abd88f675',
    },
    {
        "id": 14,
        "key_hex": '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        "nonce_hex": '000000000000000000000000',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": '2a5c1aad3e5aeecbcd3125ffa4ddad2a76c86ab9c37ac168a73252a613180b8b148b5b62de5c4f6c83245f4d60c8b09097b2ede57bd714282fb00edf5a681829',
        "tag_hex": '86c6408507e6d22251f373d1c170368e',
    },
    {
        "id": 15,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": 'ff3794f086d4f20ea0ee03ec18b40f93',
    },
    {
        "id": 16,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '',
        "ciphertext_hex": '',
        "tag_hex": '0608e88cf07ed20168f09046d405ee88',
    },
    {
        "id": 17,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '',
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f66207468652063',
        "ciphertext_hex": 'f44b26453d3f02c66b21468b6552cb54a588f6549bee854834e1c0c6c7',
        "tag_hex": 'b4c88725f1ae0ff8830c8a287dd0c223',
    },
    {
        "id": 18,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f66207468652063',
        "ciphertext_hex": 'f44b26453d3f02c66b21468b6552cb54a588f6549bee854834e1c0c6c7',
        "tag_hex": '078fab281a852f7ec5befc2c2d6cdf0b',
    },
    {
        "id": 19,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '',
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": 'b82a422c584c22a7054566cc003cbf38c0e5933abb81e3684089a5e6a4e6884af0590944364deb7b723dc5a1ca8fcf9de6b33e13d2d25dcac84a9560158fd9a4',
        "tag_hex": 'a9044d89489076d18f08814dbffb466a',
    },
    {
        "id": 20,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '070000004041424344454647',
        "aad_hex": '50515253c0c1c2c3c4c5c6c7',
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": 'b82a422c584c22a7054566cc003cbf38c0e5933abb81e3684089a5e6a4e6884af0590944364deb7b723dc5a1ca8fcf9de6b33e13d2d25dcac84a9560158fd9a4',
        "tag_hex": '3b590628e7a4158ef50aba725b44da8a',
    },

]
