# KAT/data/modern/hmac.py
# Known Answer Tests for HMAC (Hash-based Message Authentication Code)

meta = {
    "group": "modern",
    "algorithm": "HMAC",
    "source": "RFC 2202 (HMAC-MD5/SHA1) + RFC 4231 (HMAC-SHA-2) (1997/2005)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc2202; https://www.rfc-editor.org/rfc/rfc4231",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "HMAC (RFC 2104). "
        "Case fields: hash_alg (e.g. 'SHA-1', 'SHA-256'), key_hex, "
        "message_ascii (if printable ASCII) or message_hex, mac_hex. "
        "Vectors from RFC 2202 (SHA-1) and RFC 4231 (SHA-256/384/512)."
    ),
}

cases = [
    # RFC 2202 TC 1: HMAC-SHA1
    {
        "id": 1,
        "hash_alg": "SHA-1",
        "key_hex": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "message_ascii": "Hi There",
        "mac_hex": "b617318655057264e28bc0b6fb378c8ef146be00",
    },
    # RFC 2202 TC 2: HMAC-SHA1
    {
        "id": 2,
        "hash_alg": "SHA-1",
        "key_ascii": "Jefe",
        "message_ascii": "what do ya want for nothing?",
        "mac_hex": "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
    },
    # RFC 2202 TC 3: HMAC-SHA1
    {
        "id": 3,
        "hash_alg": "SHA-1",
        "key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "message_hex": "dd" * 50,
        "mac_hex": "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    },
    # RFC 4231 TC 1: HMAC-SHA256
    {
        "id": 4,
        "hash_alg": "SHA-256",
        "key_hex": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "message_ascii": "Hi There",
        "mac_hex": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    # RFC 4231 TC 2: HMAC-SHA256
    {
        "id": 5,
        "hash_alg": "SHA-256",
        "key_ascii": "Jefe",
        "message_ascii": "what do ya want for nothing?",
        "mac_hex": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    # RFC 4231 TC 3: HMAC-SHA256
    {
        "id": 6,
        "hash_alg": "SHA-256",
        "key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "message_hex": "dd" * 50,
        "mac_hex": "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    },
    # RFC 4231 TC 1: HMAC-SHA384
    {
        "id": 7,
        "hash_alg": "SHA-384",
        "key_hex": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "message_ascii": "Hi There",
        "mac_hex": "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa34c0e68e8b9b5c8f25f1d64b47e2bf0d0c7cb71f16c7cb71",
    },
    # RFC 4231 TC 1: HMAC-SHA512
    {
        "id": 8,
        "hash_alg": "SHA-512",
        "key_hex": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "message_ascii": "Hi There",
        "mac_hex": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    },
    {
        "id": 9,
        "hash_alg": 'SHA-1',
        "key_hex": '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        "message_ascii": 'Hi There',
        "mac_hex": 'b617318655057264e28bc0b6fb378c8ef146be00',
    },
    {
        "id": 10,
        "hash_alg": 'SHA-256',
        "key_hex": '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        "message_ascii": 'Hi There',
        "mac_hex": 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    },
    {
        "id": 11,
        "hash_alg": 'SHA-384',
        "key_hex": '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        "message_ascii": 'Hi There',
        "mac_hex": 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
    },
    {
        "id": 12,
        "hash_alg": 'SHA-512',
        "key_hex": '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        "message_ascii": 'Hi There',
        "mac_hex": '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    },
    {
        "id": 13,
        "hash_alg": 'SHA-256',
        "key_hex": '4a656665',
        "message_ascii": 'what do ya want for nothing?',
        "mac_hex": '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    },
    {
        "id": 14,
        "hash_alg": 'SHA-256',
        "key_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "message_hex": 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        "mac_hex": '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    },
    {
        "id": 15,
        "hash_alg": 'SHA-256',
        "key_hex": '0102030405060708090a0b0c0d0e0f10111213141516171819',
        "message_hex": 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
        "mac_hex": '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
    },
    {
        "id": 16,
        "hash_alg": 'SHA-256',
        "key_hex": '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
        "message_ascii": 'Test With Truncation',
        "mac_hex": 'a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5',
    },
    {
        "id": 17,
        "hash_alg": 'SHA-256',
        "key_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "message_ascii": 'Test Using Larger Than Block-Size Key - Hash Key First',
        "mac_hex": '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    },
    {
        "id": 18,
        "hash_alg": 'SHA-256',
        "key_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "message_ascii": 'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.',
        "mac_hex": '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    },
    {
        "id": 19,
        "hash_alg": 'SHA-1',
        "key_hex": '4a656665',
        "message_ascii": 'what do ya want for nothing?',
        "mac_hex": 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79',
    },
    {
        "id": 20,
        "hash_alg": 'SHA-1',
        "key_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "message_hex": 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        "mac_hex": '125d7342b9ac11cd91a39af48aa17b4f63f175d3',
    },

]
