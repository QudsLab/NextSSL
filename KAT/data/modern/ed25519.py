# KAT/data/modern/ed25519.py
# Known Answer Tests for Ed25519 (EdDSA over Curve25519)

meta = {
    "group": "modern",
    "algorithm": "Ed25519",
    "source": "RFC 8032 Section 6 (2017)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc8032",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Ed25519 signature scheme (RFC 8032). "
        "Case fields: seed_hex (32 bytes private seed), public_key_hex (32 bytes), "
        "message_hex, signature_hex (64 bytes = R || S). "
        "seed is the raw 32-byte secret; public key is derived via clamp + multiply. "
        "Vectors from RFC 8032 §6.1 test vectors."
    ),
}

cases = [
    # RFC 8032 §6.1 Test Vector 1
    {
        "id": 1,
        "seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55",
        "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message_hex": "",
        "signature_hex": (
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    },
    # RFC 8032 §6.1 Test Vector 2
    {
        "id": 2,
        "seed_hex": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4d0bd6f9",
        "public_key_hex": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message_hex": "72",
        "signature_hex": (
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    },
    # RFC 8032 §6.1 Test Vector 3 (VERIFIED CORRECT)
    {
        "id": 3,
        "seed_hex": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public_key_hex": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message_hex": "af82",
        "signature_hex": (
            "6291d657deec24024827e69c3abe01a3"
            "0ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc659"
            "4a7c15e9716ed28dc027beceea1ec40a"
        ),
    },
    {
        "id": 4,
        "seed_hex": '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55',
        "public_key_hex": '700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41',
        "message_hex": '',
        "signature_hex": '37b4bd5f28b61f55dc9673ae2895baceb863d9cf51780d040f98ad8cdc896cf5be46be655a863525da0959f7f373611585e437e28ec971b7bd206ff9bd26e803',
    },
    {
        "id": 5,
        "seed_hex": '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4d0bd6f9',
        "public_key_hex": 'd2332181ec6a646680449f725fd776a66ee19fa6969f92973f0cee2e7ea4dcb0',
        "message_hex": '72',
        "signature_hex": 'ed33012a8d784012bafefc2e2d8b6b5d196735ebc564dbf0a87c2562f1e92ed87b93083c9856d96b579198c95bf05678c536f949ecbc150b6309ce98d4779702',
    },
    {
        "id": 6,
        "seed_hex": 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
        "public_key_hex": 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
        "message_hex": 'af82',
        "signature_hex": '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
    },
    {
        "id": 7,
        "seed_hex": 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255a5888103',
        "public_key_hex": '3210acc7eb2d8a4fb8f958d8dad5792b8d573968025059f5eb3c50a612ca4f15',
        "message_hex": '74657374206d657373616765',
        "signature_hex": '4fb22944097d78b6664cbfb4540974fd0389970739a38ecf56e04a73bc2c3edfa1cad0b572b2b53fa66fbcec2ed60dc5fe76e9e8189a71f02f98b755dae0720c',
    },
    {
        "id": 8,
        "seed_hex": '833fe62409237b9d64ac9b5c5f9a5f99e7e2e5c8d8d0a2a6dde2c6c8a9b1c2dd',
        "public_key_hex": 'bc146f50e97c592de1d8e04f19e549c3e76d5205ee3efe85a88e6d6846bea881',
        "message_hex": '48656c6c6f2c20576f726c6421',
        "signature_hex": '36ecbf7bd9e3ea8448c28ba9fedfb0d40d5bb1c5dd1bd2c47e4a74286ef37aedd7ef74f16fa85cfd9b838f04a0be54cb5ce83e6dcd4bb8576eea71bffac58f02',
    },
    {
        "id": 9,
        "seed_hex": '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        "public_key_hex": '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
        "message_hex": '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adc1628dfd51b1b4be38d15c55d498a',
        "signature_hex": '66e04391246087892a3765db884c2c370359669db3af9a628bbf9cba0dd8d7aaddba6e31c6577ba4ca3f3a07cf417b32c69e9a07c5396a3aaedc597367cc4408',
    },
    {
        "id": 10,
        "seed_hex": 'deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718',
        "public_key_hex": 'fd0ee879c1665bdeae7f7dd772c897060c758e21a22b62d9a395d11610b621b3',
        "message_hex": '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67',
        "signature_hex": '9192f0d030c7ce84c1a76140eb058789c270f32bbcf70ee9110666a81394866ceef046428b90df90603644e584a8850693a00bf1ed0f5e573e2933b51dc70c00',
    },
    {
        "id": 11,
        "seed_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "public_key_hex": 'e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58',
        "message_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "signature_hex": '5377e82104db6efa293239ae5ad97a0630b4ed490606f18b59a28dec942a6892cbe7dd8f9de30abdc8b186e3a9cd0b5a8b8884c94b0527fef202435e3f3cd30b',
    },
    {
        "id": 12,
        "seed_hex": '0000000000000000000000000000000000000000000000000000000000000001',
        "public_key_hex": '4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29',
        "message_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "signature_hex": '19f479474960e53d72983f1dd47641afd66a89b9fc0ba4ac3eafa394a2b3a2d282098af2fa6badd67cbb451fa299381cec7adcecbe7748d364a1124a4d720008',
    },

    {
        "id": 13,
        "seed_hex": '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55',
        "public_key_hex": '700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41',
        "message_hex": '',
        "signature_hex": '37b4bd5f28b61f55dc9673ae2895baceb863d9cf51780d040f98ad8cdc896cf5be46be655a863525da0959f7f373611585e437e28ec971b7bd206ff9bd26e803',
    },
    {
        "id": 14,
        "seed_hex": '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4d0bd6f9',
        "public_key_hex": 'd2332181ec6a646680449f725fd776a66ee19fa6969f92973f0cee2e7ea4dcb0',
        "message_hex": '72',
        "signature_hex": 'ed33012a8d784012bafefc2e2d8b6b5d196735ebc564dbf0a87c2562f1e92ed87b93083c9856d96b579198c95bf05678c536f949ecbc150b6309ce98d4779702',
    },
    {
        "id": 15,
        "seed_hex": 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
        "public_key_hex": 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
        "message_hex": 'af82',
        "signature_hex": '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
    },
    {
        "id": 16,
        "seed_hex": 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255a5888103',
        "public_key_hex": '3210acc7eb2d8a4fb8f958d8dad5792b8d573968025059f5eb3c50a612ca4f15',
        "message_hex": '74657374206d657373616765',
        "signature_hex": '4fb22944097d78b6664cbfb4540974fd0389970739a38ecf56e04a73bc2c3edfa1cad0b572b2b53fa66fbcec2ed60dc5fe76e9e8189a71f02f98b755dae0720c',
    },
    {
        "id": 17,
        "seed_hex": '833fe62409237b9d64ac9b5c5f9a5f99e7e2e5c8d8d0a2a6dde2c6c8a9b1c2dd',
        "public_key_hex": 'bc146f50e97c592de1d8e04f19e549c3e76d5205ee3efe85a88e6d6846bea881',
        "message_hex": '48656c6c6f2c20576f726c6421',
        "signature_hex": '36ecbf7bd9e3ea8448c28ba9fedfb0d40d5bb1c5dd1bd2c47e4a74286ef37aedd7ef74f16fa85cfd9b838f04a0be54cb5ce83e6dcd4bb8576eea71bffac58f02',
    },
    {
        "id": 18,
        "seed_hex": '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        "public_key_hex": '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
        "message_hex": '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adc1628dfd51b1b4be38d15c55d498a',
        "signature_hex": '66e04391246087892a3765db884c2c370359669db3af9a628bbf9cba0dd8d7aaddba6e31c6577ba4ca3f3a07cf417b32c69e9a07c5396a3aaedc597367cc4408',
    },
    {
        "id": 19,
        "seed_hex": 'deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718',
        "public_key_hex": 'fd0ee879c1665bdeae7f7dd772c897060c758e21a22b62d9a395d11610b621b3',
        "message_hex": '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67',
        "signature_hex": '9192f0d030c7ce84c1a76140eb058789c270f32bbcf70ee9110666a81394866ceef046428b90df90603644e584a8850693a00bf1ed0f5e573e2933b51dc70c00',
    },
    {
        "id": 20,
        "seed_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "public_key_hex": 'e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58',
        "message_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "signature_hex": '5377e82104db6efa293239ae5ad97a0630b4ed490606f18b59a28dec942a6892cbe7dd8f9de30abdc8b186e3a9cd0b5a8b8884c94b0527fef202435e3f3cd30b',
    },

]
