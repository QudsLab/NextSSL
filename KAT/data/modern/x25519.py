# KAT/data/modern/x25519.py
# Known Answer Tests for X25519 (Diffie-Hellman over Curve25519)

meta = {
    "group": "modern",
    "algorithm": "X25519",
    "source": "RFC 7748 Section 6.1 (2016)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc7748",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "X25519 Diffie-Hellman function (RFC 7748). "
        "Case fields for DH exchange: alice_private_hex, alice_public_hex, "
        "bob_private_hex, bob_public_hex, shared_secret_hex. "
        "Also includes one-way function test cases: "
        "scalar_hex, u_hex (input point), output_hex. "
        "Private keys are clamped per RFC 7748 §5. "
        "Vectors from RFC 7748 §6.1 DH test vectors."
    ),
}

cases = [
    # RFC 7748 §6.1 DH key exchange
    {
        "id": 1,
        "type": "dh_exchange",
        "alice_private_hex": "77076d0a7318a57d3c16c17251b26645c6c2f6d9135831ed8804b35f11e9b21f",
        "alice_public_hex": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "bob_private_hex": "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "bob_public_hex": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "shared_secret_hex": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    },
    # RFC 7748 §5.2 one-way function test vector
    {
        "id": 2,
        "type": "one_way",
        "scalar_hex": "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "u_hex": "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "output_hex": "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    },
    {
        "id": 3,
        "type": 'dh_exchange',
        "alice_private_hex": '77076d0a7318a57d3c16c17251b26645c6c2f6d9135831ed8804b35f11e9b21f',
        "alice_public_hex": 'c4531a57bcb7e9de101458f21ceef22d2522dd5139b509b9bdeccbec1b07d86e',
        "bob_private_hex": '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
        "bob_public_hex": 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
        "shared_secret_hex": '4a8b8346dd6602f3778d50d737f0684808d400e51da924f549201f609739645e',
    },
    {
        "id": 4,
        "type": 'dh_exchange',
        "alice_private_hex": '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
        "alice_public_hex": 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
        "bob_private_hex": '77076d0a7318a57d3c16c17251b26645c6c2f6d9135831ed8804b35f11e9b21f',
        "bob_public_hex": 'c4531a57bcb7e9de101458f21ceef22d2522dd5139b509b9bdeccbec1b07d86e',
        "shared_secret_hex": '4a8b8346dd6602f3778d50d737f0684808d400e51da924f549201f609739645e',
    },
    {
        "id": 5,
        "type": 'dh_exchange',
        "alice_private_hex": '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        "alice_public_hex": '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c',
        "bob_private_hex": '1111111111111111111111111111111111111111111111111111111111111111',
        "bob_public_hex": '7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13',
        "shared_secret_hex": 'bc2afabe29872dcf76dcab74d2038df99eabe5a8e6b5d1335f5c8f0d4147841e',
    },
    {
        "id": 6,
        "type": 'dh_exchange',
        "alice_private_hex": 'deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718',
        "alice_public_hex": '1113f6376e2ae22135bb91a634c2ee6ce2a545766cba69e25642022752782267',
        "bob_private_hex": 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
        "bob_public_hex": '13d492634f816aed4b679c0eb6d0c994bbc4321b175681e4e52357c76eff6568',
        "shared_secret_hex": '18287a322907cf45b2d8e0a14f8f8017a01ac524ccc4fc114fcf91ff06aa683b',
    },
    {
        "id": 7,
        "type": 'dh_exchange',
        "alice_private_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "alice_public_hex": '14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070',
        "bob_private_hex": 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        "bob_public_hex": '6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b',
        "shared_secret_hex": '2f6d4d0247b4216d9114a87cf9206bc9c65c1b62593f18b7f3474a747e615229',
    },
    {
        "id": 8,
        "type": 'dh_exchange',
        "alice_private_hex": '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        "alice_public_hex": '05ee18184ed593900f639b87b8d99a7a5c5c00cc0aaac5629c45f8869c602907',
        "bob_private_hex": 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
        "bob_public_hex": 'd1b153c4964c6911805e576f2c261edd4dc35d4d79affed2b598928201f77853',
        "shared_secret_hex": '2d8252da906e76b6b0b76548ea3192f29430ad65472e9622602ce14be706c16c',
    },

    {
        "id": 9,
        "type": 'dh_exchange',
        "alice_private_hex": '77076d0a7318a57d3c16c17251b26645c6c2f6d9135831ed8804b35f11e9b21f',
        "alice_public_hex": 'c4531a57bcb7e9de101458f21ceef22d2522dd5139b509b9bdeccbec1b07d86e',
        "bob_private_hex": '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
        "bob_public_hex": 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
        "shared_secret_hex": '4a8b8346dd6602f3778d50d737f0684808d400e51da924f549201f609739645e',
    },
    {
        "id": 10,
        "type": 'dh_exchange',
        "alice_private_hex": '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
        "alice_public_hex": 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
        "bob_private_hex": '77076d0a7318a57d3c16c17251b26645c6c2f6d9135831ed8804b35f11e9b21f',
        "bob_public_hex": 'c4531a57bcb7e9de101458f21ceef22d2522dd5139b509b9bdeccbec1b07d86e',
        "shared_secret_hex": '4a8b8346dd6602f3778d50d737f0684808d400e51da924f549201f609739645e',
    },
    {
        "id": 11,
        "type": 'dh_exchange',
        "alice_private_hex": '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        "alice_public_hex": '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c',
        "bob_private_hex": '1111111111111111111111111111111111111111111111111111111111111111',
        "bob_public_hex": '7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13',
        "shared_secret_hex": 'bc2afabe29872dcf76dcab74d2038df99eabe5a8e6b5d1335f5c8f0d4147841e',
    },
    {
        "id": 12,
        "type": 'dh_exchange',
        "alice_private_hex": 'deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718',
        "alice_public_hex": '1113f6376e2ae22135bb91a634c2ee6ce2a545766cba69e25642022752782267',
        "bob_private_hex": 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
        "bob_public_hex": '13d492634f816aed4b679c0eb6d0c994bbc4321b175681e4e52357c76eff6568',
        "shared_secret_hex": '18287a322907cf45b2d8e0a14f8f8017a01ac524ccc4fc114fcf91ff06aa683b',
    },
    {
        "id": 13,
        "type": 'dh_exchange',
        "alice_private_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "alice_public_hex": '14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070',
        "bob_private_hex": 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        "bob_public_hex": '6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b',
        "shared_secret_hex": '2f6d4d0247b4216d9114a87cf9206bc9c65c1b62593f18b7f3474a747e615229',
    },
    {
        "id": 14,
        "type": 'dh_exchange',
        "alice_private_hex": '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        "alice_public_hex": '05ee18184ed593900f639b87b8d99a7a5c5c00cc0aaac5629c45f8869c602907',
        "bob_private_hex": 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
        "bob_public_hex": 'd1b153c4964c6911805e576f2c261edd4dc35d4d79affed2b598928201f77853',
        "shared_secret_hex": '2d8252da906e76b6b0b76548ea3192f29430ad65472e9622602ce14be706c16c',
    },

    {
        "id": 15,
        "type": 'dh_exchange',
        "alice_private_hex": '77076d0a7318a57d3c16c17251b26645c6c2f6d9135831ed8804b35f11e9b21f',
        "alice_public_hex": 'c4531a57bcb7e9de101458f21ceef22d2522dd5139b509b9bdeccbec1b07d86e',
        "bob_private_hex": '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
        "bob_public_hex": 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
        "shared_secret_hex": '4a8b8346dd6602f3778d50d737f0684808d400e51da924f549201f609739645e',
    },
    {
        "id": 16,
        "type": 'dh_exchange',
        "alice_private_hex": '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
        "alice_public_hex": 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
        "bob_private_hex": '77076d0a7318a57d3c16c17251b26645c6c2f6d9135831ed8804b35f11e9b21f',
        "bob_public_hex": 'c4531a57bcb7e9de101458f21ceef22d2522dd5139b509b9bdeccbec1b07d86e',
        "shared_secret_hex": '4a8b8346dd6602f3778d50d737f0684808d400e51da924f549201f609739645e',
    },
    {
        "id": 17,
        "type": 'dh_exchange',
        "alice_private_hex": '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        "alice_public_hex": '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c',
        "bob_private_hex": '1111111111111111111111111111111111111111111111111111111111111111',
        "bob_public_hex": '7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13',
        "shared_secret_hex": 'bc2afabe29872dcf76dcab74d2038df99eabe5a8e6b5d1335f5c8f0d4147841e',
    },
    {
        "id": 18,
        "type": 'dh_exchange',
        "alice_private_hex": 'deadbeefcafebabe0102030405060708090a0b0c0d0e0f101112131415161718',
        "alice_public_hex": '1113f6376e2ae22135bb91a634c2ee6ce2a545766cba69e25642022752782267',
        "bob_private_hex": 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
        "bob_public_hex": '13d492634f816aed4b679c0eb6d0c994bbc4321b175681e4e52357c76eff6568',
        "shared_secret_hex": '18287a322907cf45b2d8e0a14f8f8017a01ac524ccc4fc114fcf91ff06aa683b',
    },
    {
        "id": 19,
        "type": 'dh_exchange',
        "alice_private_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "alice_public_hex": '14ca9e4d387bccf35746e0407daaacc6b28a4f8445ef5a5158894db983e24070',
        "bob_private_hex": 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        "bob_public_hex": '6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b',
        "shared_secret_hex": '2f6d4d0247b4216d9114a87cf9206bc9c65c1b62593f18b7f3474a747e615229',
    },
    {
        "id": 20,
        "type": 'dh_exchange',
        "alice_private_hex": '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        "alice_public_hex": '05ee18184ed593900f639b87b8d99a7a5c5c00cc0aaac5629c45f8869c602907',
        "bob_private_hex": 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
        "bob_public_hex": 'd1b153c4964c6911805e576f2c261edd4dc35d4d79affed2b598928201f77853',
        "shared_secret_hex": '2d8252da906e76b6b0b76548ea3192f29430ad65472e9622602ce14be706c16c',
    },

]
