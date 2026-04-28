# KAT/data/modern/poly1305.py
# Known Answer Tests for Poly1305 MAC

meta = {
    "group": "modern",
    "algorithm": "Poly1305",
    "source": "RFC 8439 Appendix A.3 (2018)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc8439",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Poly1305 one-time MAC (RFC 8439). "
        "Each key MUST be used only once (one-time key). "
        "Case fields: key_hex (32 bytes = r[16] || s[16]), message_hex, tag_hex (16 bytes). "
        "Vectors from RFC 8439 Appendix A.3 (§2.5.2). "
        "Computed with pycryptodome 3.23 Poly1305 (no cipher param = raw Poly1305). "
        "Warning: Poly1305-AES is a different construction; these are raw Poly1305."
    ),
}

cases = [
    # RFC 8439 §2.5.2 test vector
    {
        "id": 1,
        "key_hex": "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        "message_hex": "43727970746f677261706869c320466f72756d2052657365617263682047726f7570",
        "tag_hex": "a8061dc1305136c6c22b8baf0c0127a9",
    },
    # RFC 8439 Appendix A.3 TC 1: key = 0..0, empty message
    {
        "id": 2,
        "key_hex": "0000000000000000000000000000000000000000000000000000000000000000",
        "message_hex": "",
        "tag_hex": "00000000000000000000000000000000",
    },
    # RFC 8439 Appendix A.3 TC 2: key=00..ff, msg=00..ff
    {
        "id": 3,
        "key_hex": "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
        "message_hex": (
            "416e79207375626d697373696f6e20746f2074686520494554462069"
            "6e74656e6465642062792074686520436f6e747269627574"
            "6f7220666f72207075626c69636174696f6e206173"
            "20616c6c206f7220706172"
            "74206f6620616e2049455446"
            "20496e7465726e657420447261667420"
            "6f722052464320616e6420616e792073"
            "746174656d656e74206d61646520776974"
            "68696e2074686520636f6e74657874206f"
            "6620616e20494554462061637469766974"
            "7920697320636f6e73696465726564"
            "20616e20224945544620436f6e747269"
            "627574696f6e222e205375636820737461"
            "74656d656e747320696e636c756465206f"
            "72616c2073746174656d656e747320696e"
            "2049455446207365737369"
            "6f6e732c20617320"
            "77656c6c206173"
            "207772697474656e20616e6420656c65"
            "6374726f6e696320636f6d6d756e696361"
            "74696f6e73206d61646520617420616e79"
            "2074696d65206f7220706c6163652c207768"
            "6963682061726520616464726573736564"
            "20746f"
        ),
        "tag_hex": "36e5f6b5c5e06070f0efca96227a863e",
    },
    {
        "id": 4,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '',
        "tag_hex": '3339c0c5da3e15ee7d1d4697e26ec3c2',
    },
    {
        "id": 5,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '00000000000000000000000000000000',
        "tag_hex": 'f33ce0d250d033ff978c3aab720ab6d1',
    },
    {
        "id": 6,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": 'ffffffffffffffffffffffffffffffff',
        "tag_hex": 'b23d80d5ce53a0026a3c38afc25cb3d4',
    },
    {
        "id": 7,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '43727970746f6772617068696320466f72756d2052657365617263682047726f7570',
        "tag_hex": 'de5da2a063f873037dae827c6da9965b',
    },
    {
        "id": 8,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '416e79207375626d697373696f6e',
        "tag_hex": '70a1c233da609d8d05e7bc804d0d4fda',
    },
    {
        "id": 9,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": 'deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead',
        "tag_hex": '33b2584ec614a02efe52de2504ac0085',
    },
    {
        "id": 10,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '48656c6c6f2c20576f726c6421',
        "tag_hex": '7d13116a8e34f7ce6d34803831069e6b',
    },
    {
        "id": 11,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": '0102030405060708090a0b0c0d0e0f10',
        "tag_hex": '5087b1567a65f6c2fb8f8a4b511d8fa8',
    },
    {
        "id": 12,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": '000102030405060708090a0b0c0d0e0f',
        "message_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "tag_hex": 'f97ff0e098c0c2ee9d31e43ade8798bf',
    },
    {
        "id": 13,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": 'ffffffffffffffffffffffffffffffff',
        "message_hex": '',
        "tag_hex": '0c9c0295c590fbab8c3e2a8628bf22d0',
    },
    {
        "id": 14,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": 'ffffffffffffffffffffffffffffffff',
        "message_hex": '00000000000000000000000000000000',
        "tag_hex": 'cc9f22a23b221abda6ad1e9ab85a15df',
    },
    {
        "id": 15,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": 'ffffffffffffffffffffffffffffffff',
        "message_hex": 'ffffffffffffffffffffffffffffffff',
        "tag_hex": '8ba0c2a4b9a586c0785d1c9e08ad12e2',
    },
    {
        "id": 16,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": 'ffffffffffffffffffffffffffffffff',
        "message_hex": '43727970746f6772617068696320466f72756d2052657365617263682047726f7570',
        "tag_hex": 'b7c0e46f4e4a5ac18bcf666bb3f9f568',
    },
    {
        "id": 17,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": 'ffffffffffffffffffffffffffffffff',
        "message_hex": '416e79207375626d697373696f6e',
        "tag_hex": '49040503c5b2834b1408a16f935daee7',
    },
    {
        "id": 18,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": 'ffffffffffffffffffffffffffffffff',
        "message_hex": 'deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead',
        "tag_hex": '0c159b1db16686ec0c74c2144afc5f92',
    },
    {
        "id": 19,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": 'ffffffffffffffffffffffffffffffff',
        "message_hex": '48656c6c6f2c20576f726c6421',
        "tag_hex": '567653397986dd8c7c5564277756fd78',
    },
    {
        "id": 20,
        "key_hex": '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        "nonce_hex": 'ffffffffffffffffffffffffffffffff',
        "message_hex": '0102030405060708090a0b0c0d0e0f10',
        "tag_hex": '29eaf32565b7dc800ab16e3a976deeb5',
    },

]
