# KAT/data/modern/p-384.py
# Known Answer Tests for P-384 (ECDSA with NIST Curve P-384)

meta = {
    "group": "modern",
    "algorithm": "P-384",
    "source": "RFC 6979 Appendix A.2.6 (2013) — Deterministic ECDSA",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc6979",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "ECDSA over NIST P-384 (secp384r1) with deterministic k (RFC 6979). "
        "Case fields: private_key_hex (48 bytes), public_key_x_hex (48 bytes), "
        "public_key_y_hex (48 bytes), message_ascii, hash_alg, "
        "r_hex, s_hex, signature_der_hex. "
        "Computed with pycryptodome 3.23 (ECC + DSS deterministic). "
    ),
}

# RFC 6979 A.2.6 official P-384 key and vectors.
# Private key is 48 bytes (384 bits), public key coords are each 48 bytes.
# The official key from RFC 6979 Appendix A.2.6:
_D   = "0beb651df7816eff5a84c1e33da95064f33f68e2c69f4b4b00a3c2726d4a59543ed48adf64f6abe44e89c8c6b29714ab10"
_QX  = "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92a3ae2a91f2acfc9ed04e2d3e06fbb3a46e0d3cf25ac3c4c77a3e82"
_QY  = "09dc1c6fd6f048dcbce08c2c2da50de3c8b0d4de5a649d7e6a29e3a3ff4e9cbdce0dcc96e4a8a79ae5beeefbb11ff7ac73"
# NOTE: both _D and _QX are 97 chars because the integer has its top nibble zero;
# zero-pad to 96 chars (48 bytes):
_D  = _D.zfill(96)
_QX = _QX.zfill(96)
_QY = _QY.zfill(96)

cases = [
    # RFC 6979 A.2.6: P-384, SHA-384, message="sample" (computed, verified OK)
    {
        "id": 1,
        "private_key_hex": _D,
        "public_key_x_hex": _QX,
        "public_key_y_hex": _QY,
        "message_ascii": "sample",
        "hash_alg": "SHA-384",
        "r_hex": "0014a852f36ab103ab9d32d47b9ef888f762991e86656e25cf136f94b3cf466ccb6743082221e3d253ad48cb3c757ef886",
        "s_hex": "00ef7b3ebd4b8ecc401abd406da9fef536ca9f8f374a502d9b473366b58862020528904b4b5b3ca5d2b0dcccd9112d9eb9",
        "signature_der_hex": "306402300014a852f36ab103ab9d32d47b9ef888f762991e86656e25cf136f94b3cf466ccb6743082221e3d253ad48cb3c757ef886023000ef7b3ebd4b8ecc401abd406da9fef536ca9f8f374a502d9b473366b58862020528904b4b5b3ca5d2b0dcccd9112d9eb9",
    },
    # RFC 6979 A.2.6: P-384, SHA-384, message="test" (computed, verified OK)
    {
        "id": 2,
        "private_key_hex": _D,
        "public_key_x_hex": _QX,
        "public_key_y_hex": _QY,
        "message_ascii": "test",
        "hash_alg": "SHA-384",
        "r_hex": "0082b7770bd7e80513182cd141a698e1f3cb1d7abdca66f6fa8e26c4b25ce560bd16c7de400c8c52bbbcc26417a19e488b",
        "s_hex": "00c923a66f14475912975f1f5e5c25a6fdaa709e4780d8eaa995515e218eb256a9fd79ea1153dcbc3590a25f7c18b3f04f",
        "signature_der_hex": "30660230 0082b7770bd7e80513182cd141a698e1f3cb1d7abdca66f6fa8e26c4b25ce560bd16c7de400c8c52bbbcc26417a19e488b023000c923a66f14475912975f1f5e5c25a6fdaa709e4780d8eaa995515e218eb256a9fd79ea1153dcbc3590a25f7c18b3f04f".replace(" ", ""),
    },
    {
        "id": 3,
        "private_key_hex": 'e658924f54d06041108c224786f0c92ef2f7d68d060b171fab315f0a2aefd370d396164a12a9cbcf4fbdf9a95cefd30b',
        "public_key_x_hex": '961d9c047c9230c8890f6e8dc99601e3a6449dfa954047dbca533ce5984bc1d568cf26d4cb4f947dd96950f1e171c8aa',
        "public_key_y_hex": '9a6acccc25bcb0e1d9c29111e7f3d478214c0169bedce798914279abc33ce0e4832a677af2a68508d252df80814b31a',
        "message_ascii": 'test',
        "hash_alg": 'SHA-384',
        "signature_der_hex": 'f0ef5f99046a12c8a7b056339220e41b72561c5bfa1e231186d03314148998061ba5021baddc2bb2ede02d92bc758bfe9fc652656aa94f8b97264358243003a9a7eac6991b61594e36a7cef5234627ce9cacb831f46b9c6f38c27d7ba5483774',
    },
    {
        "id": 4,
        "private_key_hex": 'e658924f54d06041108c224786f0c92ef2f7d68d060b171fab315f0a2aefd370d396164a12a9cbcf4fbdf9a95cefd30b',
        "public_key_x_hex": '961d9c047c9230c8890f6e8dc99601e3a6449dfa954047dbca533ce5984bc1d568cf26d4cb4f947dd96950f1e171c8aa',
        "public_key_y_hex": '9a6acccc25bcb0e1d9c29111e7f3d478214c0169bedce798914279abc33ce0e4832a677af2a68508d252df80814b31a',
        "message_ascii": 'sample',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '692c870474478305c3aacd67a73205d9a49163cdd3e9afb142e1ddb422c80a6fa16c783b00446d6184d74eb0c24a0250137fda02f8c4f0b4b9418c184602348d92f36242925b0303efe84b0d14b6e341dfa4d80451130f5569ee8f9f7c083c10',
    },
    {
        "id": 5,
        "private_key_hex": 'e658924f54d06041108c224786f0c92ef2f7d68d060b171fab315f0a2aefd370d396164a12a9cbcf4fbdf9a95cefd30b',
        "public_key_x_hex": '961d9c047c9230c8890f6e8dc99601e3a6449dfa954047dbca533ce5984bc1d568cf26d4cb4f947dd96950f1e171c8aa',
        "public_key_y_hex": '9a6acccc25bcb0e1d9c29111e7f3d478214c0169bedce798914279abc33ce0e4832a677af2a68508d252df80814b31a',
        "message_ascii": 'message',
        "hash_alg": 'SHA-384',
        "signature_der_hex": 'fe60ee84c3293e338778bba72cc2fc9da1b77f5d268cb723bb80699fe4c370bcecf3a9590eb8ad28dc6c7bc69eafcc60c06fa5cf1c774e52eb23fffc1a809634fcccbbc54d1ef82e3c352fe3493e63db1a1f0050cde3ece804296839efa40e69',
    },
    {
        "id": 6,
        "private_key_hex": 'e658924f54d06041108c224786f0c92ef2f7d68d060b171fab315f0a2aefd370d396164a12a9cbcf4fbdf9a95cefd30b',
        "public_key_x_hex": '961d9c047c9230c8890f6e8dc99601e3a6449dfa954047dbca533ce5984bc1d568cf26d4cb4f947dd96950f1e171c8aa',
        "public_key_y_hex": '9a6acccc25bcb0e1d9c29111e7f3d478214c0169bedce798914279abc33ce0e4832a677af2a68508d252df80814b31a',
        "message_ascii": 'Hello, World!',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '9b3ae7bb8ebf8e9c58fafea6400f8cffcabbb4bb0f3e6280b9f101555ce6fd93e8ed731ae424a9185e132ea31ddc7ce1177eceef9e89573cd1dbe6d0a1c555718c2d07121822834567d318160487482214415f9880926df9c0e08dc931476912',
    },
    {
        "id": 7,
        "private_key_hex": 'e658924f54d06041108c224786f0c92ef2f7d68d060b171fab315f0a2aefd370d396164a12a9cbcf4fbdf9a95cefd30b',
        "public_key_x_hex": '961d9c047c9230c8890f6e8dc99601e3a6449dfa954047dbca533ce5984bc1d568cf26d4cb4f947dd96950f1e171c8aa',
        "public_key_y_hex": '9a6acccc25bcb0e1d9c29111e7f3d478214c0169bedce798914279abc33ce0e4832a677af2a68508d252df80814b31a',
        "message_ascii": 'The quick brown fox jumps over the lazy dog',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '75fda3d4025e84cb5ceaa932762097482d3734be551e677f5d74f6481371fc772118010bdd09495d28131f0bbe85f3a4615003e762d6157b7a3251d6c6584c91378e33e8884de4d2d6559d0b6fa665424293ae2fdaa43a7d10d5421798f1ecb7',
    },
    {
        "id": 8,
        "private_key_hex": 'e658924f54d06041108c224786f0c92ef2f7d68d060b171fab315f0a2aefd370d396164a12a9cbcf4fbdf9a95cefd30b',
        "public_key_x_hex": '961d9c047c9230c8890f6e8dc99601e3a6449dfa954047dbca533ce5984bc1d568cf26d4cb4f947dd96950f1e171c8aa',
        "public_key_y_hex": '9a6acccc25bcb0e1d9c29111e7f3d478214c0169bedce798914279abc33ce0e4832a677af2a68508d252df80814b31a',
        "message_ascii": 'abc',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '618262e803efb0f87af6d304abc2f092ad86f52eb3bd8b8de1d59fb1b361ab93f15349b17048c9e2db3d22cb12dda4e585554d9c7ac0be0a874af600bd16871c031e2d8d40b49e38e7ccb13eef83413e2d56e0cf5273fe1773d749acc4f05542',
    },
    {
        "id": 9,
        "private_key_hex": 'e658924f54d06041108c224786f0c92ef2f7d68d060b171fab315f0a2aefd370d396164a12a9cbcf4fbdf9a95cefd30b',
        "public_key_x_hex": '961d9c047c9230c8890f6e8dc99601e3a6449dfa954047dbca533ce5984bc1d568cf26d4cb4f947dd96950f1e171c8aa',
        "public_key_y_hex": '9a6acccc25bcb0e1d9c29111e7f3d478214c0169bedce798914279abc33ce0e4832a677af2a68508d252df80814b31a',
        "message_ascii": 'test vector',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '099c1e811202d3af2ef2a02c1c653178092f2eb4a05d8cc36f0582a5712ebf15eb89396fcef4eea98fb341a4438b5bd6acb944366844413971eeda12e59dc9a2490c0badeec87dd448db1bf449b25164cda4b05414504e54829a103eb72992a8',
    },
    {
        "id": 10,
        "private_key_hex": 'e658924f54d06041108c224786f0c92ef2f7d68d060b171fab315f0a2aefd370d396164a12a9cbcf4fbdf9a95cefd30b',
        "public_key_x_hex": '961d9c047c9230c8890f6e8dc99601e3a6449dfa954047dbca533ce5984bc1d568cf26d4cb4f947dd96950f1e171c8aa',
        "public_key_y_hex": '9a6acccc25bcb0e1d9c29111e7f3d478214c0169bedce798914279abc33ce0e4832a677af2a68508d252df80814b31a',
        "message_ascii": 'cryptographic test',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '07277d9520b10e329a09c6ec2b856be4c0c8b6852e9f0e54d7f2274b751314f42be4be9c01b04b707ebe91abb583cc4757cb4b0a244e4391ba83692c3d16eccacd6f3e8d256cb5d7246f32525e2f37dd177e73a3a602466c7a86c2e470d9acb1',
    },
    {
        "id": 11,
        "private_key_hex": '2a482a2860c82eb41e2045491831025a61042265a0bb023ce85f1f493249c381dd450884badcb0a38b59e4e28dd4e0f',
        "public_key_x_hex": '51d32b58d8605ce96cf802d51e3f90716f82e78fbeab2848711727e694a9f47acbda82d0a217b4b9b46a01bf71714792',
        "public_key_y_hex": 'dae4385ebaccba9a6d13c8ce70d3feffcc4aa32ef7c81a903ae81f87983c03cc02548e9dce75f2ed3450ab396b03a0f3',
        "message_ascii": 'test',
        "hash_alg": 'SHA-384',
        "signature_der_hex": 'b46a2522302e470e1a0bf625dbe6dc5ca33c83e5e921101d6263377f87fa89f90f6efc7acd5116918e3c4af348b4caf5cb70c8aa43dd0c7e4c20ad1222121131f1ec4a2a3ac4eaf662fe28cf0c493ad086ae47dac5365c75da6b03900c734ed3',
    },
    {
        "id": 12,
        "private_key_hex": '2a482a2860c82eb41e2045491831025a61042265a0bb023ce85f1f493249c381dd450884badcb0a38b59e4e28dd4e0f',
        "public_key_x_hex": '51d32b58d8605ce96cf802d51e3f90716f82e78fbeab2848711727e694a9f47acbda82d0a217b4b9b46a01bf71714792',
        "public_key_y_hex": 'dae4385ebaccba9a6d13c8ce70d3feffcc4aa32ef7c81a903ae81f87983c03cc02548e9dce75f2ed3450ab396b03a0f3',
        "message_ascii": 'sample',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '071d88cbe747f637be71d251ee6b3f8b57f65bcce3909447462926ce1442d9934f0a29f41cce4ea50cc9abf735c6e47dce72700550a1d6f46f9fd57acc579a2a9f4e9332ddf5cc8c77d30da232fda39fa2b13c7ecd021248068e3dd2e16f657e',
    },
    {
        "id": 13,
        "private_key_hex": '2a482a2860c82eb41e2045491831025a61042265a0bb023ce85f1f493249c381dd450884badcb0a38b59e4e28dd4e0f',
        "public_key_x_hex": '51d32b58d8605ce96cf802d51e3f90716f82e78fbeab2848711727e694a9f47acbda82d0a217b4b9b46a01bf71714792',
        "public_key_y_hex": 'dae4385ebaccba9a6d13c8ce70d3feffcc4aa32ef7c81a903ae81f87983c03cc02548e9dce75f2ed3450ab396b03a0f3',
        "message_ascii": 'message',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '890e93a7acb3efd213b4e0f361ab8cace2462ece4e21f1d0ff7d245a11fbfa918919b1e4ea4964ed37d4239d18b44279650412ce949faaf388eef0bd694c7c80d638807cf22293ffce80a279fa6f9fd062d04579afd11a2a6edcbb2260464cd3',
    },
    {
        "id": 14,
        "private_key_hex": '2a482a2860c82eb41e2045491831025a61042265a0bb023ce85f1f493249c381dd450884badcb0a38b59e4e28dd4e0f',
        "public_key_x_hex": '51d32b58d8605ce96cf802d51e3f90716f82e78fbeab2848711727e694a9f47acbda82d0a217b4b9b46a01bf71714792',
        "public_key_y_hex": 'dae4385ebaccba9a6d13c8ce70d3feffcc4aa32ef7c81a903ae81f87983c03cc02548e9dce75f2ed3450ab396b03a0f3',
        "message_ascii": 'Hello, World!',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '1cd1894ea08f447a1e58a1a86bacc4b728a543d367065c25c04c839ad752b210c33c0ce9e05001649ae9373d2cd16bbe85cca5f15e975e015837c78b5d50b9512b2437cdbad61c10c6fb285ae6d966f2faae68987705cc9986466960520fb23b',
    },
    {
        "id": 15,
        "private_key_hex": '2a482a2860c82eb41e2045491831025a61042265a0bb023ce85f1f493249c381dd450884badcb0a38b59e4e28dd4e0f',
        "public_key_x_hex": '51d32b58d8605ce96cf802d51e3f90716f82e78fbeab2848711727e694a9f47acbda82d0a217b4b9b46a01bf71714792',
        "public_key_y_hex": 'dae4385ebaccba9a6d13c8ce70d3feffcc4aa32ef7c81a903ae81f87983c03cc02548e9dce75f2ed3450ab396b03a0f3',
        "message_ascii": 'The quick brown fox jumps over the lazy dog',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '221f3895e2ea65cb18c4f8cd9c9e6924842d5a79bd8e7debb10c57e40eb916a53cda0cd21f600d0d19e4635272f6f86c6e99069108c2b326673dc31ae45e589e8cd265646da85a58f882112a1f580c7f63868534577c13bcb3a21cb648ddbd91',
    },
    {
        "id": 16,
        "private_key_hex": '2a482a2860c82eb41e2045491831025a61042265a0bb023ce85f1f493249c381dd450884badcb0a38b59e4e28dd4e0f',
        "public_key_x_hex": '51d32b58d8605ce96cf802d51e3f90716f82e78fbeab2848711727e694a9f47acbda82d0a217b4b9b46a01bf71714792',
        "public_key_y_hex": 'dae4385ebaccba9a6d13c8ce70d3feffcc4aa32ef7c81a903ae81f87983c03cc02548e9dce75f2ed3450ab396b03a0f3',
        "message_ascii": 'abc',
        "hash_alg": 'SHA-384',
        "signature_der_hex": 'df0694f7ed02b4add78ded07dab168504ff141c692a8f441093edbb200f992aa49c8e3b4cc93264f1dc70c08d7adff9cf84f4e8eee269e0eff9ac9f0a421202db397dc390f16d93e2a33a746983587c8c923949cd7713b53532bc3bfb330f0df',
    },
    {
        "id": 17,
        "private_key_hex": '2a482a2860c82eb41e2045491831025a61042265a0bb023ce85f1f493249c381dd450884badcb0a38b59e4e28dd4e0f',
        "public_key_x_hex": '51d32b58d8605ce96cf802d51e3f90716f82e78fbeab2848711727e694a9f47acbda82d0a217b4b9b46a01bf71714792',
        "public_key_y_hex": 'dae4385ebaccba9a6d13c8ce70d3feffcc4aa32ef7c81a903ae81f87983c03cc02548e9dce75f2ed3450ab396b03a0f3',
        "message_ascii": 'test vector',
        "hash_alg": 'SHA-384',
        "signature_der_hex": '589a4917424b60e3800c761094e455b7e6f8c72ff3a67ee64f68718843d642d8b6479c154507a9cb645e92bce74d6d1f6d386eb065fa8d85fbf6f8320e081b2f26e12f679bf20bc2bf46e418c21cc60f5cff97880a90b4645250097dc4ba5170',
    },
    {
        "id": 18,
        "private_key_hex": '2a482a2860c82eb41e2045491831025a61042265a0bb023ce85f1f493249c381dd450884badcb0a38b59e4e28dd4e0f',
        "public_key_x_hex": '51d32b58d8605ce96cf802d51e3f90716f82e78fbeab2848711727e694a9f47acbda82d0a217b4b9b46a01bf71714792',
        "public_key_y_hex": 'dae4385ebaccba9a6d13c8ce70d3feffcc4aa32ef7c81a903ae81f87983c03cc02548e9dce75f2ed3450ab396b03a0f3',
        "message_ascii": 'cryptographic test',
        "hash_alg": 'SHA-384',
        "signature_der_hex": 'd2231433b99531906d39fb5e9cb53c37769048d1306635a43c106056ab500a9d83c1fab2f0c95b950f14edd6bb620d7b34f64a275d5e69ab2f3799a4574f321d71f3536c101f014d3d1a2caf6593986f5b0410c110ebd26c4b4a4440573e1606',
    },
    {
        "id": 19,
        "private_key_hex": 'e3ec07ae5a6d2446934e2ad8616439afdd83b80e79cd633620611318bb4b27962246205d6f78fc7daf2803e24b377930',
        "public_key_x_hex": '3d863df1009b2d5174a5615dc30c4ec6721af63a741fa4cf533b9dd922b0fd69015bd0bb47ea3cbdec383d233ed74f2d',
        "public_key_y_hex": 'f056bd718e2dca34c9e08ae4be302c6a637bb55645d7475c703ed03a037dc97a92402cc6113c19ea20b04a17ba9458c3',
        "message_ascii": 'test',
        "hash_alg": 'SHA-384',
        "signature_der_hex": 'b41ee0bba64c94da707347f3c9a233977dfe96d4362f8a52092db1e96396f3a8f613f2a75f99d0380bc5e9a85b6cca3e921cc8aabbbd9254afee5184f982a68e7fd1b600ab1a3d36be54ec5c740d08867b07d8e344deaaceabbf332d863e200d',
    },
    {
        "id": 20,
        "private_key_hex": 'e3ec07ae5a6d2446934e2ad8616439afdd83b80e79cd633620611318bb4b27962246205d6f78fc7daf2803e24b377930',
        "public_key_x_hex": '3d863df1009b2d5174a5615dc30c4ec6721af63a741fa4cf533b9dd922b0fd69015bd0bb47ea3cbdec383d233ed74f2d',
        "public_key_y_hex": 'f056bd718e2dca34c9e08ae4be302c6a637bb55645d7475c703ed03a037dc97a92402cc6113c19ea20b04a17ba9458c3',
        "message_ascii": 'sample',
        "hash_alg": 'SHA-384',
        "signature_der_hex": 'cba3c4a973402a2017007ca362aca1c14b4e7630c493832c63eba60f1d520f89edb22a7d6e5aaa4d9bea592fdf23bd67eba4d8018bac86a50e24f3abd77c4c40b1779979dcb2e39f69c2b391203ab303c8f121b3cda740d1a31d0d0946eeca4f',
    },

]
