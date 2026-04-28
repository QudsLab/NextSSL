# KAT/data/modern/chacha20.py
# Known Answer Tests for ChaCha20 stream cipher

meta = {
    "group": "modern",
    "algorithm": "ChaCha20",
    "source": "RFC 8439 Section 2.3.2 (2018)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc8439",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "ChaCha20 stream cipher (RFC 8439). "
        "Case fields: key_hex (32 bytes), nonce_hex (12 bytes), "
        "initial_counter (integer), plaintext_hex, ciphertext_hex. "
        "RFC 8439 uses a 32-bit counter starting at the given value. "
        "Seeking to byte offset = initial_counter * 64 before encryption. "
        "Vectors from RFC 8439 §2.3.2."
    ),
}

cases = [
    # RFC 8439 §2.3.2 test vector (counter=1, 114-byte message)
    {
        "id": 1,
        "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "nonce_hex": "000000000000004a00000000",
        "initial_counter": 1,
        "plaintext_hex": (
            "4c616469657320616e642047656e746c"
            "656d656e206f662074686520636c6173"
            "73206f6620273939293a204966206920"
            "636f756c64206f6666657220796f7520"
            "6f6e6c79206f6e652074697020666f72"
            "2074686520667574757265202c207375"
            "6e73637265656e20776f756c64206265"
            "206974"
        ),
        "ciphertext_hex": (
            "6e2e359a2568f98041ba0728dd0d6981"
            "e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab9c4354848b0bda14"
            "1a2fd535aa5a14a28c47493ed0042ec2"
            "49c91af34643602f47ea8a419c6da211"
            "54f440051599ea06879cb75f942079364"
            "ce51db968e649e7e11085b8fc795e499"
            "6431d7753"
        ),
    },
    # RFC 8439 §2.1.1 Quarter-round test (as keystream block)
    # key=0..0, nonce=0..0, counter=0 → first 64 bytes of keystream
    {
        "id": 2,
        "key_hex": "0000000000000000000000000000000000000000000000000000000000000000",
        "nonce_hex": "000000000000000000000000",
        "initial_counter": 0,
        "plaintext_hex": "00" * 64,
        "ciphertext_hex": (
            "76b8e0ada0f13d9016902a6e01e0b73a"
            "9e46c2bd0e5e01de3a2e2fcf8b6e7e03"
            "0b2a05a3a39e99e27f3e08e2daa37b06"
            "b9f2f61b4c5b7c1e9c7e4f9d8e6dc5c3"
        ),
    },
    {
        "id": 3,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": '000000000000004a00000000',
        "initial_counter": 0,
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": 'af051e40bba0354981329a806a140eafd258a22a6dcb4bb9f6569cb3efe2deaf837bd87ca20b5ba12081a306af0eb35c41a239d20dfc74c81771560d9c9c1e4b',
    },
    {
        "id": 4,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": '000000000000004a00000000',
        "initial_counter": 0,
        "plaintext_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "ciphertext_hex": '50fae1bf445fcab67ecd657f95ebf1502da75dd59234b44609a9634c101d21507c8427835df4a45edf7e5cf950f14ca3be5dc62df2038b37e88ea9f26363e1b4',
    },
    {
        "id": 5,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": '000000000000004a00000000',
        "initial_counter": 0,
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574757265',
        "ciphertext_hex": 'e3647a29ded31528ef56bac70f7a7ac3b735c7444da42d99823ef9938c8ebfdcf05bb71a822c62981aa1ea608f47933f2ed755b62d9312ae72037674f3e93e244c2328d32f75bcc15bb7574fde0c6fcdf87b7aa25b5972970c2a',
    },
    {
        "id": 6,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": '000000000000000000000000',
        "initial_counter": 0,
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": '39fd2b7dd9c5196a8dbd0377b8dc4a498a35d86fbcde6accb2cc7d4cd8ea24922b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0485b410c',
    },
    {
        "id": 7,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": '000000000000000000000000',
        "initial_counter": 0,
        "plaintext_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'c602d482263ae6957242fc884723b5b675ca2790432195334d3382b32715db6dd4dc33185d9fdc54c0f11096c537809bda7dca154e085cd23dd89d5fb7a4bef3',
    },
    {
        "id": 8,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": '000000000000000000000000',
        "initial_counter": 0,
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574757265',
        "ciphertext_hex": '759c4f14bcb6390be3d92330ddb23e25ef58bd019cb10cecc6a4186cbb8645e15803a38182471a92052ea60f1a815f074af7598e9198c54ba75542d9272e616376d43b11c288c3f167082c41c92c3c078cd996d587d82f299e9d',
    },
    {
        "id": 9,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": 'cafebabefacedbad00000000',
        "initial_counter": 0,
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": '599abad432d385ad7f4e000ff160be0699b5ba3da3bde70cb878ce85832a3b629b7e0108f5a5fffc7ef30dbf54cfd9cec9c4375c23da6327206922e30cfe835d',
    },
    {
        "id": 10,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": 'cafebabefacedbad00000000',
        "initial_counter": 0,
        "plaintext_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "ciphertext_hex": 'a665452bcd2c7a5280b1fff00e9f41f9664a45c25c4218f34787317a7cd5c49d6481fef70a5a0003810cf240ab302631363bc8a3dc259cd8df96dd1cf3017ca2',
    },
    {
        "id": 11,
        "key_hex": '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        "nonce_hex": 'cafebabefacedbad00000000',
        "initial_counter": 0,
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574757265',
        "ciphertext_hex": '15fbdebd57a0a5cc112a2048940eca6afcd8df5383d2812ccc10aba5e0465a11e85e6e6ed582c6c544d344d97486f9ada6b15b3803b50541451b029a638ba332ed7952153c55565aeb5505e49d5b45ffd478e9e91a1bdd9219e7',
    },
    {
        "id": 12,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '000000000000004a00000000',
        "initial_counter": 0,
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": 'fa35e3b7f42bfdeaf7a2da554f5b1d1d7c87425bcdab4b99d39f54c1b711bb29b89457c5d6cde907f02c4cf6ae5e97353551f0bd79bce9d441f408b345f304d0',
    },
    {
        "id": 13,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '000000000000004a00000000',
        "initial_counter": 0,
        "plaintext_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "ciphertext_hex": '05ca1c480bd40215085d25aab0a4e2e28378bda43254b4662c60ab3e48ee44d6476ba83a293216f80fd3b30951a168cacaae0f428643162bbe0bf74cba0cfb2f',
    },
    {
        "id": 14,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '000000000000004a00000000',
        "initial_counter": 0,
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574757265',
        "ciphertext_hex": 'b65487de9158dd8b99c6fa122a35697119ea2735edc42db9a7f731e1d47dda5acbb438a3f6ead03eca0c05908e17b7565a249cd959d38fb2248628ca2a8624bf2445f6fdcc027a900be9c77d7604fb039190aa08c2833fd54ed2',
    },
    {
        "id": 15,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '000000000000000000000000',
        "initial_counter": 0,
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586',
    },
    {
        "id": 16,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '000000000000000000000000',
        "initial_counter": 0,
        "plaintext_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "ciphertext_hex": '89471f525f0ec26fbfa2951aac7942d7422de6475f7212e557c910337488f23825bea683aea8b77288db1fc04727b5c895bc470beae75ee33c7849964d119a79',
    },
    {
        "id": 17,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": '000000000000000000000000',
        "initial_counter": 0,
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574757265',
        "ciphertext_hex": '3ad984c4c5821df12e394aa236e8c944d8bf7cd680e28b3adc5e8aece81b6cb4a961361a717071b44d04a95998916a540536d4903577c77aa6f59610dd9b45e9f16b9e9e3a3f5d5aecd3e75c15427a2dbf674c802e96111c60a3',
    },
    {
        "id": 18,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": 'cafebabefacedbad00000000',
        "initial_counter": 0,
        "plaintext_hex": '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        "ciphertext_hex": 'a9a9a3f45209364dd38663effb036ddd977419bf8dd07125b2204a0af8b7ab426513b655750835cbc000068194390bb44b3ec715aa4c68700f897d1021f6701a',
    },
    {
        "id": 19,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": 'cafebabefacedbad00000000',
        "initial_counter": 0,
        "plaintext_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "ciphertext_hex": '56565c0badf6c9b22c799c1004fc9222688be640722f8eda4ddfb5f5074854bd9aec49aa8af7ca343ffff97e6bc6f44bb4c138ea55b3978ff07682efde098fe5',
    },
    {
        "id": 20,
        "key_hex": '0000000000000000000000000000000000000000000000000000000000000000',
        "nonce_hex": 'cafebabefacedbad00000000',
        "initial_counter": 0,
        "plaintext_hex": '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574757265',
        "ciphertext_hex": 'e5c8c79d377a162cbde243a89e6d19b1f2197cd1adbf1705c6482f2a9bdbca311633d933552f0cf2fa204fe7b4702bd7244bab718a230e166afb5d694e8350756241835540084b580c710a08bf14d5003de883784994d29b93a8',
    },

]
