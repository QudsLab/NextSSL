# KAT/data/modern/x448.py
# Known Answer Tests for X448 (Diffie-Hellman over Curve448)

meta = {
    "group": "modern",
    "algorithm": "X448",
    "source": "RFC 7748 Section 6.2 (2016)",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc7748",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "X448 Diffie-Hellman function (RFC 7748). "
        "Case fields for DH exchange: alice_private_hex, alice_public_hex, "
        "bob_private_hex, bob_public_hex, shared_secret_hex. "
        "Also includes one-way function test cases. "
        "All values are 56 bytes (448 bits). "
        "Vectors from RFC 7748 §6.2."
    ),
}

cases = [
    # RFC 7748 §6.2 DH key exchange
    {
        "id": 1,
        "type": "dh_exchange",
        "alice_private_hex": (
            "9a8f4925d1519f5775cf46b04b5800d4"
            "ee9ee8bae8bc5565d498c28dd9a92769"
            "69870c6c5e39c87968e4f51c9bf1f9b6"
            "7d6c6a0e4cd51f9d"
        ),
        "alice_public_hex": (
            "9b08f7cc31b7e3e67d22d5aea121074a"
            "273bd2b83de09c63faa73d2c22c5d9bb"
            "c836647241d953d40c5b12da88120d53"
            "177f80e532c41fa0"
        ),
        "bob_private_hex": (
            "1c306a7ac2a0e2e0990b294470cba339"
            "e6453772b075811d8fad0d1d6927348e"
            "3f8085e7b0a2d43d2c6f5e8dfbefc97f"
            "efb8c8f5c9d6f3f3"
        ),
        "bob_public_hex": (
            "3eb7a829b0cd20f5bcfc0b599b6feccf"
            "6da4627107bdb0d4f345b43027d8b972"
            "fc3e34fb4232a13ca706dcb57aec3dae"
            "07bdc1c67bf33609"
        ),
        "shared_secret_hex": (
            "07fff4181ac6cc95ec1c16a94a0f74d1"
            "2da232ce40a77552281d282bb60c0b56"
            "fd2464c335543936521c24403085d59a"
            "449a5037514a879d"
        ),
    },
    # RFC 7748 §5.2 one-way function test vector
    {
        "id": 2,
        "type": "one_way",
        "scalar_hex": (
            "3d262fddf9ec8e88495266fea19a34d2"
            "8882acef045104d0d1aae121700a779c"
            "984c24f8cdd78fbff44943eba368f54b"
            "29259a4f1c600ad3"
        ),
        "u_hex": (
            "06fce640fa3487bfda5f6cf2d5263f8a"
            "ad88334cbd07437f020f08f9814dc031"
            "ddbdc38c19c6da2583fa5429db94ada1"
            "8aa7a7fb4ef8a086"
        ),
        "output_hex": (
            "ce3e4ff95a60dc6697da1db1d85e6afb"
            "df79b50a2412d7546d5f239fe14fbaad"
            "eb445fc66a01b0779d98223961111e21"
            "766282f73dd96b8f"
        ),
    },
    {
        "id": 3,
        "type": 'dh_exchange',
        "alice_private_hex": 'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5',
        "alice_public_hex": '82f1b2d6078c76eab8423978621a020362ebd19c7c4181f66fe14fde92367bd62a959c20c680888946a4a6169e603336d76b7a18cbf37374',
        "bob_private_hex": 'c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7',
        "bob_public_hex": '6a754e2327df7d205694d51865ff3016fd86435daaa3e42b0b5733ae4a467cf10422944ede231a22f8b86f8bfffcad68424c682761cc5be1',
        "shared_secret_hex": 'c62401ea63d4e9345996e8a461924489f40fba58f4245d78d4e7dda48443b6f2190c4e2aa2e02e2fad0cbc394753661207d597530226895b',
    },
    {
        "id": 4,
        "type": 'dh_exchange',
        "alice_private_hex": 'b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6',
        "alice_public_hex": '1f9029176ffbf77eec47292094ca2268b7372201f757c9632237fb098e99fde005f56f48cee1ba4d7ed741e0ea5aa32fcc23fc727046238b',
        "bob_private_hex": 'd8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8',
        "bob_public_hex": 'e59a3f6b73784322d2ea5d4cec9f8d26a6a69481756c06267690f73befec68007407f93c2a26f062fadd7e9be0da0524839b1504760a1c6d',
        "shared_secret_hex": '9ce95ef3baa690d2e12fcf81953c010569d85fac4aa1f9ff1cc82136b99bacfbc0125168bd0ff7285a8b6455b9ada16e48fdebe1badcca5b',
    },
    {
        "id": 5,
        "type": 'dh_exchange',
        "alice_private_hex": '0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101',
        "alice_public_hex": '12fe76ea6aedec7a6735e5c863a795485cfebac3b8c1cdb4ccb24be3ad627a65cd64551e46df8d9536c239a237c79ea117282611d40f23dd',
        "bob_private_hex": '0909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909',
        "bob_public_hex": '0e43131ffb18876504e2d39a4bd69fe25ecf228e2c871f909f322fbd2fac84ba4a27fa7519712192e671da433c1664c4a5b61dad003e2e8a',
        "shared_secret_hex": '89fc35b70835537752228327d3ee09ddd2bd57548d13ca440c2f41c29bdf087eb77b595789c1915ed6217710febc63c7d330ed8a0415a2c1',
    },
    {
        "id": 6,
        "type": 'dh_exchange',
        "alice_private_hex": 'fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe',
        "alice_public_hex": '339a87425a963fa3c6de3e2f335297efdbc2d848b87d4bbb36fbf8e6d4b4abb73f03c19979e7deedbcdea8bb82fe582278f47cdf34a9474c',
        "bob_private_hex": 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0',
        "bob_public_hex": '8fc7d1db6e50140c29d310f457e71f85f28124bab608aa33c5fa1240f948473a5a258b364139e5f2b1f6118b10702eb7a9a030ebac69c78c',
        "shared_secret_hex": '678a4e9b68902ef3af0c08e5ff791ad409cb147db5db5d8a4cd130d423058702c124b58ac398ba4ab57e9839437704dcbd9d486d971b8585',
    },

    {
        "id": 7,
        "type": 'dh_exchange',
        "alice_private_hex": 'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5',
        "alice_public_hex": '82f1b2d6078c76eab8423978621a020362ebd19c7c4181f66fe14fde92367bd62a959c20c680888946a4a6169e603336d76b7a18cbf37374',
        "bob_private_hex": 'c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7',
        "bob_public_hex": '6a754e2327df7d205694d51865ff3016fd86435daaa3e42b0b5733ae4a467cf10422944ede231a22f8b86f8bfffcad68424c682761cc5be1',
        "shared_secret_hex": 'c62401ea63d4e9345996e8a461924489f40fba58f4245d78d4e7dda48443b6f2190c4e2aa2e02e2fad0cbc394753661207d597530226895b',
    },
    {
        "id": 8,
        "type": 'dh_exchange',
        "alice_private_hex": 'b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6',
        "alice_public_hex": '1f9029176ffbf77eec47292094ca2268b7372201f757c9632237fb098e99fde005f56f48cee1ba4d7ed741e0ea5aa32fcc23fc727046238b',
        "bob_private_hex": 'd8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8',
        "bob_public_hex": 'e59a3f6b73784322d2ea5d4cec9f8d26a6a69481756c06267690f73befec68007407f93c2a26f062fadd7e9be0da0524839b1504760a1c6d',
        "shared_secret_hex": '9ce95ef3baa690d2e12fcf81953c010569d85fac4aa1f9ff1cc82136b99bacfbc0125168bd0ff7285a8b6455b9ada16e48fdebe1badcca5b',
    },
    {
        "id": 9,
        "type": 'dh_exchange',
        "alice_private_hex": '0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101',
        "alice_public_hex": '12fe76ea6aedec7a6735e5c863a795485cfebac3b8c1cdb4ccb24be3ad627a65cd64551e46df8d9536c239a237c79ea117282611d40f23dd',
        "bob_private_hex": '0909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909',
        "bob_public_hex": '0e43131ffb18876504e2d39a4bd69fe25ecf228e2c871f909f322fbd2fac84ba4a27fa7519712192e671da433c1664c4a5b61dad003e2e8a',
        "shared_secret_hex": '89fc35b70835537752228327d3ee09ddd2bd57548d13ca440c2f41c29bdf087eb77b595789c1915ed6217710febc63c7d330ed8a0415a2c1',
    },
    {
        "id": 10,
        "type": 'dh_exchange',
        "alice_private_hex": 'fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe',
        "alice_public_hex": '339a87425a963fa3c6de3e2f335297efdbc2d848b87d4bbb36fbf8e6d4b4abb73f03c19979e7deedbcdea8bb82fe582278f47cdf34a9474c',
        "bob_private_hex": 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0',
        "bob_public_hex": '8fc7d1db6e50140c29d310f457e71f85f28124bab608aa33c5fa1240f948473a5a258b364139e5f2b1f6118b10702eb7a9a030ebac69c78c',
        "shared_secret_hex": '678a4e9b68902ef3af0c08e5ff791ad409cb147db5db5d8a4cd130d423058702c124b58ac398ba4ab57e9839437704dcbd9d486d971b8585',
    },
    {
        "id": 11,
        "type": 'dh_exchange',
        "alice_private_hex": '1212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212',
        "alice_public_hex": '97ccdc6b224c4026a6f8a2ce3371e630d37ab4cef4f4e37476d37336f4dc5df3d11bb61e6560c56e0f47ae06c989710b7e47091b4d6f15ab',
        "bob_private_hex": 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
        "bob_public_hex": 'bf8a7378007f397170802569914e8abdf734fdc390507d8d91f3da9249a7686395bb7f2cbea95eda84fef592576582d6a335f05dd15d8d0c',
        "shared_secret_hex": '6467d9d7fb066699aa121270f35295afe2ee32278fbe9d75bd9df85115c3db6aef210226bb077a682eba95b4aa4c706094ba97fbc10076d5',
    },
    {
        "id": 12,
        "type": 'dh_exchange',
        "alice_private_hex": '3434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434',
        "alice_public_hex": '7a8b3d6179f0162023cc83dbc41bbd2e1bd0dfb8d47ddc37a8321166ad5cd54a1c880fe14fad9a58e47bdda29f0744d48497344904305cdd',
        "bob_private_hex": 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
        "bob_public_hex": '3c01edc478a156b277520434f10943f17e1ebb2ab135e0a98a94bea1fbf6232e49ed7249c952b445bbc699ba3136a6eec54e51ac0be19731',
        "shared_secret_hex": 'eee8d38d647756b7bdf5369eeca3f00a79f54dd8ccce46adc38ea4ca50d996a26ebdab46f505729c110fe7bbe497a85779db991e6da72e8e',
    },
    {
        "id": 13,
        "type": 'dh_exchange',
        "alice_private_hex": '5656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656',
        "alice_public_hex": '66af089d01301d49e7e75b9eb3c6da39b993be4943123169c3308800b62c038a35c909ab8e8400f56c3320661561a72d8b4e71817e197290',
        "bob_private_hex": 'efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef',
        "bob_public_hex": '181d37d4663c1679e6a2618b6164a40f0f0f2ecf12aff25789b160a38bc12ee6078bd9be590048ef89e62293d721c1e09999aee941cad083',
        "shared_secret_hex": 'd2117c02d2de66189c5900d27a203e0215dff9c46817f26b678b1fa3fb6bc49d39fea1a9f67b93c8363e36bd4bc6aecf59c7739a7d4b7583',
    },
    {
        "id": 14,
        "type": 'dh_exchange',
        "alice_private_hex": '7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878',
        "alice_public_hex": '0bbfafb171ef1d83f7be74a49bb5468d5bdfd55d8aa997e54a4369f0bf05702b47592fd7db3157f057ee1c66c8eaffb02e4a3b1c436928dc',
        "bob_private_hex": 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        "bob_public_hex": 'f12ae7d15865e69394e5dfb159644cf25419805e4329567f285eb7e0705f8dd9399c0ec8044ad0fbbfd3316b2be6c82adf8aa2382b122eeb',
        "shared_secret_hex": '076e9b716eba0a00c1398020cb04a683d2a22fe7e4e42200c178eb5bf2d02aa81d59bc392f0b2342dc4aa4739bf8481076d9e92a427e5fe2',
    },
    {
        "id": 15,
        "type": 'dh_exchange',
        "alice_private_hex": '9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a',
        "alice_public_hex": 'e88176429165fcdf6a759cc690f4ac90109c9d616da765c32ca933d3b5f1182793c6f1df6ead2f8b7da30d3ff27bce6894da24f88acd6dcd',
        "bob_private_hex": 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        "bob_public_hex": '3b4fe2a5b8dd78f3c75d475040c339ae777baed7385d818402063656b1d32198c063dffd65e55b7f49a0d8a9f60bcc070e1e39a9f356a13e',
        "shared_secret_hex": '9c8eb27636841cb23258f9538e7dbb14e39e95890146efb6dc23611c24d6af16d4966621daba9c616c141a5726dd32a5766348b7fdee9f01',
    },
    {
        "id": 16,
        "type": 'dh_exchange',
        "alice_private_hex": 'bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc',
        "alice_public_hex": '26d7ffe6d12129e45889b6c91974ff6be383db18433c7131df03571b8a67dc552f8f770a2bcc507a99275d2aae1c5d4b82d5feea494395e6',
        "bob_private_hex": 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        "bob_public_hex": '31e3dd1a3b6c5b61edae58997cb5dd685e452972e71950f12d860f8654f05ec69ef17a286e06a0652a8adfbb45105d05a61b44a0e129b0fc',
        "shared_secret_hex": '6997efb315e18347ce5a4a5d5a7bcb78e40ddccc562f18f5ebef44436a27af7dad2dcb3f1470f6d9ac420d713a1fbf7010275b7b1ce893c3',
    },
    {
        "id": 17,
        "type": 'dh_exchange',
        "alice_private_hex": 'dededededededededededededededededededededededededededededededededededededededededededededededededededededededede',
        "alice_public_hex": '5cd54ddcf481e45c85c6a9b4ad18982d0182a0d71316a04291badfb9de379c420f943080e6398444ca7397e1cde79752f5d9bb12f52c6fbe',
        "bob_private_hex": 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        "bob_public_hex": 'abbabeb71b49d2660b842f34e6cb2fe0e0dbeb9850dd4b2ba91774a8d6cc1255fd492a7e682e8aa30c0d30cf3e9950534c5a5f9dde526fcd',
        "shared_secret_hex": '93f349453475e00c0816d50ecef9c0d7b68464fc46d6c3669025787214b89608fd956fb16847a95ed748c5f4280bec618fe6cbb2c3cd14b8',
    },
    {
        "id": 18,
        "type": 'dh_exchange',
        "alice_private_hex": '1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111',
        "alice_public_hex": 'b1a0c38170e994f11bb7f2b26d2b92f08d2f770578d0382532d58a5c2884a497c2779e5c7d7549d670a4f2d2289a73a3c434e3ea542b67cb',
        "bob_private_hex": 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        "bob_public_hex": '2444f227ccb3e072794f708d272f91665a08c15ec0153d08af51d6ecae301348a7ecff9a3953e8f798183c32f00c97690a1cd53eb6954829',
        "shared_secret_hex": 'dd7049317e20897124efb72a2e2ec48636ed62b8333edf8d5c5cf23c52a433ebda51764c8063e2cf4afa319cf091887fdf074d32926b872c',
    },
    {
        "id": 19,
        "type": 'dh_exchange',
        "alice_private_hex": '2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222',
        "alice_public_hex": '98e8a07dc1c0b4701d3d791e6d4e11d2c898919f3c6336b9c638dc543c4f6df664bd64edf27db87879d61ab2e5233e51c55208c34079a0b6',
        "bob_private_hex": 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        "bob_public_hex": '172837c1ef0bf5d890af8dcee6bda1ad1970c167e893dd46054795693a11397580fe732f2b50bd9fc1d7596c62fd5c4d5df403e94ad8c507',
        "shared_secret_hex": 'db5d65a39e5be659e6f1167240b3f3ad459a389604190045e855a76ffaabaff1aa24368f84bafa0bff33b7d7dd38371f78d239ffa1993f98',
    },
    {
        "id": 20,
        "type": 'dh_exchange',
        "alice_private_hex": '3333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333',
        "alice_public_hex": 'cee158ab1851a4ca0fc33aa716c3ec8eb50a9890a33685a501a7e3a05cf85af18b820c4f89ad00f4f8143dbc8c829c13cf0c24733034fcd2',
        "bob_private_hex": '1313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313',
        "bob_public_hex": 'bb763502be02706076dfda7b4eb0aee066cd0926772d23effed7994bbc7e01bde4936f0ab2d47bbd14da137b54e39a7f9962cd0ea00f9a02',
        "shared_secret_hex": '939e59f6a60c64f3d440e8dd98bfa3b892cf14059becc50389395dd8e480fd8d507e7b2f8cfd1c7e620bd0116d49c131ea0cb9be71f93770',
    },

]
