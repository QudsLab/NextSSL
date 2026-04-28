# Base58Check — Base58 + double-SHA256 4-byte checksum
meta = {
    "group": "encoding",
    "algorithm": "base58check",
    "source": "bitcoin-core",
    "source_ref": "KAT/repo/encoding/base58check / Bitcoin Base58Check spec",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # From keis/base58 README (Python lib)
    {"id": "base58check-basic-0001",
     "input_ascii": "hello world",
     "output_ascii": "3vQB7B6MrGQZaxCuFg4oh"},
    # Invalid checksum must fail decode
    {"id": "base58check-invalid-0001",
     "encoded": "4vQB7B6MrGQZaxCuFg4oh",
     "valid": False,
     "note": "First character changed → checksum mismatch"},
    # Known Bitcoin WIF private key (version byte 0x80)
    {"id": "base58check-wif-0001",
     "input_hex": "800c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d",
     "output_ascii": "5HueCGU8rMjxECyDialwujzXLDABOKN2HNmDSdBPVGDCMFGhyiK",
     "note": "WIF uncompressed: version=0x80 + 32-byte key + 4-byte checksum"},
    # Empty payload
    {"id": "base58check-empty-0001",
     "input_hex": "00",
     "output_ascii": "1Wh4bh",
     "note": "Single version byte 0x00, no payload"},
    {
        "id": 5,
        "version_hex": "00",
        "payload_hex": "0000000000000000000000000000000000000000",
        "encoded": "1111111111111111111114oLvT2",
    },
    {
        "id": 6,
        "version_hex": "00",
        "payload_hex": "0101010101010101010101010101010101010101",
        "encoded": "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf",
    },
    {
        "id": 7,
        "version_hex": "00",
        "payload_hex": "751e76e8199196d454941c45d1b3a323f1433bd6",
        "encoded": "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    },
    {
        "id": 8,
        "version_hex": "05",
        "payload_hex": "a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        "encoded": "3H8F9dX9VK5rToBZirXp87AtciABbuGJdd",
    },
    {
        "id": 9,
        "version_hex": "80",
        "payload_hex": "0000000000000000000000000000000000000000000000000000000000000000",
        "encoded": "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU",
    },
    {
        "id": 10,
        "version_hex": "80",
        "payload_hex": "0101010101010101010101010101010101010101010101010101010101010101",
        "encoded": "5HpjE2Hs7vjU4SN3YyPQCdhzCu92WoEeuE6PWNuiPyTu3ESGnzn",
    },
    {
        "id": 11,
        "version_hex": "80",
        "payload_hex": "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d",
        "encoded": "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
    },
    {
        "id": 12,
        "version_hex": "04",
        "payload_hex": "746573747061796c6f6164",
        "encoded": "YuUbvyNnLU4zCdQQj4Uhn",
    },
    {
        "id": 13,
        "version_hex": "00",
        "payload_hex": "68656c6c6f",
        "encoded": "12L5B5yqsf7vwb",
    },
    {
        "id": 14,
        "version_hex": "00",
        "payload_hex": "89abcdef89abcdef89abcdef89abcdef89abcdef",
        "encoded": "1DYwPTp6PAnXhbaUeHgTXwYV4UNuN85ZJw",
    },
    {
        "id": 15,
        "version_hex": "06",
        "payload_hex": "00000000000000000000000000000000",
        "encoded": "NQ9Siqho2ywWjgt837GS9naPK9mC",
    },
    {
        "id": 16,
        "version_hex": "10",
        "payload_hex": "7465737474657374746573747465737474657374",
        "encoded": "7d26fvrReqJbUNJurFdeFDa1AtJtEAg2YB",
    },
    {
        "id": 17,
        "version_hex": "00",
        "payload_hex": "000102030405060708090a0b0c0d0e0f10111213",
        "encoded": "112D2adLM3UKy4Z4giRbReR6gjWuvHUqB",
    },
    {
        "id": 18,
        "version_hex": "01",
        "payload_hex": "00010203040506070809",
        "encoded": "2d7iPHQ4FjxRbFRFmaB4",
    },
    {
        "id": 19,
        "version_hex": "00",
        "payload_hex": "616263",
        "encoded": "14h3c6cfU92",
    },
    {
        "id": 20,
        "version_hex": "00",
        "payload_hex": "73686f7274",
        "encoded": "12UCh2qWrfM72t",
    },

]
