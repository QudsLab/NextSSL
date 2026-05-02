# KAT/data/hash/sha224.py
# Known Answer Tests for SHA-224 (FIPS 180-4)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "SHA-224",
    "source": "FIPS 180-4 / di-mgt.com.au SHA test vector aggregation",
    "source_ref": "https://www.di-mgt.com.au/sha_testvectors.html",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "SHA-224 is a truncated variant of SHA-256. 28-byte output.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    },
    {
        "id": 2,
        "input_ascii": "abc",
        "output_hex": "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    },
    {
        "id": 3,
        "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "output_hex": "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
    },
    {
        "id": 4,
        "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "output_hex": "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
    },
    {
        "id": 5,
        # 1 million repetitions of "a"
        "input_ascii": "a" * 1_000_000,
        "output_hex": "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
    },
    {"id": 6, "input_ascii": "message digest", "output_hex": "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb"},
    {"id": 7, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2"},
    {"id": 8, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9"},
    {"id": 9, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e"},
    {"id": 10, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"},
    {"id": 11, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b"},
    {"id": 12, "input_ascii": "Hello, World!", "output_hex": "72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff"},
    {"id": 13, "input_ascii": "Python", "output_hex": "f8fef02326b9f70d67c68faefc4d41b3fd039d77e11643bccab9d47a"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "fb0bd626a70c28541dfa781bb5cc4d7d7f56622a58f01a0b1ddd646f"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "d40854fc9caf172067136f2e29e1380b14626bf6f0dd06779f820dcd"},
    {"id": 16, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "a88cd5cde6d6fe9136a4e58b49167461ea95d388ca2bdb7afdc3cbf4"},
    {"id": 17, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "39873a2441c56608137850f4c54dde157710b9a2b83c8bdc756dd643"},
    {"id": 18, "input_ascii": A_LONG, "output_hex": "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "fc5d6aed7146d6747dd6fca075f9fe5a30a4c0c9ff67effc484f10b5"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "b564e8a5cf20a254eb34e1ae98c3d957c351ce854491ccbeaeb220ea"},

]
