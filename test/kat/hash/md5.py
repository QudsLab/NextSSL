# KAT/data/hash/md5.py
# Known Answer Tests for MD5 (RFC 1321)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "MD5",
    "source": "RFC 1321 - The MD5 Message-Digest Algorithm, Appendix A.5",
    "source_ref": "https://www.rfc-editor.org/rfc/rfc1321",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": "MD5 is considered cryptographically broken for security purposes. Vectors from RFC 1321 §A.5.",
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": "d41d8cd98f00b204e9800998ecf8427e",
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": "0cc175b9c0f1b6a831c399e269772661",
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": "900150983cd24fb0d6963f7d28e17f72",
    },
    {
        "id": 4,
        "input_ascii": "message digest",
        "output_hex": "f96b697d7cb7938d525a2f31aaf161d0",
    },
    {
        "id": 5,
        "input_ascii": "abcdefghijklmnopqrstuvwxyz",
        "output_hex": "c3fcd3d76192e4007dfb496cca67e13b",
    },
    {
        "id": 6,
        "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "output_hex": "d174ab98d277d9f5a5611c2c9f419d9f",
    },
    {
        "id": 7,
        "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "output_hex": "57edf4a22be3c955ac49da2e2107b67a",
    },
    {"id": 8, "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "9e107d9d372bb6826bd81d3542a419d6"},
    {"id": 9, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "1055d3e698d289f2af8663725127bd4b"},
    {"id": 10, "input_ascii": "Hello, World!", "output_hex": "65a8e27d8879283831b664bd8b7f0ad4"},
    {"id": 11, "input_ascii": "Python", "output_hex": "a7f5f35426b927411fc9231b56382173"},
    {"id": 12, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "ef1772b6dff9a122358552954ad0df65"},
    {"id": 13, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "3b0c8ac703f828b04c6c197006d17218"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "014842d480b571495a4a0363793f7367"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "e510683b3f5ffe4093d021808bc6ff70"},
    {"id": 16, "input_ascii": A_LONG, "output_hex": "7707d6ae4e027c70eea2a935c2296f21"},
    {"id": 17, "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "output_hex": "8215ef0796a20bcaaae116d3876c664a"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_hex": "03dd8807a93175fb062dfb55dc7d359c"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "10eab6008d5642cf42abd2aa41f847cb"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "e807f1fcf82d132f9bb018ca6738a19f"},

]
