# KAT/data/hash/skein512.py
# Known Answer Tests for Skein-512 (512-bit output, 512-bit internal state)

A_LONG = "a"*1000000

meta = {
    "group": "hash",
    "algorithm": "Skein-512",
    "source": "Skein v1.3 specification — Ferguson, Lucks, Schneier, Whiting, Bellare, Kohno, Callas, Walker",
    "source_ref": "https://www.schneier.com/academic/skein/",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "Skein-512 uses a 512-bit Threefish internal state.  This is the simple "
        "hash mode (no tree, no MAC, no personalisation) with 512-bit output. "
        "Vectors computed with the pyskein library (Skein v1.3)."
    ),
}

cases = [
    {
        "id": 1,
        "input_ascii": "",
        "output_hex": (
            "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4"
            "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
        ),
    },
    {
        "id": 2,
        "input_ascii": "a",
        "output_hex": (
            "b1cd8d33f61b3737adfd59bb13ad82f4a9548e92f22956a8976cca3fdb7fee4f"
            "e91698146c4197cec85d38b83c5d93bdba92c01fd9a53870d0c7f967bc62bdce"
        ),
    },
    {
        "id": 3,
        "input_ascii": "abc",
        "output_hex": (
            "8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f938"
            "93ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75"
        ),
    },
    {
        "id": 4,
        "input_ascii": "message digest",
        "output_hex": (
            "15b73c158ffb875fed4d72801ded0794c720b121c0c78edf45f900937e6933d9"
            "e21a3a984206933d504b5dbb2368000411477ee1b204c986068df77886542fcc"
        ),
    },
    {
        "id": 5,
        "input_ascii": "The quick brown fox jumps over the lazy dog",
        "output_hex": (
            "94c2ae036dba8783d0b3f7d6cc111ff810702f5c77707999be7e1c9486ff238a"
            "7044de734293147359b4ac7e1d09cd247c351d69826b78dcddd951f0ef912713"
        ),
    },
    {"id": 6, "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "23793ad900ef12f9165c8080da6fdfd2c8354a2929b8aadf83aa82a3c6470342f57cf8c035ec0d97429b626c4d94f28632c8f5134fd367dca5cf293d2ec13f8c"},
    {"id": 7, "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "output_hex": "0c6bed927e022f5ddcf81877d42e5f75798a9f8fd3ede3d83baac0a2f364b082e036c11af35fe478745459dd8f5c0b73efe3c56ba5bb2009208d5a29cc6e469c"},
    {"id": 8, "input_ascii": "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "output_hex": "2ca9fcffb3456f297d1b5f407014ecb856f0baac8eb540f534b1f187196f21e88f31103128c2f03fcc9857d7a58eb66f9525e2302d88833ee069295537a434ce"},
    {"id": 9, "input_ascii": "The quick brown fox jumps over the lazy cog", "output_hex": "7f81113575e4b4d3441940e87aca331e6d63d103fe5107f29cd877af0d0f5e0ea34164258c60da5190189d0872e63a96596d2ef25e709099842da71d64111e0f"},
    {"id": 10, "input_ascii": "Hello, World!", "output_hex": "7c434640c75d07623bf0c2500561b6ca45ed3e3a8d84ff89a4404440d91471f8a90d6db222dc7a20f583e40fcfb2d40b19d34877fc431d2c0b0c94f293e0805b"},
    {"id": 11, "input_ascii": "Python", "output_hex": "81039b8212f936fa513b8bbbae4bb32aa2de9f8e5f6b6d01dc318cc3b5739735384145264d1763e4b36e6fa6a1a8ae0572ede8b9ff3382eb0ca57821578a36c7"},
    {"id": 12, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "5865a9bf27a1885d150e93f30b80628cc59b3b8a87419cfe88294dbf178aea5acbe9e3a01571e3bafe91e98e09ff1d9a99cb5254fcb8b0d9148577ab03d9c278"},
    {"id": 13, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "b644bd8a8dd3553be33d47b528e75f2586ca0faeab8755cc9a62e0b53029d2e02844bf67df078b4625522c8b90eeceb4a1db64b516789ccd3102a40de48a87e6"},
    {"id": 14, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "98dc948cd8379b1a27880eeedfa68b4108cfad77dd922dde8d4a7e4b897c27cdf2555515772c1443b0a9756a6cf3db3d4790b0a76f433d5e6134bba87ba191da"},
    {"id": 15, "input_ascii": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "output_hex": "cd1d378f44bc2714eb3acaf61ce3d79d8fd7bcd8a94586fa8fee4ea7ad8e4d9db10c2e623493af08d7e3b310eddb7489738a81e11098c6009579e131d74c4581"},
    {"id": 16, "input_ascii": A_LONG, "output_hex": "c9d41b77b77b77e954284185af682a5a8b25b9d31e6d58eb9fd329f5bcca34d7b285ab130a9c14c872192bcdf2b67d883280a754acba942a7cf448e841a74ed2"},
    {"id": 17, "input_ascii": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "output_hex": "ded9469f2dbb2bd32390d2a3396045bb33c706291954f66d4f296ade2c09a61eeb51a72d86e392c489b53a90536045222b40d9355d1aa187d59041b7b98e521a"},
    {"id": 18, "input_ascii": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "output_hex": "106521be7d48c73dbe2567e7609550ca5edaf0dd5058230b95711fe19294629fc7a263fbf62bea6b01f98b22d7aef979740aee851b4a36837fed3e3732e3c84a"},
    {"id": 19, "input_ascii": "0000000000000000000000000000000000000000000000000000000000000000", "output_hex": "d14c014dafb5d6ab8724092dd7738adfd9552493f219a089fc1d37d997489b19d3b82325c8b7e6171b58f4a0a774eed3572c5c014268a4fcbb5295a484e7a63a"},
    {"id": 20, "input_ascii": "1234567890", "output_hex": "5c7ddfe7eafe1c18e1e2218d6adb1bcbdec87ed33bcf5f545d1b2ab18d82d87c7a7097aca34086ac65408ac91c2060b04fe45b0d5b30a7f1e89a0f530a9dd35d"},

]
