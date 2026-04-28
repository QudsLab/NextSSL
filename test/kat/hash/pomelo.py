# KAT/data/hash/pomelo.py
# Known Answer Tests for POMELO password hashing

meta = {
    "group": "hash",
    "algorithm": "Pomelo",
    "source": "POMELO-v3 official test vectors — PHC submission by Hongjun Wu",
    "source_ref": "https://www.password-hashing.net/submissions/POMELO-v3.tar.gz",
    "generated_by": "GitHub Copilot (Claude Sonnet 4.6)",
    "date": "2025-07-01",
    "notes": (
        "POMELO is a memory-hard password hashing function (PHC submission by Hongjun Wu). "
        "Vectors extracted directly from pomelo_testvectors.txt distributed inside "
        "the official POMELO-v3.tar.gz PHC submission archive. "
        "Parameters: t_cost (0..3), m_cost (0..3), output always 256 bytes (outlen=256). "
        "Password and salt are sequential byte sequences (binary, not ASCII). "
        "Case fields: password_hex, salt_hex, t_cost, m_cost, output_len, output_hex."
    ),
}

cases = [
    # From pomelo_testvectors.txt in official POMELO-v3.tar.gz
    # All cases: t_cost=0, m_cost=0, outlen=256 bytes
    {
        "id": 1,
        "password_hex": "000102030405060708090a0b0c0d0e0f",
        "salt_hex": "01030507090b0d0f11131517191b1d1f",
        "t_cost": 0,
        "m_cost": 0,
        "output_len": 256,
        "output_hex": "105f424523592c4f2d8b9a10a0edc102176c47a077c799cb469f2b1e6143e7778e46716e6ea61b618fe2f840dbc0c2a939a4b479208e0d43fe217126d9dc5df7c4b2dd8b8550d56936b9c5cfa3c28142f09e18b7a785d688f7aff54d478163ba0ba9f561055afe630a9b535edf92278e086e92adb36f915c3bddb5ebab045c5b11aae0200ae079f4023c3387fecd889e27ec5a6f3c0b24b5d3440a276c91c3a575692340b18d6e070ddea96e3f4f5638fb3f6a6d094b59a435a0778cce6b8bcdb63259ad38bfa0cbd07c72191823dfe398fbfcf65c61c1aa3d57d15dadd99e8eb71ff4107e02969cff5427185846d2c6f564d4c8efaf3b1bdefaa6241902da97",
    },
    {
        "id": 2,
        "password_hex": "000102030405060708090a0b0c0d0e0f",
        "salt_hex": "01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f",
        "t_cost": 0,
        "m_cost": 0,
        "output_len": 256,
        "output_hex": "21fcfdfe3af69fd8d587e4fd4b9d5f020e41375e92fb9846716dc9b6ebaf0b7fa2748f987461d7ec445d11c7d87967e734bde72389b5162f807308a04f877115e8f84adb9d7497b2c670619138b49ab5e4e0f7f3a6a6627d557fcf7046eea95edff1dd55f2ae1d89865cb9fc7130335dfc9ec0b9c44d7e324d508a9bed9b7f2cda712301c34dcf5a75181d187b40049bfe7f88815bfe9fe8180de80beaef9f6a6b804a0bab928e3041a11d62f619384868b4b18ece5aedae28e65e463da6cd9fa22daa36c897cf5493f00ff969c57c9a1c4c350c31108d8bcf982fdd3e40cc63b039ab89e97979fab157a4dc8fbc59b68aa8723ba9046d87b03a8cf05c3a6882",
    },
    {
        "id": 3,
        "password_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "salt_hex": "01030507090b0d0f11131517191b1d1f",
        "t_cost": 0,
        "m_cost": 0,
        "output_len": 256,
        "output_hex": "62da075e8851e9403a065272c271111f9887acd28bc80aea3b0e2532b164a2c2639f4a5758a08035ee0bffab4771f672905acdca629850cde0fe9475b9165d9d96a9b192bd88d56e72d718c63d25d422cd0b045bcb1587f6ebb3537896e22bcc743c7639e24946759e3d32533554f84fde35d1655b6c602c36e24cb13ad0b541064d2ea9993e5f24294d31eba6f7a455b19578dfdd39f537bbde3e101bb9625a51979b190f87fb85a55b30dcc437e6559c8c38c4b1c4a7262219ca7ea4786c654ad6271e64b314332851acb8f58787adad12d3ecfa8e0bbb99d1fd6a7f726a0ddc95c10f968e56a4ff5dccca68bbd3ca86a861151e341ce631f9ac4e2c60de1b",
    },
    {
        "id": 4,
        "password_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "salt_hex": "01030507090b0d0f11131517191b1d1f21232527292b2d2f31333537393b3d3f",
        "t_cost": 0,
        "m_cost": 0,
        "output_len": 256,
        "output_hex": "a81175e73c324a8ab285a544501031539324cfa87b2eb61bda0da6a460f47d29d6dcf9c1daf1c55e46c70d4e123dc45101296442a6c973bb7b7bef01a23bd040afeb5088573407154b861f2e11ec0600db3b8ef2b1afcac4c8a4266c8710c408b39edb99969e641aba88cbad1a42d5c042dda757f1e03af4eb284e27cc57c7fa2b504c23a853f14d4f1f607c94fb26af9322d0c5ea70b40d86333c4127ece3146365c64dc5a965fa8e8ad3e14ab3ee7498e295ee60bbd34b6e6f27a76c0e10f072ea93b3f20a0d3fe3226b7a8b4b3783c359eb387a62361cf6dd659378c5b7bb8a61a8263a38b6a3bb157e2d640fe7c0d3e83ae7819460af1d882140ba84b7ee",
    },
]
