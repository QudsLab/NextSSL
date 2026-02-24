"""Unsafe/legacy cryptographic primitives - BROKEN, DO NOT USE IN PRODUCTION!

These algorithms have known vulnerabilities and MUST NOT be used for security.
They are included only for:
- Legacy system compatibility
- Historical research
- Breaking old protocols
- Educational purposes

⚠️ WARNING: Using these algorithms can compromise your security! ⚠️
"""

import ctypes
from enum import IntEnum
from typing import Optional
from .._loader import get_loader


class UnsafeHashAlgorithm(IntEnum):
    """BROKEN hash algorithms - DO NOT USE!"""
    # Collision-broken (NEVER use for signatures or integrity)
    MD2 = 0      # Broken since 2004
    MD4 = 1      # Broken since 1996 
    MD5 = 2      # Collision attacks (2004), prefix collisions (2012)
    SHA0 = 3     # Withdrawn 1995, collisions found 1998
    SHA1 = 4     # Collision attacks (SHAttered 2017)
    
    # Weak algorithms
    HAS160 = 10  # Korean standard, weak design
    RIPEMD128 = 11  # Insufficient security margin
    RIPEMD256 = 12  # Not RIPEMD160 extension, weak
    RIPEMD320 = 13  # Not RIPEMD160 extension, weak
    
    # Legacy alive but avoid
    NTLM = 20    # MD4-based Windows hash


class UnsafeHash:
    """
    UNSAFE hash functions.
    
    ⚠️ WARNING: These are cryptographically broken! ⚠️
    """
    
    DIGEST_SIZES = {
        UnsafeHashAlgorithm.MD2: 16,
        UnsafeHashAlgorithm.MD4: 16,
        UnsafeHashAlgorithm.MD5: 16,
        UnsafeHashAlgorithm.SHA0: 20,
        UnsafeHashAlgorithm.SHA1: 20,
        UnsafeHashAlgorithm.HAS160: 20,
        UnsafeHashAlgorithm.RIPEMD128: 16,
        UnsafeHashAlgorithm.RIPEMD256: 32,
        UnsafeHashAlgorithm.RIPEMD320: 40,
        UnsafeHashAlgorithm.NTLM: 16,
    }
    
    def __init__(self, algorithm: UnsafeHashAlgorithm, use_system: bool = True):
        """
        Initialize unsafe hash.
        
        ⚠️ DO NOT USE FOR SECURITY! ⚠️
        
        Args:
            algorithm: Legacy hash algorithm
            use_system: Use system library
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("hash", "partial")
        self.algorithm = algorithm
        
        # Map algorithm to function name
        func_map = {
            UnsafeHashAlgorithm.MD2: "leyline_md2",
            UnsafeHashAlgorithm.MD4: "leyline_md4",
            UnsafeHashAlgorithm.MD5: "leyline_md5",
            UnsafeHashAlgorithm.SHA0: "leyline_sha0",
            UnsafeHashAlgorithm.SHA1: "leyline_sha1",
            UnsafeHashAlgorithm.HAS160: "leyline_has160",
            UnsafeHashAlgorithm.RIPEMD128: "leyline_ripemd128",
            UnsafeHashAlgorithm.RIPEMD256: "leyline_ripemd256",
            UnsafeHashAlgorithm.RIPEMD320: "leyline_ripemd320",
            UnsafeHashAlgorithm.NTLM: "leyline_nt_hash",
        }
        
        self.func_name = func_map[algorithm]
        func = getattr(self._lib, self.func_name)
        
        # Setup signature: int func(const char *data, size_t len, char *out)
        func.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        func.restype = ctypes.c_int
        self._hash_func = func
    
    def digest(self, data: bytes) -> bytes:
        """
        Compute hash digest.
        
        ⚠️ WARNING: Output is NOT secure! ⚠️
        
        Args:
            data: Data to hash
        
        Returns:
            Hash digest (INSECURE!)
        
        Raises:
            ValueError: If hashing fails
        """
        digest_size = self.DIGEST_SIZES[self.algorithm]
        output = ctypes.create_string_buffer(digest_size)
        
        ret = self._hash_func(data, len(data), output)
        if ret != 0:
            raise ValueError(f"Hash computation failed with code {ret}")
        
        return bytes(output.raw)
    
    def hexdigest(self, data: bytes) -> str:
        """
        Compute hash digest as hex string.
        
        ⚠️ WARNING: Output is NOT secure! ⚠️
        
        Args:
            data: Data to hash
        
        Returns:
            Hex-encoded hash (INSECURE!)
        """
        return self.digest(data).hex()


# Convenience functions with strong warnings
def md5(data: bytes) -> bytes:
    """
    MD5 hash (BROKEN - collisions trivial!).
    
    ⚠️ DO NOT USE FOR SECURITY! ⚠️
    Use only for legacy compatibility or checksums.
    """
    return UnsafeHash(UnsafeHashAlgorithm.MD5).digest(data)


def sha1(data: bytes) -> bytes:
    """
    SHA-1 hash (BROKEN - SHAttered attack 2017!).
    
    ⚠️ DO NOT USE FOR SECURITY! ⚠️
    Use SHA-256 or SHA3-256 instead.
    """
    return UnsafeHash(UnsafeHashAlgorithm.SHA1).digest(data)


def sha0(data: bytes) -> bytes:
    """
    SHA-0 hash (WITHDRAWN 1995!).
    
    ⚠️ EXTREMELY BROKEN! Historical purposes only! ⚠️
    """
    return UnsafeHash(UnsafeHashAlgorithm.SHA0).digest(data)


def md4(data: bytes) -> bytes:
    """
    MD4 hash (BROKEN since 1996!).
    
    ⚠️ EXTREMELY BROKEN! Historical purposes only! ⚠️
    """
    return UnsafeHash(UnsafeHashAlgorithm.MD4).digest(data)


def md2(data: bytes) -> bytes:
    """
    MD2 hash (BROKEN since 2004!).
    
    ⚠️ EXTREMELY BROKEN! Historical purposes only! ⚠️
    """
    return UnsafeHash(UnsafeHashAlgorithm.MD2).digest(data)
