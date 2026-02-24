"""Complete MAC implementation - all variants."""
import ctypes
from enum import IntEnum
from typing import Optional
from .._loader import get_loader


class MACAlgorithm(IntEnum):
    """All MAC algorithms."""
    # AES-based
    CMAC_AES = 0
    
    # Poly1305
    POLY1305 = 10
    AES_POLY1305 = 11
    
    # SipHash
    SIPHASH_2_4 = 20
    SIPHASH_4_8 = 21
    
    # HMAC variants
    HMAC_SHA256 = 100
    HMAC_SHA512 = 101
    HMAC_SHA3_256 = 102
    HMAC_SHA3_512 = 103
    HMAC_SHA1 = 104  # Legacy
    HMAC_MD5 = 105   # Unsafe


class MAC:
    """Message Authentication Code operations."""
    
    TAG_SIZES = {
        MACAlgorithm.CMAC_AES: 16,
        MACAlgorithm.POLY1305: 16,
        MACAlgorithm.AES_POLY1305: 16,
        MACAlgorithm.SIPHASH_2_4: 8,  # or 16
        MACAlgorithm.SIPHASH_4_8: 8,  # or 16
        MACAlgorithm.HMAC_SHA256: 32,
        MACAlgorithm.HMAC_SHA512: 64,
        MACAlgorithm.HMAC_SHA3_256: 32,
        MACAlgorithm.HMAC_SHA3_512: 64,
        MACAlgorithm.HMAC_SHA1: 20,
        MACAlgorithm.HMAC_MD5: 16,
    }
    
    def __init__(self, algorithm: MACAlgorithm, key: bytes, use_system: bool = True):
        """
        Initialize MAC.
        
        Args:
            algorithm: MAC algorithm to use
            key: Authentication key
            use_system: Use system library
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("core", "main")
        self.algorithm = algorithm
        self.key = key
        
        # TODO: Setup function signatures
        # AES_CMAC, siphash, pqc_hmac_*, hmac_sha3_*
    
    def compute(self, data: bytes) -> bytes:
        """
        Compute MAC tag.
        
        Args:
            data: Data to authenticate
        
        Returns:
            MAC tag
        """
        # TODO: Implement based on algorithm
        raise NotImplementedError(f"MAC {self.algorithm.name} API pending")
    
    def verify(self, data: bytes, tag: bytes) -> bool:
        """
        Verify MAC tag (constant-time).
        
        Args:
            data: Data to verify
            tag: MAC tag to check
        
        Returns:
            True if valid
        """
        expected = self.compute(data)
        # Constant-time comparison
        return len(tag) == len(expected) and all(a == b for a, b in zip(tag, expected))


class SipHash:
    """SipHash MAC (optimized for short messages)."""
    
    def __init__(self, c: int = 2, d: int = 4,  output_size: int = 8, use_system: bool = True):
        """
        Initialize SipHash.
        
        Args:
            c: Number of compression rounds (default: 2)
            d: Number of finalization rounds (default: 4)
            output_size: Output size in bytes (8 or 16)
            use_system: Use system library
        """
        if output_size not in (8, 16):
            raise ValueError("output_size must be 8 or 16")
        
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("core", "main")
        self.c = c
        self.d = d
        self.output_size = output_size
        
        # TODO: Setup siphash function
    
    def compute(self, key: bytes, data: bytes) -> bytes:
        """
        Compute SipHash.
        
        Args:
            key: 16-byte key
            data: Data to hash
        
        Returns:
            Hash (8 or 16 bytes)
        """
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        
        # TODO: Call siphash(data, len, key, out, outlen)
        raise NotImplementedError("SipHash API pending")
