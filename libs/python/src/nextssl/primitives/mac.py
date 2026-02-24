"""Message Authentication Codes."""
import ctypes
from enum import IntEnum
from typing import Optional
from .._loader import get_loader


class MACAlgorithm(IntEnum):
    """MAC Algorithms."""
    HMAC_SHA256 = 0
    HMAC_SHA512 = 1
    HMAC_SHA1 = 2
    HMAC_MD5 = 3
    POLY1305 = 10
    CMAC_AES = 20


class MAC:
    """Message Authentication Code operations."""
    
    TAG_SIZES = {
        MACAlgorithm.HMAC_SHA256: 32,
        MACAlgorithm.HMAC_SHA512: 64,
        MACAlgorithm.HMAC_SHA1: 20,
        MACAlgorithm.HMAC_MD5: 16,
        MACAlgorithm.POLY1305: 16,
        MACAlgorithm.CMAC_AES: 16,
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
    
    def compute(self, data: bytes) -> bytes:
        """
        Compute MAC tag.
        
        Args:
            data: Data to authenticate
        
        Returns:
            MAC tag
        """
        # TODO: Implement
        raise NotImplementedError("MAC API pending - functions not yet exposed in C layer")
    
    def verify(self, data: bytes, tag: bytes) -> bool:
        """
        Verify MAC tag.
        
        Args:
            data: Data to verify
            tag: MAC tag to check
        
        Returns:
            True if valid
        """
        expected = self.compute(data)
        # Constant-time comparison
        return len(tag) == len(expected) and all(a == b for a, b in zip(tag, expected))
