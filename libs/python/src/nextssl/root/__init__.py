"""Root-level operations: DRBG and UDBF (User Determined Byte Feeder)."""
import ctypes
from typing import Optional
from .._loader import get_loader


class DRBG:
    """
    CTR_DRBG (AES-256 based) - Deterministic Random Bit Generator.
    
    Available in ALL PQC libraries. Provides deterministic randomness
    for testing and reproducible results.
    """
    
    def __init__(self, use_system: bool = False):
        """
        Initialize DRBG.
        
        Args:
            use_system: Use system library (default: PQC library)
        """
        loader = get_loader()
        # DRBG functions available in PQC libraries
        self._lib = loader.load_system() if use_system else loader.load("pqc", "partial")
        
        # Setup function signatures
        # int pqc_randombytes_seed(const unsigned char *seed, size_t seed_len)
        self._lib.pqc_randombytes_seed.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        self._lib.pqc_randombytes_seed.restype = ctypes.c_int
        
        # int pqc_randombytes_reseed(const unsigned char *seed, size_t seed_len)
        self._lib.pqc_randombytes_reseed.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        self._lib.pqc_randombytes_reseed.restype = ctypes.c_int
    
    def seed(self, seed: bytes) -> None:
        """
        Initialize DRBG with seed (AES-256 CTR_DRBG).
        
        Args:
            seed: 48-byte seed (384 bits for AES-256 CTR_DRBG)
        
        Raises:
            ValueError: If seeding fails
        """
        if len(seed) != 48:
            raise ValueError("Seed must be 48 bytes for AES-256 CTR_DRBG")
        
        ret = self._lib.pqc_randombytes_seed(seed, len(seed))
        if ret != 0:
            raise ValueError(f"DRBG seeding failed with code {ret}")
    
    def reseed(self, seed: bytes) -> None:
        """
        Reseed DRBG with additional entropy.
        
        Args:
            seed: Additional seed data (48 bytes recommended)
        
        Raises:
            ValueError: If reseeding fails
        """
        ret = self._lib.pqc_randombytes_reseed(seed, len(seed))
        if ret != 0:
            raise ValueError(f"DRBG reseeding failed with code {ret}")


class UDBF:
    """
    UDBF (User Determined Byte Feeder) - Root-level control.
    
    Allows injecting custom randomness source for complete determinism.
    **WARNING**: Only use for testing! Never in production.
    """
    
    def __init__(self, use_system: bool = False):
        """
        Initialize UDBF.
        
        Args:
            use_system: Use system library (default: PQC library)
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("pqc", "partial")
        
        # Setup function signature
        # int pqc_set_udbf(const unsigned char *buf, size_t len)
        self._lib.pqc_set_udbf.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        self._lib.pqc_set_udbf.restype = ctypes.c_int
    
    def set(self, buffer: bytes) -> None:
        """
        Set UDBF buffer (replaces random source completely).
        
        **DANGER**: This gives you complete control over "random" bytes.
        Only use for testing NIST KAT vectors or debugging.
        
        Args:
            buffer: Byte buffer to use as randomness source
        
        Raises:
            ValueError: If setting fails
        """
        ret = self._lib.pqc_set_udbf(buffer, len(buffer))
        if ret != 0:
            raise ValueError(f"UDBF setup failed with code {ret}")
    
    def clear(self) -> None:
        """
        Clear UDBF (restore system randomness).
        """
        # Setting empty buffer clears UDBF
        self.set(b"")


# Global instances for convenience
_drbg = None
_udbf = None


def get_drbg() -> DRBG:
    """Get global DRBG instance."""
    global _drbg
    if _drbg is None:
        _drbg = DRBG()
    return _drbg


def get_udbf() -> UDBF:
    """Get global UDBF instance."""
    global _udbf
    if _udbf is None:
        _udbf = UDBF()
    return _udbf


# Convenience functions
def seed_drbg(seed: bytes) -> None:
    """Seed global DRBG instance."""
    get_drbg().seed(seed)


def reseed_drbg(seed: bytes) -> None:
    """Reseed global DRBG instance."""
    get_drbg().reseed(seed)


def set_udbf(buffer: bytes) -> None:
    """
    Set User Determined Byte Feeder (DANGEROUS - testing only!).
    
    WARNING: This replaces all randomness with your buffer.
    """
    get_udbf().set(buffer)


def clear_udbf() -> None:
    """Clear UDBF and restore system randomness."""
    get_udbf().clear()
