"""Complete hash implementation - ALL variants from primitives and legacy."""
import ctypes
from enum import IntEnum
from typing import Optional, Union
from ._loader import get_loader


class HashAlgorithm(IntEnum):
    """ALL Hash Algorithms from NextSSL."""
    # Primitive Fast
    SHA224 = 0
    SHA256 = 1
    SHA384 = 2
    SHA512 = 3
    SHA512_224 = 4
    SHA512_256 = 5
    BLAKE2B = 10
    BLAKE2S = 11
    BLAKE3 = 12
    
    # Primitive Memory Hard (Argon2 variants)
    ARGON2D = 100
    ARGON2I = 101
    ARGON2ID = 102
    
    # Primitive Sponge/XOF
    SHA3_224 = 200
    SHA3_256 = 201
    SHA3_384 = 202
    SHA3_512 = 203
    KECCAK_224 = 210
    KECCAK_256 = 211
    KECCAK_384 = 212
    KECCAK_512 = 213
    SHAKE128 = 220
    SHAKE256 = 221
    
    # Legacy Alive (deprecated but still used)
    MD5 = 300
    SHA1 = 301
    RIPEMD160 = 302
    WHIRLPOOL = 303
    WHIRLPOOL0 = 304
    WHIRLPOOLT = 305
    NT = 310
    
    # Legacy Unsafe (broken, for compatibility only)
    MD2 = 400
    MD4 = 401
    SHA0 = 402
    HAS160 = 403
    RIPEMD128 = 404
    RIPEMD256 = 405
    RIPEMD320 = 406


# Output sizes mapping
DIGEST_SIZES = {
    # Fast
    HashAlgorithm.SHA224: 28,
    HashAlgorithm.SHA256: 32,
    HashAlgorithm.SHA384: 48,
    HashAlgorithm.SHA512: 64,
    HashAlgorithm.SHA512_224: 28,
    HashAlgorithm.SHA512_256: 32,
    HashAlgorithm.BLAKE2B: 64,  # default, configurable
    HashAlgorithm.BLAKE2S: 32,  # default, configurable
    HashAlgorithm.BLAKE3: 32,   # default, XOF
    # Sponge
    HashAlgorithm.SHA3_224: 28,
    HashAlgorithm.SHA3_256: 32,
    HashAlgorithm.SHA3_384: 48,
    HashAlgorithm.SHA3_512: 64,
    HashAlgorithm.KECCAK_224: 28,
    HashAlgorithm.KECCAK_256: 32,
    HashAlgorithm.KECCAK_384: 48,
    HashAlgorithm.KECCAK_512: 64,
    # Legacy Alive
    HashAlgorithm.MD5: 16,
    HashAlgorithm.SHA1: 20,
    HashAlgorithm.RIPEMD160: 20,
    HashAlgorithm.WHIRLPOOL: 64,
    HashAlgorithm.WHIRLPOOL0: 64,
    HashAlgorithm.WHIRLPOOLT: 64,
    HashAlgorithm.NT: 16,
    # Legacy Unsafe
    HashAlgorithm.MD2: 16,
    HashAlgorithm.MD4: 16,
    HashAlgorithm.SHA0: 20,
    HashAlgorithm.HAS160: 20,
    HashAlgorithm.RIPEMD128: 16,
    HashAlgorithm.RIPEMD256: 32,
    HashAlgorithm.RIPEMD320: 40,
}


class Hash:
    """Hash function wrapper - supports all NextSSL hash algorithms."""
    
    def __init__(self, algorithm: HashAlgorithm, use_system: bool = True):
        """
        Initialize hash function.
        
        Args:
            algorithm: Hash algorithm to use
            use_system: Use system library (all algorithms)
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("hash", "main")
        self.algorithm = algorithm
        self.digest_size = DIGEST_SIZES.get(algorithm, 32)
        
        # TODO: Setup function signatures once hash library API is finalized
        # API pattern: leyline_<algo>(data, len, digest)
    
    def digest(self, data: bytes, output_length: Optional[int] = None) -> bytes:
        """
        One-shot hash computation.
        
        Args:
            data: Data to hash
            output_length: Override output length (for XOF/variable-length hashes)
        
        Returns:
            Hash digest
        """
        # TODO: Implement once hash library API is finalized
        raise NotImplementedError(f"Hash API pending - algorithm {self.algorithm.name}")


class BLAKE2:
    """BLAKE2 with configurable output length and keyed mode."""
    
    def __init__(self, variant: str = 'b', key: Optional[bytes] = None, use_system: bool = True):
        """
        Args:
            variant: 'b' for BLAKE2b (up to 64 bytes), 's' for BLAKE2s (up to 32 bytes)
            key: Optional key for MAC mode
            use_system: Use system library
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("hash", "main")
        self.variant = variant
        self.key = key
        self.max_output = 64 if variant == 'b' else 32
    
    def digest(self, data: bytes, output_length: int = None) -> bytes:
        """
        Compute BLAKE2 hash.
        
        Args:
            data: Input data
            output_length: Output size (default: 64 for b, 32 for s)
        
        Returns:
            Hash digest
        """
        if output_length is None:
            output_length = self.max_output
        if output_length > self.max_output:
            raise ValueError(f"Output length {output_length} exceeds max {self.max_output}")
        
        # TODO: Call leyline_blake2<b|s> with key if provided
        raise NotImplementedError("BLAKE2 API pending")


class SHAKE:
    """SHAKE XOF (Extendable Output Function)."""
    
    def __init__(self, bits: int = 128, use_system: bool = True):
        """
        Args:
            bits: 128 or 256
            use_system: Use system library
        """
        if bits not in (128, 256):
            raise ValueError("bits must be 128 or 256")
        
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("hash", "main")
        self.bits = bits
    
    def digest(self, data: bytes, output_length: int) -> bytes:
        """
        Compute SHAKE hash with arbitrary output length.
        
        Args:
            data: Input data
            output_length: Desired output length in bytes
        
        Returns:
            Hash digest
        """
        # TODO: Call leyline_shake<128|256>
        raise NotImplementedError("SHAKE API pending")


class Argon2:
    """Argon2 password hashing - all three variants."""
    
    def __init__(self, variant: str = 'id', use_system: bool = True):
        """
        Args:
            variant: 'd' (data-dependent), 'i' (data-independent), 'id' (hybrid, recommended)
            use_system: Use system library
        """
        if variant not in ('d', 'i', 'id'):
            raise ValueError("variant must be 'd', 'i', or 'id'")
        
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("hash", "main")
        self.variant = variant
        
        # TODO: Setup argon2<d|i|id>_hash_raw and _hash_encoded functions
    
    def hash_raw(
        self,
        password: bytes,
        salt: bytes,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32
    ) -> bytes:
        """
        Hash password with Argon2 (raw output).
        
        Args:
            password: Password to hash
            salt: Salt (16 bytes recommended)
            time_cost: Number of iterations
            memory_cost: Memory usage in KiB
            parallelism: Number of parallel threads
            hash_len: Output hash length
        
        Returns:
            Raw hash bytes
        """
        # TODO: Call argon2<variant>_hash_raw
        raise NotImplementedError(f"Argon2{self.variant} raw API pending")
    
    def hash_encoded(
        self,
        password: bytes,
        salt: bytes,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32
    ) -> str:
        """
        Hash password with Argon2 (PHC encoded string).
        
        Returns:
            PHC encoded string (e.g., $argon2id$v=19$m=65536$...)
        """
        # TODO: Call argon2<variant>_hash_encoded
        raise NotImplementedError(f"Argon2{self.variant} encoded API pending")
    
    def verify(self, encoded: str, password: bytes) -> bool:
        """
        Verify password against PHC encoded hash.
        
        Args:
            encoded: PHC formatted hash string
            password: Password to verify
        
        Returns:
            True if password matches
        """
        # TODO: Call argon2<variant>_verify
        raise NotImplementedError(f"Argon2{self.variant} verify API pending")
