"""Hash functions - Fast, Memory-Hard, Sponge/XOF, Legacy."""
import ctypes
from enum import IntEnum
from typing import Optional
from ._loader import get_loader


class HashAlgorithm(IntEnum):
    """Hash Algorithms - ALL from primitives/hash and legacy."""
    # Primitive Fast
    SHA256 = 0
    SHA512 = 1
    BLAKE2B = 2
    BLAKE2S = 3
    BLAKE3 = 4
    
    # Primitive Memory Hard (Argon2 variants)
    ARGON2D = 100
    ARGON2I = 101
    ARGON2ID = 102
    
    # Primitive Sponge/XOF
    SHA3_256 = 200
    SHA3_512 = 201
    KECCAK_256 = 202
    SHAKE128 = 203
    SHAKE256 = 204
    
    # Legacy Alive (deprecated but still used)
    MD5 = 300
    SHA1 = 301
    RIPEMD160 = 302
    WHIRLPOOL = 303
    NT = 304
    
    # Legacy Unsafe (broken, for compatibility only)
    MD2 = 400
    MD4 = 401
    SHA0 = 402
    HAS160 = 403
    RIPEMD128 = 404
    RIPEMD256 = 405
    RIPEMD320 = 406


class Hash:
    """Hash function wrapper."""
    
    # Output sizes in bytes (for fixed-length hashes)
    DIGEST_SIZES = {
        # Primitive Fast
        HashAlgorithm.SHA256: 32,
        HashAlgorithm.SHA512: 64,
        HashAlgorithm.BLAKE2B: 64,
        HashAlgorithm.BLAKE2S: 32,
        HashAlgorithm.BLAKE3: 32,
        # Primitive Sponge/XOF
        HashAlgorithm.SHA3_256: 32,
        HashAlgorithm.SHA3_512: 64,
        HashAlgorithm.KECCAK_256: 32,
        # SHAKE128/256 are XOF - variable length output
        # Legacy Alive
        HashAlgorithm.MD5: 16,
        HashAlgorithm.SHA1: 20,
        HashAlgorithm.RIPEMD160: 20,
        HashAlgorithm.WHIRLPOOL: 64,
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
        
        # TODO: Setup function signatures once hash API is defined
    
    def digest(self, data: bytes) -> bytes:
        """
        One-shot hash computation.
        
        Args:
            data: Data to hash
        
        Returns:
            Hash digest
        """
        # TODO: Implement once hash library API is finalized
        raise NotImplementedError("Hash API pending - functions not yet exposed in C layer")
    
    def update(self, data: bytes):
        """
        Incremental hash update (for streaming).
        
        Args:
            data: Data chunk to hash
        """
        # TODO: Implement streaming API
        raise NotImplementedError("Streaming hash API pending")
    
    def finalize(self) -> bytes:
        """
        Finalize incremental hash.
        
        Returns:
            Hash digest
        """
        # TODO: Implement
        raise NotImplementedError("Streaming hash API pending")


class Argon2d:
    """Argon2d password hashing (data-dependent, faster but vulnerable to side-channels)."""
    
    def __init__(self, use_system: bool = True):
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("hash", "main")
        # TODO: Setup functions
    
    def hash(
        self,
        password: bytes,
        salt: bytes,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32
    ) -> bytes:
        """
        Hash password with Argon2d.
        
        Args:
            password: Password to hash
            salt: Salt (16 bytes recommended)
            time_cost: Number of iterations
            memory_cost: Memory usage in KiB
            parallelism: Number of parallel threads
            hash_len: Output hash length
        
        Returns:
            Hash bytes
        """
        # TODO: Implement
        raise NotImplementedError("Argon2d API pending")


class Argon2i:
    """Argon2i password hashing (data-independent, resistant to side-channels)."""
    
    def __init__(self, use_system: bool = True):
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("hash", "main")
        # TODO: Setup functions
    
    def hash(
        self,
        password: bytes,
        salt: bytes,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32
    ) -> bytes:
        """
        Hash password with Argon2i.
        
        Args:
            password: Password to hash
            salt: Salt (16 bytes recommended)
            time_cost: Number of iterations
            memory_cost: Memory usage in KiB
            parallelism: Number of parallel threads
            hash_len: Output hash length
        
        Returns:
            Hash bytes
        """
        # TODO: Implement
        raise NotImplementedError("Argon2i API pending")


class Argon2id:
    """Argon2id password hashing (hybrid, recommended variant)."""
    
    def __init__(self, use_system: bool = True):
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("hash", "main")
        # TODO: Setup functions
    
    def hash(
        self,
        password: bytes,
        salt: bytes,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32
    ) -> bytes:
        """
        Hash password with Argon2id (recommended).
        
        Args:
            password: Password to hash
            salt: Salt (16 bytes recommended)
            time_cost: Number of iterations
            memory_cost: Memory usage in KiB
            parallelism: Number of parallel threads
            hash_len: Output hash length
        
        Returns:
            Hash bytes
        """
        # TODO: Implement
        raise NotImplementedError("Argon2id API pending")
