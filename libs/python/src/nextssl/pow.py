"""PoW (Proof of Work) - Client and Server implementations."""
import ctypes
from enum import IntEnum
from typing import Optional, Tuple
from ._loader import get_loader


class PoWAlgorithm(IntEnum):
    """PoW Hash Algorithms - ALL supported variants."""
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


class PoWDifficultyModel(IntEnum):
    """Difficulty measurement models."""
    LEADING_ZEROS_BITS = 0
    LEADING_ZEROS_BYTES = 1
    LESS_THAN_TARGET = 2


class PoWClient:
    """PoW Client - Solve challenges."""
    
    def __init__(self, algorithm: PoWAlgorithm = PoWAlgorithm.SHA256, use_system: bool = True):
        """
        Initialize PoW client.
        
        Args:
            algorithm: Hash algorithm to use
            use_system: Use system library vs individual client library
        """
        loader = get_loader()
        if use_system:
            self._lib = loader.load_system()
        else:
            self._lib = loader.load("pow_client", "main")
        
        self.algorithm = algorithm
        # TODO: Setup function signatures based on PoW client API
    
    def solve(
        self,
        challenge: bytes,
        difficulty: int,
        max_iterations: Optional[int] = None
    ) -> Optional[Tuple[bytes, int]]:
        """
        Solve a PoW challenge.
        
        Args:
            challenge: Challenge data
            difficulty: Number of leading zeros required
            max_iterations: Maximum iterations (None = unlimited)
        
        Returns:
            (solution_nonce, iterations) or None if not found
        """
        # TODO: Implement once PoW client API is finalized
        raise NotImplementedError("PoW client API pending")


class PoWServer:
    """PoW Server - Issue and verify challenges."""
    
    def __init__(self, algorithm: PoWAlgorithm = PoWAlgorithm.SHA256, use_system: bool = True):
        """
        Initialize PoW server.
        
        Args:
            algorithm: Hash algorithm to use
            use_system: Use system library vs individual server library
        """
        loader = get_loader()
        if use_system:
            self._lib = loader.load_system()
        else:
            self._lib = loader.load("pow_server", "main")
        
        self.algorithm = algorithm
        # TODO: Setup function signatures
    
    def generate_challenge(self, difficulty: int) -> bytes:
        """
        Generate a new PoW challenge.
        
        Args:
            difficulty: Required difficulty level
        
        Returns:
            Challenge data
        """
        # TODO: Implement
        raise NotImplementedError("PoW server API pending")
    
    def verify(
        self,
        challenge: bytes,
        solution: bytes,
        difficulty: int
    ) -> bool:
        """
        Verify a PoW solution.
        
        Args:
            challenge: Original challenge
            solution: Proposed solution nonce
            difficulty: Required difficulty
        
        Returns:
            True if valid
        """
        # TODO: Implement
        raise NotImplementedError("PoW server API pending")
