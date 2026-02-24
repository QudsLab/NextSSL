"""Elliptic Curve Cryptography."""
import ctypes
from enum import IntEnum
from typing import Tuple
from .._loader import get_loader


class ECCCurve(IntEnum):
    """ECC Curves."""
    ED25519 = 0      # EdDSA signing
    CURVE25519 = 1   # X25519 key exchange
    ED448 = 2        # Ed448 signing
    CURVE448 = 3     # X448 key exchange
    RISTRETTO255 = 4 # Ristretto group


class ECC:
    """Elliptic curve cryptography operations."""
    
    KEY_SIZES = {
        ECCCurve.ED25519: (32, 64, 64),      # (private, public, signature)
        ECCCurve.CURVE25519: (32, 32, 32),   # (private, public, shared)
        ECCCurve.ED448: (57, 57, 114),
        ECCCurve.CURVE448: (56, 56, 56),
        ECCCurve.RISTRETTO255: (32, 32, 64),
    }
    
    def __init__(self, curve: ECCCurve = ECCCurve.ED25519, use_system: bool = True):
        """
        Initialize ECC operations.
        
        Args:
            curve: Elliptic curve to use
            use_system: Use system library
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("core", "main")
        self.curve = curve
        
        if curve not in self.KEY_SIZES:
            raise ValueError(f"Unknown curve: {curve}")
        
        # TODO: Setup function signatures
    
    def keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a keypair.
        
        Returns:
            (secret_key, public_key)
        """
        # TODO: Implement
        raise NotImplementedError("ECC API pending - functions not yet exposed in C layer")
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message (EdDSA curves).
        
        Args:
            message: Message to sign
            secret_key: Signing key
        
        Returns:
            Signature
        """
        if self.curve not in (ECCCurve.ED25519, ECCCurve.ED448):
            raise ValueError(f"Curve {self.curve} does not support signing")
        
        # TODO: Implement
        raise NotImplementedError("ECC sign API pending")
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Signer's public key
        
        Returns:
            True if valid
        """
        # TODO: Implement
        raise NotImplementedError("ECC verify API pending")
    
    def shared_secret(self, secret_key: bytes, public_key: bytes) -> bytes:
        """
        Compute ECDH shared secret (X25519/X448).
        
        Args:
            secret_key: Our secret key
            public_key: Their public key
        
        Returns:
            Shared secret
        """
        if self.curve not in (ECCCurve.CURVE25519, ECCCurve.CURVE448):
            raise ValueError(f"Curve {self.curve} does not support key exchange")
        
        # TODO: Implement
        raise NotImplementedError("ECDH API pending")
