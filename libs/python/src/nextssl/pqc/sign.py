"""Post-Quantum Digital Signatures."""
import ctypes
from enum import IntEnum
from typing import Tuple
from .._loader import get_loader


class SignAlgorithm(IntEnum):
    """PQC Signature Algorithms."""
    # ML-DSA (Dilithium - NIST standard)
    ML_DSA_44 = 0
    ML_DSA_65 = 1
    ML_DSA_87 = 2
    
    # Falcon (Lattice-based)
    FALCON_512 = 10
    FALCON_1024 = 11
    FALCON_PADDED_512 = 12
    FALCON_PADDED_1024 = 13
    
    # SPHINCS+ (Hash-based)
    SPHINCS_SHA2_128F_SIMPLE = 20
    SPHINCS_SHA2_128S_SIMPLE = 21
    SPHINCS_SHA2_192F_SIMPLE = 22
    SPHINCS_SHA2_192S_SIMPLE = 23
    SPHINCS_SHA2_256F_SIMPLE = 24
    SPHINCS_SHA2_256S_SIMPLE = 25
    
    SPHINCS_SHAKE_128F_SIMPLE = 30
    SPHINCS_SHAKE_128S_SIMPLE = 31
    SPHINCS_SHAKE_192F_SIMPLE = 32
    SPHINCS_SHAKE_192S_SIMPLE = 33
    SPHINCS_SHAKE_256F_SIMPLE = 34
    SPHINCS_SHAKE_256S_SIMPLE = 35


class PQC_Sign:
    """Post-Quantum digital signature operations."""
    
    # Algorithm parameters: (public_key_bytes, secret_key_bytes, signature_bytes)
    PARAMS = {
        SignAlgorithm.ML_DSA_44: (1312, 2560, 2420),
        SignAlgorithm.ML_DSA_65: (1952, 4032, 3309),
        SignAlgorithm.ML_DSA_87: (2592, 4896, 4627),
        SignAlgorithm.FALCON_512: (897, 1281, 690),
        SignAlgorithm.FALCON_1024: (1793, 2305, 1330),
    }
    
    def __init__(self, algorithm: SignAlgorithm, use_system: bool = True):
        """
        Initialize PQC Signature.
        
        Args:
            algorithm: Signature algorithm to use
            use_system: Use system library (all algorithms)
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("pqc", "main")
        self.algorithm = algorithm
        
        if algorithm not in self.PARAMS:
            raise ValueError(f"Unknown signature algorithm: {algorithm}")
        
        self.pk_bytes, self.sk_bytes, self.sig_bytes = self.PARAMS[algorithm]
        
        # TODO: Setup function signatures
    
    def keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a signing keypair.
        
        Returns:
            (public_key, secret_key)
        """
        # TODO: Implement once PQC Sign API is finalized
        raise NotImplementedError("PQC Sign API pending - functions not yet exposed in C layer")
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message.
        
        Args:
            message: Message to sign
            secret_key: Signing secret key
        
        Returns:
            signature
        """
        if len(secret_key) != self.sk_bytes:
            raise ValueError(f"Invalid secret key length: {len(secret_key)} != {self.sk_bytes}")
        
        # TODO: Implement
        raise NotImplementedError("PQC Sign API pending")
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Signer's public key
        
        Returns:
            True if signature is valid
        """
        if len(signature) != self.sig_bytes:
            raise ValueError(f"Invalid signature length: {len(signature)} != {self.sig_bytes}")
        if len(public_key) != self.pk_bytes:
            raise ValueError(f"Invalid public key length: {len(public_key)} != {self.pk_bytes}")
        
        # TODO: Implement
        raise NotImplementedError("PQC Sign API pending")
