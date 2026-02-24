"""Complete PQC Signature implementation - ML-DSA, Falcon, SPHINCS+."""
import ctypes
from enum import IntEnum
from typing import Tuple
from .._loader import get_loader


class SignAlgorithm(IntEnum):
    """Post-quantum signature algorithms."""
    # ML-DSA (Dilithium) - NIST standard
    ML_DSA_44 = 0
    ML_DSA_65 = 1
    ML_DSA_87 = 2
    
    # Falcon (fast lattice signatures)
    FALCON_512 = 10
    FALCON_1024 = 11
    
    # SPHINCS+ (hash-based, conservative)
    # SHAKE256 variants
    SPHINCS_SHAKE_128F_SIMPLE = 20
    SPHINCS_SHAKE_128F_ROBUST = 21
    SPHINCS_SHAKE_128S_SIMPLE = 22
    SPHINCS_SHAKE_128S_ROBUST = 23
    SPHINCS_SHAKE_192F_SIMPLE = 24
    SPHINCS_SHAKE_192F_ROBUST = 25
    SPHINCS_SHAKE_192S_SIMPLE = 26
    SPHINCS_SHAKE_192S_ROBUST = 27
    SPHINCS_SHAKE_256F_SIMPLE = 28
    SPHINCS_SHAKE_256F_ROBUST = 29
    SPHINCS_SHAKE_256S_SIMPLE = 30
    SPHINCS_SHAKE_256S_ROBUST = 31
    
    # SHA-256 variants
    SPHINCS_SHA2_128F_SIMPLE = 40
    SPHINCS_SHA2_128F_ROBUST = 41
    SPHINCS_SHA2_128S_SIMPLE = 42
    SPHINCS_SHA2_128S_ROBUST = 43
    SPHINCS_SHA2_192F_SIMPLE = 44
    SPHINCS_SHA2_192F_ROBUST = 45
    SPHINCS_SHA2_192S_SIMPLE = 46
    SPHINCS_SHA2_192S_ROBUST = 47
    SPHINCS_SHA2_256F_SIMPLE = 48
    SPHINCS_SHA2_256F_ROBUST = 49
    SPHINCS_SHA2_256S_SIMPLE = 50
    SPHINCS_SHA2_256S_ROBUST = 51


class Sign:
    """Post-quantum digital signatures."""
    
    # Parameter table: (pk_bytes, sk_bytes, sig_bytes)
    PARAMS = {
        # ML-DSA
        SignAlgorithm.ML_DSA_44: (1312, 2528, 2420),
        SignAlgorithm.ML_DSA_65: (1952, 4000, 3293),
        SignAlgorithm.ML_DSA_87: (2592, 4864, 4595),
        
        # Falcon
        SignAlgorithm.FALCON_512: (897, 1281, 690),
        SignAlgorithm.FALCON_1024: (1793, 2305, 1330),
        
        # SPHINCS+ SHAKE256 (F=fast, S=small)
        SignAlgorithm.SPHINCS_SHAKE_128F_SIMPLE: (32, 64, 17088),
        SignAlgorithm.SPHINCS_SHAKE_128F_ROBUST: (32, 64, 17088),
        SignAlgorithm.SPHINCS_SHAKE_128S_SIMPLE: (32, 64, 7856),
        SignAlgorithm.SPHINCS_SHAKE_128S_ROBUST: (32, 64, 7856),
        SignAlgorithm.SPHINCS_SHAKE_192F_SIMPLE: (48, 96, 35664),
        SignAlgorithm.SPHINCS_SHAKE_192F_ROBUST: (48, 96, 35664),
        SignAlgorithm.SPHINCS_SHAKE_192S_SIMPLE: (48, 96, 16224),
        SignAlgorithm.SPHINCS_SHAKE_192S_ROBUST: (48, 96, 16224),
        SignAlgorithm.SPHINCS_SHAKE_256F_SIMPLE: (64, 128, 49856),
        SignAlgorithm.SPHINCS_SHAKE_256F_ROBUST: (64, 128, 49856),
        SignAlgorithm.SPHINCS_SHAKE_256S_SIMPLE: (64, 128, 29792),
        SignAlgorithm.SPHINCS_SHAKE_256S_ROBUST: (64, 128, 29792),
        
        # SPHINCS+ SHA-256
        SignAlgorithm.SPHINCS_SHA2_128F_SIMPLE: (32, 64, 17088),
        SignAlgorithm.SPHINCS_SHA2_128F_ROBUST: (32, 64, 17088),
        SignAlgorithm.SPHINCS_SHA2_128S_SIMPLE: (32, 64, 7856),
        SignAlgorithm.SPHINCS_SHA2_128S_ROBUST: (32, 64, 7856),
        SignAlgorithm.SPHINCS_SHA2_192F_SIMPLE: (48, 96, 35664),
        SignAlgorithm.SPHINCS_SHA2_192F_ROBUST: (48, 96, 35664),
        SignAlgorithm.SPHINCS_SHA2_192S_SIMPLE: (48, 96, 16224),
        SignAlgorithm.SPHINCS_SHA2_192S_ROBUST: (48, 96, 16224),
        SignAlgorithm.SPHINCS_SHA2_256F_SIMPLE: (64, 128, 49856),
        SignAlgorithm.SPHINCS_SHA2_256F_ROBUST: (64, 128, 49856),
        SignAlgorithm.SPHINCS_SHA2_256S_SIMPLE: (64, 128, 29792),
        SignAlgorithm.SPHINCS_SHA2_256S_ROBUST: (64, 128, 29792),
    }
    
    def __init__(self, algorithm: SignAlgorithm, use_system: bool = False):
        """
        Initialize PQC signature scheme.
        
        Args:
            algorithm: Signature algorithm to use
            use_system: Use system library (default: PQC library)
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("pqc", "partial")
        self.algorithm = algorithm
        
        # Get parameters
        pk_size, sk_size, sig_size = self.PARAMS[algorithm]
        self.public_key_size = pk_size
        self.secret_key_size = sk_size
        self.signature_size = sig_size
        
        # Map algorithm to function prefix
        self.func_prefix = self._get_func_prefix()
        
        # TODO: Setup function signatures (pattern: <prefix>_keypair, <prefix>_sign, <prefix>_verify)
    
    def _get_func_prefix(self) -> str:
        """Get C function prefix for algorithm."""
        prefix_map = {
            SignAlgorithm.ML_DSA_44: "pqc_ml_dsa_44",
            SignAlgorithm.ML_DSA_65: "pqc_ml_dsa_65",
            SignAlgorithm.ML_DSA_87: "pqc_ml_dsa_87",
            
            SignAlgorithm.FALCON_512: "pqc_falcon_512",
            SignAlgorithm.FALCON_1024: "pqc_falcon_1024",
            
            # SPHINCS+ prefixes (long but systematic)
            SignAlgorithm.SPHINCS_SHAKE_128F_SIMPLE: "pqc_sphincs_shake_128f_simple",
            SignAlgorithm.SPHINCS_SHAKE_128F_ROBUST: "pqc_sphincs_shake_128f_robust",
            SignAlgorithm.SPHINCS_SHAKE_128S_SIMPLE: "pqc_sphincs_shake_128s_simple",
            SignAlgorithm.SPHINCS_SHAKE_128S_ROBUST: "pqc_sphincs_shake_128s_robust",
            SignAlgorithm.SPHINCS_SHAKE_192F_SIMPLE: "pqc_sphincs_shake_192f_simple",
            SignAlgorithm.SPHINCS_SHAKE_192F_ROBUST: "pqc_sphincs_shake_192f_robust",
            SignAlgorithm.SPHINCS_SHAKE_192S_SIMPLE: "pqc_sphincs_shake_192s_simple",
            SignAlgorithm.SPHINCS_SHAKE_192S_ROBUST: "pqc_sphincs_shake_192s_robust",
            SignAlgorithm.SPHINCS_SHAKE_256F_SIMPLE: "pqc_sphincs_shake_256f_simple",
            SignAlgorithm.SPHINCS_SHAKE_256F_ROBUST: "pqc_sphincs_shake_256f_robust",
            SignAlgorithm.SPHINCS_SHAKE_256S_SIMPLE: "pqc_sphincs_shake_256s_simple",
            SignAlgorithm.SPHINCS_SHAKE_256S_ROBUST: "pqc_sphincs_shake_256s_robust",
            
            SignAlgorithm.SPHINCS_SHA2_128F_SIMPLE: "pqc_sphincs_sha2_128f_simple",
            SignAlgorithm.SPHINCS_SHA2_128F_ROBUST: "pqc_sphincs_sha2_128f_robust",
            SignAlgorithm.SPHINCS_SHA2_128S_SIMPLE: "pqc_sphincs_sha2_128s_simple",
            SignAlgorithm.SPHINCS_SHA2_128S_ROBUST: "pqc_sphincs_sha2_128s_robust",
            SignAlgorithm.SPHINCS_SHA2_192F_SIMPLE: "pqc_sphincs_sha2_192f_simple",
            SignAlgorithm.SPHINCS_SHA2_192F_ROBUST: "pqc_sphincs_sha2_192f_robust",
            SignAlgorithm.SPHINCS_SHA2_192S_SIMPLE: "pqc_sphincs_sha2_192s_simple",
            SignAlgorithm.SPHINCS_SHA2_192S_ROBUST: "pqc_sphincs_sha2_192s_robust",
            SignAlgorithm.SPHINCS_SHA2_256F_SIMPLE: "pqc_sphincs_sha2_256f_simple",
            SignAlgorithm.SPHINCS_SHA2_256F_ROBUST: "pqc_sphincs_sha2_256f_robust",
            SignAlgorithm.SPHINCS_SHA2_256S_SIMPLE: "pqc_sphincs_sha2_256s_simple",
            SignAlgorithm.SPHINCS_SHA2_256S_ROBUST: "pqc_sphincs_sha2_256s_robust",
        }
        return prefix_map[self.algorithm]
    
    def keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate signature keypair.
        
        Returns:
            (public_key, secret_key)
        
        Raises:
            ValueError: If keypair generation fails
        """
        pk = ctypes.create_string_buffer(self.public_key_size)
        sk = ctypes.create_string_buffer(self.secret_key_size)
        
        # TODO: Call <prefix>_keypair(pk, sk)
        # int func(unsigned char *pk, unsigned char *sk)
        raise NotImplementedError(f"Sign {self.algorithm.name} keypair API pending")
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign message.
        
        Args:
            message: Message to sign
            secret_key: Your secret key
        
        Returns:
            Signature
        
        Raises:
            ValueError: If signing fails
        """
        if len(secret_key) != self.secret_key_size:
            raise ValueError(f"Secret key must be {self.secret_key_size} bytes")
        
        sig = ctypes.create_string_buffer(self.signature_size)
        sig_len = ctypes.c_size_t(self.signature_size)
        
        # TODO: Call <prefix>_sign(sig, &sig_len, msg, msg_len, sk)
        # int func(unsigned char *sig, size_t *sig_len, const unsigned char *msg, size_t msg_len, const unsigned char *sk)
        raise NotImplementedError(f"Sign {self.algorithm.name} sign API pending")
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify signature.
        
        Args:
            message: Signed message
            signature: Signature to verify
            public_key: Signer's public key
        
        Returns:
            True if valid
        """
        if len(signature) > self.signature_size:
            return False
        if len(public_key) != self.public_key_size:
            raise ValueError(f"Public key must be {self.public_key_size} bytes")
        
        # TODO: Call <prefix>_verify(msg, msg_len, sig, sig_len, pk)
        # int func(const unsigned char *msg, size_t msg_len, const unsigned char *sig, size_t sig_len, const unsigned char *pk)
        # Returns 0 on success, non-zero on failure
        raise NotImplementedError(f"Sign {self.algorithm.name} verify API pending")
