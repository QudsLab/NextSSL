"""NextSSL: Comprehensive cryptography library with PQC support.

Complete implementation of 100+ cryptographic algorithms:
- Hash: SHA-2/3, BLAKE2/3, Argon2, Keccak, legacy (MD5, SHA1, etc.)
- PQC: ML-KEM, ML-DSA, Falcon, SPHINCS+, HQC, McEliece
- Primitives: AES (15+ modes), ChaCha20-Poly1305, ECC (Ed25519/448, Curve25519/448, Ristretto255)
- MAC: HMAC, CMAC, Poly1305, SipHash
- KDF: HKDF, KDF-SHAKE256, TLS 1.3 HKDF-Expand-Label
- Encoding: Base64, Hex, FlexFrame-70
- DHCM: Dynamic Hash Cost Model for all algorithms
- PoW: Proof-of-Work client/server
- Root: DRBG and UDBF for deterministic testing
- Unsafe: Legacy broken algorithms (MD2/4/5, SHA0/1) for compatibility only

⚠️ WARNING: The 'unsafe' module contains BROKEN algorithms! Use only for legacy compatibility.
"""

__version__ = "0.0.1"

# Core modules
from . import dhcm
from . import pow
from . import pqc
from . import primitives
from . import kdf
from . import encoding

# Hash modules (complete implementations)
from . import hash_complete as hash

# Special namespaces
from . import root      # DRBG and UDBF
from . import unsafe    # Legacy broken algorithms

# Convenience imports
from .dhcm import DHCM, DHCMAlgorithm, DHCMDifficultyModel
from .pow import PoWClient, PoWServer, PoWAlgorithm
from .pqc import KEM, KEMAlgorithm, Sign, SignAlgorithm
from .hash_complete import Hash, HashAlgorithm, BLAKE2, SHAKE, Argon2
from .primitives import AES, AESMode, ChaCha20Poly1305
from .primitives import Ed25519, Ed448, Curve25519, Curve448, Ristretto255, Elligator2
from .primitives import MAC, MACAlgorithm, SipHash
from .kdf import HKDF, KDF_SHAKE256, TLS13_HKDF, KDFAlgorithm
from .encoding import Base64, Hex, FlexFrame70, b64encode, b64decode, hexencode, hexdecode

__all__ = [
    # Version
    '__version__',
    
    # Modules
    'dhcm',
    'pow',
    'pqc',
    'hash',
    'primitives',
    'kdf',
    'encoding',
    'root',
    'unsafe',
    
    # DHCM
    'DHCM',
    'DHCMAlgorithm',
    'DHCMDifficultyModel',
    
    # PoW
    'PoWClient',
    'PoWServer',
    'PoWAlgorithm',
    
    # PQC
    'KEM',
    'KEMAlgorithm',
    'Sign',
    'SignAlgorithm',
    
    # Hash
    'Hash',
    'HashAlgorithm',
    'BLAKE2',
    'SHAKE',
    'Argon2',
    
    # Cipher
    'AES',
    'AESMode',
    'ChaCha20Poly1305',
    
    # ECC
    'Ed25519',
    'Ed448',
    'Curve25519',
    'Curve448',
    'Ristretto255',
    'Elligator2',
    
    # MAC
    'MAC',
    'MACAlgorithm',
    'SipHash',
    
    # KDF
    'HKDF',
    'KDF_SHAKE256',
    'TLS13_HKDF',
    'KDFAlgorithm',
    
    # Encoding
    'Base64',
    'Hex',
    'FlexFrame70',
    'b64encode',
    'b64decode',
    'hexencode',
    'hexdecode',
]
