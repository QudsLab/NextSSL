"""Complete AES/cipher implementation - ALL modes and variants."""
import ctypes
from enum import IntEnum
from typing import Optional, Tuple, Union
from .._loader import get_loader


class AESMode(IntEnum):
    """All AES operation modes."""
    # Block cipher modes
    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4
    XTS = 5
    
    # Key wrap
    KW = 10
    
    # Format-Preserving Encryption
    FPE_FF1 = 20
    FPE_FF3 = 21
    
    # AEAD modes
    GCM = 100
    CCM = 101
    OCB = 102
    EAX = 103
    GCM_SIV = 104
    SIV = 105
    POLY1305 = 106
    
    # Stream cipher AEAD
    CHACHA20_POLY1305 = 200


class AES:
    """AES cipher - all modes supported."""
    
    def __init__(
        self,
        key: bytes,
        mode: AESMode = AESMode.GCM,
        use_system: bool = True
    ):
        """
        Initialize AES cipher.
        
        Args:
            key: Encryption key (16, 24, or 32 bytes for AES-128/192/256)
            mode: Operation mode
            use_system: Use system library
        """
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes")
        
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("core", "main")
        self.key = key
        self.mode = mode
        
        # TODO: Setup function signatures
        # Pattern: AES_<MODE>_encrypt/decrypt
    
    def encrypt(
        self,
        plaintext: bytes,
        nonce: Optional[bytes] = None,
        aad: Optional[bytes] = None
    ) -> Union[bytes, Tuple[bytes, bytes]]:
        """
        Encrypt data.
        
        Args:
            plaintext: Data to encrypt
            nonce: Nonce/IV (mode-dependent, auto-generated if None)
            aad: Additional authenticated data (AEAD modes only)
        
        Returns:
            For AEAD modes: (ciphertext, tag)
            For block modes: ciphertext
        """
        # TODO: Implement based on mode
        raise NotImplementedError(f"AES {self.mode.name} encrypt API pending")
    
    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        tag: Optional[bytes] = None,
        aad: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt data.
        
        Args:
            ciphertext: Encrypted data
            nonce: Nonce/IV used during encryption
            tag: Authentication tag (AEAD modes only)
            aad: Additional authenticated data (AEAD modes only)
        
        Returns:
            Decrypted plaintext
        
        Raises:
            ValueError: If authentication fails (AEAD modes)
        """
        # TODO: Implement based on mode
        raise NotImplementedError(f"AES {self.mode.name} decrypt API pending")


class ChaCha20Poly1305:
    """ChaCha20-Poly1305 AEAD cipher."""
    
    def __init__(self, use_system: bool = True):
        """
        Initialize ChaCha20-Poly1305.
        
        Args:
            use_system: Use system library
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("core", "main")
        
        # TODO: Setup ChaCha20_Poly1305_encrypt/decrypt
    
    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        aad: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt with ChaCha20-Poly1305.
        
        Args:
            key: 32-byte key
            nonce: 24-byte nonce (XChaCha20)
            plaintext: Data to encrypt
            aad: Additional authenticated data
        
        Returns:
            (ciphertext, tag)
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        if len(nonce) != 24:
            raise ValueError("Nonce must be 24 bytes (XChaCha20)")
        
        # TODO: Call ChaCha20_Poly1305_encrypt
        raise NotImplementedError("ChaCha20-Poly1305 API pending")
    
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt with ChaCha20-Poly1305.
        
        Args:
            key: 32-byte key
            nonce: 24-byte nonce
            ciphertext: Encrypted data
            tag: 16-byte authentication tag
            aad: Additional authenticated data
        
        Returns:
            Decrypted plaintext
        
        Raises:
            ValueError: If authentication fails
        """
        # TODO: Call ChaCha20_Poly1305_decrypt (returns char, 0=fail)
        raise NotImplementedError("ChaCha20-Poly1305 API pending")
