"""AES encryption and AEAD modes."""
import ctypes
from enum import IntEnum
from typing import Optional, Tuple
from .._loader import get_loader


class AESMode(IntEnum):
    """AES operation modes."""
    # Block cipher modes
    ECB = 0
    CBC = 1
    CTR = 2
    CFB = 3
    OFB = 4
    
    # AEAD modes
    GCM = 10
    CCM = 11
    EAX = 12
    OCB = 13
    
    # Stream cipher AEAD
    CHACHA20_POLY1305 = 20


class AES:
    """AES cipher operations."""
    
    def __init__(self, key: bytes, mode: AESMode = AESMode.GCM, use_system: bool = True):
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
    
    def encrypt(
        self,
        plaintext: bytes,
        nonce: Optional[bytes] = None,
        aad: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt data.
        
        Args:
            plaintext: Data to encrypt
            nonce: Nonce/IV (mode-dependent, auto-generated if None)
            aad: Additional authenticated data (AEAD modes only)
        
        Returns:
            (ciphertext, tag) for AEAD modes
            (ciphertext, nonce) for non-AEAD modes
        """
        # TODO: Implement
        raise NotImplementedError("AES API pending - functions not yet exposed in C layer")
    
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
        # TODO: Implement
        raise NotImplementedError("AES API pending")
