"""Complete encoding utilities - Base64, Hex, FlexFrame."""
import ctypes
from enum import IntEnum
from typing import Union
from ._loader import get_loader


class EncodingType(IntEnum):
    """Encoding types."""
    BASE64 = 0
    BASE64_URL = 1
    HEX = 2
    HEX_UPPER = 3
    FLEXFRAME_70 = 10


class Base64:
    """Base64 encoding/decoding (standard and URL-safe)."""
    
    def __init__(self, url_safe: bool = False, use_system: bool = True):
        """
        Initialize Base64 encoder.
        
        Args:
            url_safe: Use URL-safe variant (- and _ instead of + and /)
            use_system: Use system library
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("core", "main")
        self.url_safe = url_safe
        
        # TODO: Setup base64_encode/decode, base64url_encode/decode
    
    def encode(self, data: bytes, padding: bool = True) -> str:
        """
        Encode to Base64.
        
        Args:
            data: Data to encode
            padding: Include padding (=)
        
        Returns:
            Base64-encoded string
        """
        # TODO: Call base64_encode or base64url_encode
        raise NotImplementedError("Base64 encode API pending")
    
    def decode(self, encoded: str) -> bytes:
        """
        Decode from Base64.
        
        Args:
            encoded: Base64 string
        
        Returns:
            Decoded bytes
        
        Raises:
            ValueError: If invalid encoding
        """
        # TODO: Call base64_decode or base64url_decode
        raise NotImplementedError("Base64 decode API pending")


class Hex:
    """Hexadecimal encoding/decoding."""
    
    def __init__(self, uppercase: bool = False, use_system: bool = True):
        """
        Initialize Hex encoder.
        
        Args:
            uppercase: Use uppercase letters (A-F)
            use_system: Use system library
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("core", "main")
        self.uppercase = uppercase
        
        # TODO: Setup hex_encode/decode functions
    
    def encode(self, data: bytes) -> str:
        """
        Encode to hexadecimal.
        
        Args:
            data: Data to encode
        
        Returns:
            Hex string
        """
        # TODO: Call hex_encode (returns lowercase or uppercase)
        # Python fallback: data.hex().upper() if self.uppercase else data.hex()
        return data.hex().upper() if self.uppercase else data.hex()
    
    def decode(self, encoded: str) -> bytes:
        """
        Decode from hexadecimal.
        
        Args:
            encoded: Hex string
        
        Returns:
            Decoded bytes
        
        Raises:
            ValueError: If invalid hex
        """
        # TODO: Call hex_decode
        # Python fallback:
        return bytes.fromhex(encoded)


class FlexFrame70:
    """FlexFrame-70: Flexible frame format for structured data encoding."""
    
    def __init__(self, use_system: bool = True):
        """
        Initialize FlexFrame-70 encoder.
        
        Args:
            use_system: Use system library
        """
        loader = get_loader()
        self._lib = loader.load_system() if use_system else loader.load("core", "main")
        
        # TODO: Setup flexframe70_encode/decode
    
    def encode(self, data: bytes, metadata: bytes = b"") -> str:
        """
        Encode to FlexFrame-70.
        
        Args:
            data: Primary data
            metadata: Optional metadata
        
        Returns:
            FlexFrame-70 encoded string
        """
        # TODO: Call flexframe70_encode
        raise NotImplementedError("FlexFrame-70 encode API pending")
    
    def decode(self, encoded: str) -> tuple[bytes, bytes]:
        """
        Decode from FlexFrame-70.
        
        Args:
            encoded: FlexFrame-70 string
        
        Returns:
            (data, metadata)
        
        Raises:
            ValueError: If invalid encoding
        """
        # TODO: Call flexframe70_decode
        raise NotImplementedError("FlexFrame-70 decode API pending")


# Convenience functions
def b64encode(data: bytes, url_safe: bool = False) -> str:
    """Encode bytes to Base64 string."""
    return Base64(url_safe=url_safe).encode(data)


def b64decode(encoded: str, url_safe: bool = False) -> bytes:
    """Decode Base64 string to bytes."""
    return Base64(url_safe=url_safe).decode(encoded)


def hexencode(data: bytes, uppercase: bool = False) -> str:
    """Encode bytes to hex string."""
    return Hex(uppercase=uppercase).encode(data)


def hexdecode(encoded: str) -> bytes:
    """Decode hex string to bytes."""
    return Hex().decode(encoded)
