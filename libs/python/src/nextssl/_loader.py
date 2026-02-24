"""Binary loader for NextSSL native libraries."""
import os
import sys
import platform
import ctypes
from pathlib import Path
from typing import Optional


def get_platform_info():
    """Detect platform and return (platform_name, lib_extension)."""
    system = platform.system().lower()
    if system == "windows":
        return "windows", ".dll"
    elif system == "darwin":
        return "mac", ".dylib"
    elif system == "linux":
        return "linux", ".so"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def find_bin_directory() -> Optional[Path]:
    """Find the bin directory with compiled libraries."""
    # Try multiple locations
    locations = [
        Path(__file__).parent.parent.parent.parent.parent / "bin",  # In repo
        Path(sys.prefix) / "share" / "nextssl" / "bin",              # Installed
        Path.home() / ".nextssl" / "bin",                           # User dir
    ]
    
    platform_name, _ = get_platform_info()
    for loc in locations:
        platform_dir = loc / platform_name
        if platform_dir.exists():
            return platform_dir
    
    return None


class LibraryLoader:
    """Loads NextSSL native libraries."""
    
    def __init__(self):
        self.platform_name, self.lib_ext = get_platform_info()
        self.bin_dir = find_bin_directory()
        self._cache = {}
    
    def load(self, lib_name: str, tier: str = "main") -> ctypes.CDLL:
        """
        Load a library by name.
        
        Args:
            lib_name: Library name without extension (e.g., "dhcm", "pow_client")
            tier: Directory tier ("partial", "base", "main")
        
        Returns:
            ctypes.CDLL object
        """
        cache_key = f"{tier}/{lib_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        if not self.bin_dir:
            raise RuntimeError(
                "Could not find NextSSL binaries. "
                "Please ensure binaries are built or installed."
            )
        
        lib_file = lib_name + self.lib_ext
        lib_path = self.bin_dir / tier / lib_file
        
        if not lib_path.exists():
            raise FileNotFoundError(
                f"Library not found: {lib_path}\n"
                f"Available tiers: partial, base, main"
            )
        
        try:
            lib = ctypes.CDLL(str(lib_path))
            self._cache[cache_key] = lib
            return lib
        except OSError as e:
            raise RuntimeError(f"Failed to load {lib_path}: {e}")
    
    def load_system(self) -> ctypes.CDLL:
        """Load the system library (all-in-one)."""
        return self.load("system", "main")


# Global loader instance
_loader = LibraryLoader()


def get_loader() -> LibraryLoader:
    """Get the global library loader instance."""
    return _loader
