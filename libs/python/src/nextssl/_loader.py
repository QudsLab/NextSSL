"""Platform-aware loader for the NextSSL native shared library."""
from __future__ import annotations

import ctypes
import os
import platform as _platform


def _find_lib() -> str:
    system = _platform.system()
    ext_map = {"Windows": ".dll", "Linux": ".so", "Darwin": ".dylib"}
    ext = ext_map.get(system)
    if ext is None:
        raise OSError(f"Unsupported platform: {system}")

    lib_name = f"nextssl{ext}"
    lib_dir = os.path.join(os.path.dirname(__file__), "lib")
    path = os.path.join(lib_dir, lib_name)

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"NextSSL native library not found: {path}\n"
            f"Platform detected: {system}.\n"
            f"Ensure you installed the platform-specific wheel for your OS.\n"
            f"Expected: {lib_name} inside the package lib/ directory."
        )
    return path


def _load() -> ctypes.CDLL:
    try:
        return ctypes.CDLL(_find_lib())
    except OSError as exc:
        raise ImportError(f"Failed to load NextSSL library: {exc}") from exc


#: The loaded native library handle.  All API modules import from here.
lib: ctypes.CDLL = _load()
