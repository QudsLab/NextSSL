"""Binary format verification by magic bytes.

Checks that a built binary:
  1. Exists on disk and is non-empty
  2. Has the correct magic bytes for its expected format

Expected format is inferred from exec_mode + platform:
  pe_check / win        → MZ   (0x4D 0x5A)
  native win            → MZ
  macho_check / macos   → Mach-O (four known magic values)
  native macos / ios    → Mach-O
  node_wasm             → JS text glue (non-empty; no fixed magic)
  wasi_wasm             → WASM  (0x00 0x61 0x73 0x6D  = \\0asm)
  everything else       → ELF  (0x7F 0x45 0x4C 0x46  = \\x7fELF)
    (covers all Linux glibc/musl, Android, QEMU targets)
"""
from __future__ import annotations

from pathlib import Path
from typing import Tuple

# ---------------------------------------------------------------------------
# Magic constants
# ---------------------------------------------------------------------------
_PE_MAGIC:   bytes = b"MZ"
_ELF_MAGIC:  bytes = b"\x7fELF"
_WASM_MAGIC: bytes = b"\x00asm"

# All four Mach-O magic variants (LE 32/64, BE 32/64, fat)
_MACHO_MAGICS: frozenset[bytes] = frozenset({
    b"\xca\xfe\xba\xbe",  # fat / universal binary
    b"\xce\xfa\xed\xfe",  # 32-bit LE
    b"\xcf\xfa\xed\xfe",  # 64-bit LE
    b"\xbe\xba\xfe\xca",  # 32-bit BE (rare)
    b"\xfe\xed\xfa\xce",  # 32-bit BE
    b"\xfe\xed\xfa\xcf",  # 64-bit BE
})

# Header-only execution modes (no KAT possible)
HEADER_ONLY_MODES: frozenset[str] = frozenset({"pe_check", "macho_check"})


def _expected_format(exec_mode: str, platform: str) -> str:
    """Return the expected binary format string for a given variant."""
    if platform == "win" or exec_mode == "pe_check":
        return "pe"
    if platform in ("macos", "ios") or exec_mode == "macho_check":
        return "macho"
    if exec_mode == "wasi_wasm":
        return "wasm"
    if exec_mode == "node_wasm":
        return "js"
    # native linux/android and all qemu_* modes
    return "elf"


def check(lib_path: "str | Path", exec_mode: str, platform: str) -> Tuple[bool, str]:
    """Verify the binary at *lib_path* has the correct magic bytes.

    Parameters
    ----------
    lib_path:  path to the binary file
    exec_mode: Variant.exec_mode (e.g. "native", "pe_check", "qemu_arm64")
    platform:  Variant.platform  (e.g. "win", "linux-glibc", "macos")

    Returns
    -------
    (ok, message)  where ok=True means the check passed.
    """
    p = Path(lib_path)

    if not p.exists():
        return False, f"not found: {p}"
    size = p.stat().st_size
    if size == 0:
        return False, f"empty file: {p}"

    fmt = _expected_format(exec_mode, platform)

    if fmt == "pe":
        magic = p.read_bytes()[:2]
        if magic == _PE_MAGIC:
            return True, f"PE/MZ     {p.name}  ({size:,} B)"
        return False, f"bad PE magic {magic.hex()}  {p.name}"

    if fmt == "elf":
        magic = p.read_bytes()[:4]
        if magic == _ELF_MAGIC:
            return True, f"ELF       {p.name}  ({size:,} B)"
        return False, f"bad ELF magic {magic.hex()}  {p.name}"

    if fmt == "macho":
        magic = p.read_bytes()[:4]
        if magic in _MACHO_MAGICS:
            return True, f"Mach-O    {p.name}  ({size:,} B)"
        return False, f"bad Mach-O magic {magic.hex()}  {p.name}"

    if fmt == "wasm":
        magic = p.read_bytes()[:4]
        if magic == _WASM_MAGIC:
            return True, f"WASM      {p.name}  ({size:,} B)"
        return False, f"bad WASM magic {magic.hex()}  {p.name}"

    if fmt == "js":
        # Emscripten JS glue – just ensure non-empty
        return True, f"JS-glue   {p.name}  ({size:,} B)"

    return False, f"unknown format '{fmt}' for exec_mode={exec_mode} platform={platform}"
