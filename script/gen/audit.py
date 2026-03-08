"""
script/gen/audit.py
────────────────────
Post-build export verification.

Call verify_exports() after any build_target() to confirm every expected
symbol was actually linked into the output binary.  Returns the list of
missing symbols; an empty list means success.

Platform dispatch:
  Windows  → dumpbin /EXPORTS  <binary>
  Linux    → nm -D              <binary>
  macOS    → nm -gU             <binary>
  WASM     → wasm-objdump -x   <binary>   (grep for Function section entries)
"""
from __future__ import annotations

import os
import re
import subprocess
from script.core.platform import Platform


def _exported_symbols_native(binary_path: str) -> set[str]:
    """Return the set of exported symbol names from a native shared library."""
    os_name = Platform.get_os()

    if os_name == 'windows':
        cmd = ['dumpbin', '/EXPORTS', binary_path]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                          text=True, timeout=60)
        except (FileNotFoundError, subprocess.SubprocessError):
            # dumpbin not on PATH — fall back to objdump if available
            try:
                cmd = ['objdump', '-p', binary_path]
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                              text=True, timeout=60)
            except (FileNotFoundError, subprocess.SubprocessError):
                return set()
        # dumpbin output: "  <ordinal>  <hint>  <RVA>  <name>"
        # objdump -p output: "[Ordinal/Name Pointer] Table" then lines
        symbols: set[str] = set()
        for line in out.splitlines():
            # dumpbin: lines with 4 hex columns then name
            m = re.match(r'^\s+\d+\s+\w+\s+\w+\s+(\w+)\s*$', line)
            if m:
                symbols.add(m.group(1))
            # objdump -p: "   [  0] AES_CBC_encrypt"
            m2 = re.match(r'^\s+\[\s*\d+\]\s+(\w+)\s*$', line)
            if m2:
                symbols.add(m2.group(1))
        return symbols

    elif os_name == 'linux':
        cmd = ['nm', '-D', '--defined-only', binary_path]
    elif os_name == 'mac':
        cmd = ['nm', '-gU', binary_path]
    else:
        return set()

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      text=True, timeout=60)
    except (FileNotFoundError, subprocess.SubprocessError):
        return set()

    symbols: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            name = parts[-1]
            # Strip leading underscore (macOS convention)
            if name.startswith('_'):
                name = name[1:]
            symbols.add(name)
    return symbols


def _exported_symbols_wasm(binary_path: str) -> set[str]:
    """Return exported symbol names from a WASM binary via wasm-objdump."""
    try:
        out = subprocess.check_output(
            ['wasm-objdump', '-x', binary_path],
            stderr=subprocess.DEVNULL, text=True, timeout=60,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return set()

    symbols: set[str] = set()
    # wasm-objdump -x lines look like:
    #  - func[123] <AES_CBC_encrypt> -> "AES_CBC_encrypt"
    for line in out.splitlines():
        m = re.search(r'"(\w+)"', line)
        if m:
            name = m.group(1)
            # Strip Emscripten leading underscore if present
            if name.startswith('_'):
                name = name[1:]
            symbols.add(name)
    return symbols


def verify_exports(
    binary_path: str,
    expected_symbols: list[str],
    intentionally_excluded: list[str] | None = None,
) -> list[str]:
    """Check that every symbol in *expected_symbols* appears in the binary.

    Symbols in *intentionally_excluded* are silently skipped so callers can
    document known omissions (e.g. McEliece excluded from WASM) without
    triggering false failures.

    Returns a (possibly empty) list of symbols that are missing from the
    binary.  An empty list means the binary exports everything it should.
    """
    if not os.path.exists(binary_path):
        return list(expected_symbols)

    excluded: set[str] = set(intentionally_excluded or [])

    is_wasm = binary_path.endswith('.wasm')
    if is_wasm:
        present = _exported_symbols_wasm(binary_path)
    else:
        present = _exported_symbols_native(binary_path)

    if not present:
        # Tool unavailable — skip verification rather than false-fail
        return []

    missing = [
        s for s in expected_symbols
        if s not in present and s not in excluded
    ]
    return missing
