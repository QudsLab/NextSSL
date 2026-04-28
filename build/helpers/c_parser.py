"""c_parser.py — lightweight C header / source parser for NEXTSSL.

Extracts NEXTSSL_API declarations, EXPORT function definitions, and
function definitions from .c files.  No dependency on libclang.
"""
import re
from pathlib import Path
from typing import List, Tuple

# Matches:  NEXTSSL_API int nextssl_foo(...)  or  NEXTSSL_API void nextssl_bar(...)
_RE_NEXTSSL_API_DECL = re.compile(
    r'NEXTSSL_API\s+'
    r'(?:(?:const\s+)?(?:unsigned\s+)?[\w*]+(?:\s*\*)?)\s+'  # return type
    r'(nextssl_\w+)\s*\(',                                     # function name
    re.MULTILINE,
)

# Matches function definitions in .c that start with the function name at col-0
#   int nextssl_foo(...)  {   or   void nextssl_foo(...)  {
_RE_FUNC_DEF = re.compile(
    r'^(?:(?:const\s+)?(?:unsigned\s+)?[\w*]+(?:\s*\*)?)\s+'
    r'(nextssl_\w+)\s*\(',
    re.MULTILINE,
)

# Matches EXPORT int pqc_foo(...)  in pqc_main.c
_RE_PQC_EXPORT = re.compile(
    r'EXPORT\s+'
    r'(?:(?:const\s+)?(?:unsigned\s+)?[\w*]+(?:\s*\*)?)\s+'
    r'(pqc_\w+)\s*\(',
    re.MULTILINE,
)

# Matches NEXTSSL_API in pow_api.c (symbol-providing, no separate .h wrapper)
_RE_POW_API = re.compile(
    r'NEXTSSL_API\s+'
    r'(?:(?:const\s+)?(?:unsigned\s+)?[\w*]+(?:\s*\*)?)\s+'
    r'(nextssl_\w+)\s*\(',
    re.MULTILINE,
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def extract_api_declarations(root_dir: Path) -> List[Tuple[str, str]]:
    """Return [(filename, func_name), ...] for every NEXTSSL_API in root headers."""
    results = []
    for h in sorted(root_dir.rglob("*.h")):
        text = _read(h)
        for m in _RE_NEXTSSL_API_DECL.finditer(text):
            results.append((str(h.relative_to(root_dir)), m.group(1)))
    return results


def extract_wrapper_definitions(root_dir: Path) -> List[Tuple[str, str]]:
    """Return [(filename, func_name), ...] for every nextssl_* definition in root .c files."""
    results = []
    for c in sorted(root_dir.rglob("*.c")):
        text = _read(c)
        for m in _RE_FUNC_DEF.finditer(text):
            results.append((str(c.relative_to(root_dir)), m.group(1)))
    return results


def extract_pqc_exports(pqc_main_path: Path) -> List[str]:
    """Return [func_name, ...] for every EXPORT function in pqc_main.c."""
    text = _read(pqc_main_path)
    return [m.group(1) for m in _RE_PQC_EXPORT.finditer(text)]


def extract_pow_api(pow_api_path: Path) -> List[str]:
    """Return [func_name, ...] for every nextssl_* function defined in pow_api.c."""
    text = _read(pow_api_path)
    # pow_api.c definitions may or may not have NEXTSSL_API prefix
    pat = re.compile(
        r'^(?:NEXTSSL_API\s+)?'
        r'(?:(?:const\s+)?(?:unsigned\s+)?[\w*]+(?:\s*\*)?)\s+'
        r'(nextssl_\w+)\s*\(',
        re.MULTILINE,
    )
    return [m.group(1) for m in pat.finditer(text)]


def scan_modern_sources(modern_dir: Path) -> List[Tuple[str, str]]:
    """Return [(subdir, filename), ...] for every .c in modern/ subdirectories."""
    results = []
    for c in sorted(modern_dir.rglob("*.c")):
        rel = c.relative_to(modern_dir)
        parts = rel.parts
        subdir = parts[0] if len(parts) > 1 else ""
        results.append((subdir, c.name))
    return results
