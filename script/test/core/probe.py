"""script/test/core/probe.py — symbol existence check (no execution).

probe_symbol() sets argtypes/restype on the attribute to confirm the symbol
is present and type-assignable.  It never calls the function, so no crypto
operation is performed.  Used by all script/test/probe/ files.
"""
from .result import Results


def probe_symbol(
    lib,
    fn_name:  str,
    argtypes: list,
    restype,
    results:  Results,
) -> bool:
    """
    Tries:
        f = getattr(lib, fn_name)
        f.argtypes = argtypes
        f.restype  = restype
    Records pass/fail in *results*.
    Returns True if the symbol was found and type-assignable, False otherwise.
    Never calls the function.
    """
    try:
        f = getattr(lib, fn_name)
        f.argtypes = argtypes
        f.restype  = restype
        results.ok(f"probe: {fn_name}")
        return True
    except AttributeError:
        results.fail(f"probe: {fn_name}", reason="symbol not found in binary")
        return False
    except Exception as e:
        results.fail(f"probe: {fn_name}", reason=str(e))
        return False
