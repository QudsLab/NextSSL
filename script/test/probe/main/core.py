"""script/test/probe/main/core.py — structural probe for core.dll.

Checks every symbol in _WASM_CORE_EXPORTS exists and is type-assignable.
No crypto is executed.
"""
import os
import sys
import ctypes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import Config, console
from script.test.core.probe  import probe_symbol
from script.test.core.result import Results
from script.gen.main.core    import _WASM_CORE_EXPORTS

_SKIP = {'malloc', 'free'}


def main() -> int:
    config   = Config()
    dll_path = config.get_lib_path('main', 'core')
    console.print_info(f"Probe: {dll_path}")
    if not os.path.exists(dll_path):
        console.print_fail(f"DLL not found: {dll_path}")
        return 1
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError as e:
        console.print_fail(f"Failed to load: {e}")
        return 1

    r = Results('probe/main/core')
    for sym in _WASM_CORE_EXPORTS:
        if sym in _SKIP:
            continue
        probe_symbol(lib, sym, argtypes=[], restype=None, results=r)
    return r.summary()


if __name__ == "__main__":
    sys.exit(main())
