"""script/test/probe/main/pow.py — structural probe for pow.dll + dhcm.dll.

Checks every symbol in _WASM_POW_EXPORTS and _WASM_DHCM_EXPORTS exists and
is type-assignable.  No crypto is executed.
"""
import os
import sys
import ctypes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))
from script.core import Config, console
from script.test.core.probe  import probe_symbol
from script.test.core.result import Results
from script.gen.main.pow     import _WASM_POW_EXPORTS, _WASM_DHCM_EXPORTS

_SKIP = {'malloc', 'free'}


def _probe_dll(dll_path, exports, label) -> Results:
    r = Results(label)
    console.print_info(f"Probe: {dll_path}")
    if not os.path.exists(dll_path):
        console.print_fail(f"DLL not found: {dll_path}")
        r.fail(label, reason="file not found")
        return r
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError as e:
        console.print_fail(f"Failed to load: {e}")
        r.fail(label, reason=str(e))
        return r
    for sym in exports:
        if sym in _SKIP:
            continue
        probe_symbol(lib, sym, argtypes=[], restype=None, results=r)
    return r


def main() -> int:
    config = Config()
    r_pow  = _probe_dll(config.get_lib_path('main', 'pow'),  _WASM_POW_EXPORTS,  'probe/main/pow')
    r_dhcm = _probe_dll(config.get_lib_path('main', 'dhcm'), _WASM_DHCM_EXPORTS, 'probe/main/dhcm')
    r_pow.summary()
    r_dhcm.summary()
    return 0 if (r_pow.failed == 0 and r_dhcm.failed == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
