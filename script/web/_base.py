"""
script/web/_base.py — Shared WASM loader and memory helper.

Uses the wasmtime Python package to load .wasm modules, allocate WASM
memory (via exported malloc/free), and call exported C functions with
pointer-based arguments.

All crypto functions in this project follow the signatures:
  fn(in_ptr, in_len, out_ptr)           → int  (hash1 helpers)
  fn(in_ptr, in_len, out_ptr, out_len)  → int  (hash2 / XOF helpers)

The WASM modules must be built with 'malloc' and 'free' in their
_WASM_*_EXPORTS lists (see script/gen/main/).
"""
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from script.core import console

_WASMTIME_OK = False
try:
    from wasmtime import Engine, Store, Module, Linker, WasiConfig   # type: ignore
    _WASMTIME_OK = True
except ImportError:
    pass


def require_wasmtime() -> bool:
    """Print an error and return False if wasmtime package is missing."""
    if not _WASMTIME_OK:
        console.print_fail(
            "wasmtime Python package not installed — run:  pip install wasmtime"
        )
    return _WASMTIME_OK


def wasm_path_for(tier: str, name: str) -> str:
    """Return absolute path to  bin/web/{tier}/{name}.wasm  in this repo."""
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
    return os.path.join(root, 'bin', 'web', tier, f'{name}.wasm')


# ─────────────────────────────────────────────────────────────────────────────

class WasmModule:
    """
    Thin wrapper around a loaded WASM instance.

    Provides:
      - malloc / free backed by the exported C allocator
      - read / write into WASM linear memory
      - helper methods for the common crypto call patterns
    """

    def __init__(self, path: str):
        engine = Engine()
        cfg = WasiConfig()
        cfg.inherit_stdout()
        cfg.inherit_stderr()
        store = Store(engine)
        store.set_wasi(cfg)
        linker = Linker(engine)
        linker.define_wasi()
        module = Module.from_file(engine, path)
        self._inst = linker.instantiate(store, module)
        self._store = store
        ex = self._inst.exports(store)
        self._mem    = ex['memory']
        self._malloc = ex['malloc']
        self._free   = ex['free']

    # ── allocator ────────────────────────────────────────────────────────────

    def malloc(self, n: int) -> int:
        """Allocate n bytes in WASM linear memory; returns i32 address."""
        return self._malloc(self._store, max(n, 1))

    def free(self, ptr: int):
        """Free a previously malloc'd WASM pointer."""
        self._free(self._store, ptr)

    # ── raw memory access ─────────────────────────────────────────────────────

    def _data(self):
        """Return a ctypes byte-array pointer to the raw WASM memory."""
        return self._mem.data_ptr(self._store)

    def read(self, ptr: int, length: int) -> bytes:
        d = self._data()
        return bytes(d[ptr + i] for i in range(length))

    def write(self, ptr: int, data: bytes):
        d = self._data()
        for i, b in enumerate(data):
            d[ptr + i] = b

    # ── convenience allocators ────────────────────────────────────────────────

    def buf(self, data: bytes) -> int:
        """Allocate WASM memory and copy data into it.  Caller must free."""
        ptr = self.malloc(max(len(data), 1))
        if data:
            self.write(ptr, data)
        return ptr

    def zbuf(self, size: int) -> int:
        """Allocate a zero-filled WASM buffer.  Caller must free."""
        ptr = self.malloc(size)
        self.write(ptr, b'\x00' * size)
        return ptr

    # ── direct export call ─────────────────────────────────────────────────

    def call(self, name: str, *args):
        """Call an exported function by name with scalar (i32/i64/f64) args."""
        return self._inst.exports(self._store)[name](self._store, *args)

    # ── common crypto call patterns ───────────────────────────────────────────

    def hash1(self, fn: str, inp: bytes, out_len: int) -> bytes:
        """
        fn(in_ptr, in_len, out_ptr) → int
        Returns out_len bytes from out_ptr.
        """
        p_in  = self.buf(inp)
        p_out = self.zbuf(out_len)
        self.call(fn, p_in, len(inp), p_out)
        result = self.read(p_out, out_len)
        self.free(p_in)
        self.free(p_out)
        return result

    def hash2(self, fn: str, inp: bytes, out_len: int) -> bytes:
        """
        fn(in_ptr, in_len, out_ptr, out_len) → int   (XOF / SHAKE)
        Returns out_len bytes.
        """
        p_in  = self.buf(inp)
        p_out = self.zbuf(out_len)
        self.call(fn, p_in, len(inp), p_out, out_len)
        result = self.read(p_out, out_len)
        self.free(p_in)
        self.free(p_out)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Simple test runner helpers shared by all web test modules
# ─────────────────────────────────────────────────────────────────────────────

class _Tester:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def ok(self, name: str, condition: bool):
        if condition:
            console.print_pass(name)
            self.passed += 1
        else:
            console.print_fail(name)
            self.failed += 1
        return condition

    def run(self, name: str, fn):
        """Run fn(); treat any exception as a failure."""
        try:
            result = fn()
            self.ok(name, bool(result))
        except Exception as exc:
            console.print_fail(f"{name}: {exc}")
            self.failed += 1


def load_module(tier: str, name: str):
    """
    Load bin/web/{tier}/{name}.wasm.
    Returns (WasmModule, None) on success or (None, error_message) on failure.
    """
    if not require_wasmtime():
        return None, "wasmtime not available"
    path = wasm_path_for(tier, name)
    if not os.path.exists(path):
        return None, f"WASM not found: {path}"
    try:
        mod = WasmModule(path)
        return mod, None
    except Exception as exc:
        return None, str(exc)
