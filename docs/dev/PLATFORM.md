# Platform Guide

---

## Platform Matrix

| Platform | Compiler | Extension | Runner flag |
|---|---|---|---|
| Windows | GCC (MinGW) | `.dll` | `--platform windows` |
| Linux | GCC / Clang | `.so` | `--platform linux` |
| macOS | Clang | `.dylib` | `--platform mac` |
| WebAssembly | `emcc` (Emscripten) | `.wasm` | `--platform web` |

---

## Platform Detection

`script/core/platform.py` exposes `Platform.get_os()` which returns one of:
`windows`, `linux`, `macos`, `web`.

The build system checks `Platform.get_os()` to select compiler flags — never
use raw `sys.platform` comparisons in build scripts.

---

## Platform-Specific Flags

### Windows (`.dll`)

- Compiler: `gcc` (MinGW)
- Flags: `-shared -fPIC -O2 -Wall -static`
- Extra library: `-lbcrypt`

  > `-lbcrypt` is appended **only** when `lib_ext == '.dll'`.  It is not
  > passed on Linux, macOS, or WASM builds.  Do not add OS-name checks for
  > this — the extension check is the correct guard.

- Reproducibility: `--no-insert-timestamp` via `Config.WINDOWS_DLL_REPRO_FLAGS`

### Linux (`.so`)

- Compiler: `gcc`
- Flags: `-shared -fPIC -O2 -Wall -nostartfiles`
- Build-id: `-Wl,--build-id=0x<Config.LINUX_SO_BUILD_ID>`

  The build-id is a 40-hex-digit fixed value (default: all-zeros) that
  replaces the random SHA1 the linker would normally generate.  Change
  `Config.LINUX_SO_BUILD_ID` once to rotate it for all Linux builds.

### macOS (`.dylib`)

- Compiler: `clang`
- Flags: `-shared -fPIC -O2 -Wall`
- UUID: Apple ld always writes `LC_UUID` (required by `dlopen`).  The
  `-uuid` linker flag is not reliably supported across ld versions, so
  `Config.MACOS_DYLIB_UUID` defaults to `''` (let ld generate naturally).

  > macOS `.dylib` files are NOT bitwise-reproducible between rebuilds
  > unless a fixed UUID is forced.  This is a known limitation.

- Extra macro: `BLAKE3_USE_NEON=0` is injected automatically on macOS to
  disable the NEON BLAKE3 path.

### WebAssembly (`.wasm`)

- Compiler: `emcc`
- Flags: `-O2 -Wall -s WASM=1 -s STANDALONE_WASM=1 -Wl,--no-entry`
- Exported function: `_nextssl_wasm_selftest`
- Runtime: `wasmtime` for local execution; browser runtime for web targets.

---

## Reproducible Builds

All platforms strip compile-time timestamps by injecting:

```
-Wno-builtin-macro-redefined -D__DATE__= -D__TIME__= -D__TIMESTAMP__=
```

To additionally enforce a stable `SOURCE_DATE_EPOCH` when calling the
compiler externally:

```sh
export SOURCE_DATE_EPOCH=0
python runner.py
```

---

## DLL Export Guard

All public symbols that should be visible in the DLL/SO/DYLIB must be
declared with `NEXTSSL_API`:

```c
// src/config/config.h (or platform.h)
#ifdef _WIN32
  #define NEXTSSL_API __declspec(dllexport)
#else
  #define NEXTSSL_API __attribute__((visibility("default")))
#endif
```

Symbols not marked `NEXTSSL_API` will be hidden on Linux/macOS `-fvisibility=hidden`
builds and will not be exported from the DLL on Windows.
