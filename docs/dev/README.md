# Developer Guide

---

## Prerequisites

| Tool | Minimum version | Required for |
|---|---|---|
| GCC or Clang | 12 | All C compilation |
| Python | 3.10 | Build scripts, test runner |
| `emcc` (Emscripten) | 3.x | WebAssembly targets |
| `wasmtime` | 1.x | Running WASM tests locally |
| Make / CMake | any | Optional — runner.py does not require it |

---

## Getting Started

```sh
git clone https://github.com/QudsLab/NextSSL.git
cd NextSSL
pip install -r requirements.txt

# Build and test everything on the host platform
python runner.py
```

---

## Further Reading

| Guide | Contents |
|---|---|
| [BUILD.md](BUILD.md) | Build system internals — `Config`, `Builder`, macros |
| [ADDING_MODULE.md](ADDING_MODULE.md) | Step-by-step guide for adding a new algorithm module |
| [PLATFORM.md](PLATFORM.md) | Platform-specific flags and reproducibility requirements |

---

## Key Script Files

| File | Role |
|---|---|
| `runner.py` | Top-level CLI — build + test orchestration |
| `script/core/builder.py` | Invokes compiler, assembles flags |
| `script/core/config.py` | Central paths, excludes, macros, repro identifiers |
| `script/core/platform.py` | OS detection |
| `script/core/logger.py` | Structured log output |
| `script/core/console.py` | Colored terminal output |
| `script/gen/` | Code generation scripts (per tier/module) |
| `script/test/` | Test scripts (per tier/module) |
