# Build Guide

## Python Requirement

NextSSL's Python build helpers use the Python standard library only.

- Python 3.8+ is enough
- no virtual environment is required
- use `python`, `python3`, or `py -3`
- do not depend on a repo-local `.venv` for normal builds

## Recommended Path

The recommended build path is CMake.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

For the full algorithm build:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DNEXTSSL_BUILD_VARIANT=full
cmake --build build
```

## Python Helpers

The Python helpers are for audits, platform-specific helper builds, and CI-style sequencing.

### Audit Helpers

```bash
python build/build.py --check
python build/check_exports.py
python build/check_algos.py
```

### Test Runner

```bash
python test.py
```

### Platform Build Helper

```bash
python build.py --platform win x86_64
python build.py --platform linux x86_64
python build.py --platform macos arm64
python build.py --platform wasm wasm32
```

### CI-Style Sequential Runner

```bash
python build/ci_runner.py --platform win --variants x86_64 x86 arm64 --jobs 4
python build/ci_runner.py --platform linux --variants x86_64 x86 arm64 armv7 riscv64 --jobs 4
python build/ci_runner.py --platform macos --variants x86_64 arm64 --jobs 4
python build/ci_runner.py --platform wasm --variants wasm32 --jobs 4
```

The CI runner writes durable logs to `logs/<platform>/<variant>/` and stops the remaining variants in that platform queue after the first failure.

## Current Adapter Coverage

The direct `build.py` platform adapters are still:

- `win`
- `linux`
- `macos`
- `wasm`

The CI matrix is broader than the direct adapter list.
Visible CI jobs for `linux-glibc`, `linux-musl`, `android`, `ios`, and `wasi-wasm32` are driven through `build/ci_runner.py` with workflow-provided toolchains rather than through additional `build/platform/*.py` entry points.

## CI Notes

- CI should use system Python from the runner image
- build helpers should not assume an activated virtual environment
- logs should always be uploaded, even when a platform queue stops early
- the collect job should only report repo publication when a real push happened

See `FLOW.md` for the live CI topology and `BINARY.md` for the full platform and variant matrix.
