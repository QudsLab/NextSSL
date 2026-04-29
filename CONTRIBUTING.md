# Contributing to NextSSL

Thank you for your interest in contributing to NextSSL! We welcome contributions from everyone. By participating in this project, you agree to abide by our code of conduct.

## How to Contribute

1. **Fork the repository** [Qudslab/NextSSL](https://github.com/Qudslab/NextSSL) and create a new branch for your feature or bug fix.
2. **Make your changes**, ensuring you follow the coding standards below.
3. **Run the tests** locally to ensure your changes don't break existing functionality.

```bash
python build/build.py --check
python test.py
```

1. **Submit a Pull Request (PR)** with a clear description of your changes.

## Development Setup

NextSSL requires **Python 3.8+** and a **C compiler** (GCC recommended). The Python helpers live under `build/` plus the root `test.py`, use the standard library only, and do not require a virtual environment.

### Directory Structure

- `src/`: C source code for cryptographic primitives.
- `build/`: Python build helpers, audits, and platform adapters.
- `test/`: Known Answer Test data and Python test modules.
- `bin/`: Compiled binaries (DLLs/SOs) are placed here.

## Coding Standards

### C Code (`src/`)

- **Style**: Follow the existing style (K&R-like). Use 4 spaces for indentation.
- **Safety**: Avoid dynamic memory allocation (`malloc`/`free`) in core primitives where possible.
- **Safety**: Use constant-time comparisons for secret data (e.g. tags, keys).
- **Safety**: Ensure all public API functions are properly exported using the `EXPORT` macro.
- **Portability**: Code should be compatible with Windows (MSVC/MinGW) and Linux (GCC/Clang).

### Python Code (`build/` and `test.py`)

- **Style**: Follow PEP 8 guidelines.
- **Compatibility**: Ensure scripts run on standard Python 3.8+ without external dependencies.

## Reporting Bugs

If you find a bug, please open an issue on GitHub with:

- A clear title.
- A description of the bug.
- Steps to reproduce.
- Expected vs. actual behavior.

## Adding New Algorithms

If you are adding a new cryptographic primitive:

1. Place the implementation in the appropriate `src/` subsystem directory.
2. Add or update root wrappers, registries, or dispatch tables where needed.
3. Update the relevant build or audit helper in `build/` if exports, registries, or feature flags changed.
4. Add or update KAT coverage under `test/kat/`.
5. Update the relevant docs such as `ALGO.md`, `BINARY.md`, and `FLOW.md`.

## License

By contributing, you agree that your contributions will be licensed under the project's license.
