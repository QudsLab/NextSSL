# Contributing to NextSSL

Thank you for your interest in contributing to NextSSL! We welcome contributions from everyone. By participating in this project, you agree to abide by our code of conduct.

## How to Contribute

1.  **Fork the repository** (https://github.com/Qudslab/NextSSL) and create a new branch for your feature or bug fix.
2.  **Make your changes**, ensuring you follow the coding standards below.
3.  **Run the tests** locally to ensure your changes don't break existing functionality.
    ```bash
    python runner.py
    ```
4.  **Submit a Pull Request (PR)** with a clear description of your changes.

## Development Setup

NextSSL requires **Python 3.8+** and a **C compiler** (GCC recommended). The build system is self-contained in `runner.py` and the `script/` directory.

### Directory Structure
-   `src/`: C source code for cryptographic primitives.
-   `script/`: Python build system and test suite.
-   `bin/`: Compiled binaries (DLLs/SOs) are placed here.

## Coding Standards

### C Code (src/)
-   **Style**: Follow the existing style (K&R-like). Use 4 spaces for indentation.
-   **Safety**:
    -   Avoid dynamic memory allocation (`malloc`/`free`) in core primitives where possible.
    -   Use constant-time comparisons for secret data (e.g., tags, keys).
    -   Ensure all public API functions are properly exported using the `EXPORT` macro.
-   **Portability**: Code should be compatible with Windows (MSVC/MinGW) and Linux (GCC/Clang).

### Python Code (script/)
-   **Style**: Follow PEP 8 guidelines.
-   **Compatibility**: Ensure scripts run on standard Python 3.8+ without external dependencies.

## Reporting Bugs

If you find a bug, please open an issue on GitHub with:
-   A clear title.
-   A description of the bug.
-   Steps to reproduce.
-   Expected vs. actual behavior.

## Adding New Algorithms

If you are adding a new cryptographic primitive:
1.  Place the implementation in the appropriate `src/primitives/` subdirectory.
2.  Create a wrapper in `src/utils/` if necessary.
3.  Add a corresponding build script in `script/gen/`.
4.  Add a test suite in `script/test/` verifying against Known Answer Tests (KATs).
5.  Update `ALGORITHM.md` and `SOURCE.md` to reflect the new addition.

## License

By contributing, you agree that your contributions will be licensed under the project's license.
