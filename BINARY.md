# NextSSL — Binary Distribution Matrix

This document lists every platform/architecture variant for `nextssl` shared
and static library builds.  Each row represents one distinct binary artifact.

**Legend**

| Symbol | Meaning |
|--------|---------|
| ✅ Pre-built | Binary committed to `bin/` and ready to use |
| 🔄 CI | Built and uploaded by GitHub Actions on every push |
| 📋 Planned | Toolchain identified; not yet wired into CI |
| 🔵 Optional | Out-of-scope for default builds; requires separate job |

---

## Windows

| # | OS | Architecture | ABI / Toolchain | Binary Name | Import Lib | Build Host | Status |
|---|----|--------------|-----------------|-----------  |------------|------------|--------|
| 1 | Windows 10/11 | x86\_64 (64-bit) | MSVC 2019/2022 | `nextssl.dll` | `nextssl.lib` | `windows-2022` | ✅ Pre-built |
| 2 | Windows 10/11 | x86\_64 (64-bit) | MinGW-w64 (GCC 13) | `nextssl.dll` | `libnextssl.dll.a` | `windows-2022` | 🔄 CI |
| 3 | Windows 10/11 | x86 / i686 (32-bit) | MSVC 2019/2022 (`-A Win32`) | `nextssl.dll` | `nextssl.lib` | `windows-2022` | 🔄 CI |
| 4 | Windows 10/11 | x86 / i686 (32-bit) | MinGW-w64 (GCC 13, `-m32`) | `nextssl.dll` | `libnextssl.dll.a` | `windows-2022` | 🔄 CI |
| 5 | Windows 11 | arm64 / AArch64 | MSVC 2022 (`-A ARM64`, cross) | `nextssl.dll` | `nextssl.lib` | `windows-2022` | 🔄 CI |
| 6 | Windows 11 | arm / ARMv7 (32-bit) | MSVC 2022 (`-A ARM`, cross) | `nextssl.dll` | `nextssl.lib` | `windows-2022` | 🔄 CI |

> **CI artifact path**: `bin/win/<variant>/`  
> **Examples**: `bin/win/x86_64-msvc/`, `bin/win/x86_64-mingw/`, `bin/win/arm64-msvc/`  
> **Static variant**: replace `-DNEXTSSL_SHARED=ON` with `OFF` → produces `.lib` only.

---

## Linux — glibc (GNU)

| # | OS | Architecture | ABI / Toolchain | Binary Name | Build Host | Status |
|---|----|--------------|-----------------|-----------  |------------|--------|
| 7  | Linux (glibc 2.35+) | x86\_64 (64-bit) | GCC 12 / Clang 15 | `libnextssl.so` | `ubuntu-22.04` | 🔄 CI |
| 8  | Linux (glibc 2.35+) | x86 / i686 (32-bit) | GCC 12 `-m32` | `libnextssl.so` | `ubuntu-22.04` | 🔄 CI |
| 9  | Linux (glibc 2.35+) | arm64 / AArch64 | `aarch64-linux-gnu-gcc` (cross) | `libnextssl.so` | `ubuntu-22.04` | 🔄 CI |
| 10 | Linux (glibc 2.35+) | armv7 / ARMhf | `arm-linux-gnueabihf-gcc` (cross) | `libnextssl.so` | `ubuntu-22.04` | 🔄 CI |
| 11 | Linux (glibc 2.35+) | riscv64 | `riscv64-linux-gnu-gcc` (cross) | `libnextssl.so` | `ubuntu-22.04` | 🔄 CI |
| 12 | Linux (glibc 2.35+) | s390x (IBM Z) | `s390x-linux-gnu-gcc` (cross) | `libnextssl.so` | `ubuntu-24.04` | 🔄 CI |
| 13 | Linux (glibc 2.35+) | ppc64le (Power) | `powerpc64le-linux-gnu-gcc` (cross) | `libnextssl.so` | `ubuntu-24.04` | 🔄 CI |
| 14 | Linux (glibc 2.35+) | loongarch64 | `gcc-14-loongarch64-linux-gnu` (cross) | `libnextssl.so` | `ubuntu-24.04` | 🔄 CI |

> **CI artifact path**: `bin/linux-glibc/<variant>/`  
> **Cross-compile**: `build/ci_runner.py` selects the toolchain for each visible variant job.

---

## Linux — musl (Alpine / static-pie)

| # | OS | Architecture | ABI / Toolchain | Binary Name | Build Host | Status |
|---|----|--------------|-----------------|-----------  |------------|--------|
| 15 | Linux musl | x86\_64 | `zig cc -target x86_64-linux-musl` | `libnextssl.so` | `ubuntu-24.04` | 🔄 CI |
| 16 | Linux musl | arm64 / AArch64 | `zig cc -target aarch64-linux-musl` | `libnextssl.so` | `ubuntu-24.04` | 🔄 CI |
| 17 | Linux musl | armv7 | `zig cc -target arm-linux-musleabihf` | `libnextssl.so` | `ubuntu-24.04` | 🔄 CI |

> **CI artifact path**: `bin/linux-musl/<variant>/`  
> **Note**: CI uses Zig musl cross-targets rather than an Alpine container.

---

## macOS

| # | OS | Architecture | ABI / Toolchain | Binary Name | Build Host | Status |
|---|----|--------------|-----------------|-----------  |------------|--------|
| 18 | macOS 13 (Ventura) | x86\_64 (Intel) | Apple Clang 15 | `libnextssl.dylib` | `macos-13` | 🔄 CI |
| 19 | macOS 14 (Sonoma) | arm64 (M1/M2/M3) | Apple Clang 15 | `libnextssl.dylib` | `macos-14` | 🔄 CI |
| 20 | macOS 13/14 | universal (fat) | Apple Clang universal build | `libnextssl.dylib` | `macos-14` | 🔄 CI |

> **CI artifact path**: `bin/macos/<variant>/`  
> **Universal build**: CI configures CMake with `-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64`.

---

## WebAssembly (WASM)

| # | Target | Runtime | ABI / Toolchain | Binary Name | JS Glue | Build Host | Status |
|---|--------|---------|-----------------|-------------|---------|------------|--------|
| 21 | Emscripten (wasm32) | Browser / Node.js | Emscripten 3.x (`emcmake`) | `libnextssl.wasm` | `libnextssl.js` | `ubuntu-22.04` | 🔄 CI |
| 22 | WASI (wasm32-wasi) | Wasmtime / WasmEdge | wasi-sdk 32 | `libnextssl.wasm` | — | `ubuntu-24.04` | 🔄 CI |

> **CI artifact path**: `bin/wasm/<variant>/`  
> **Note**: the Emscripten helper still produces `bin/web/` first, then CI stages the result into `bin/wasm/emscripten-wasm32/`.

---

## Android

Built via Android NDK in visible CI jobs.

| # | OS | Architecture | ABI | Binary Name | NDK | Build Host | Status |
|---|----|--------------|----|-------------|-----|------------|--------|
| 23 | Android 7.0+ (API 24) | arm64-v8a | Android NDK r27 | `libnextssl.so` | clang (NDK) | `ubuntu-24.04` | 🔄 CI |
| 24 | Android 5.0+ (API 21) | armeabi-v7a | Android NDK r27 | `libnextssl.so` | clang (NDK) | `ubuntu-24.04` | 🔄 CI |
| 25 | Android 7.0+ (API 24) | x86\_64 | Android NDK r27 | `libnextssl.so` | clang (NDK) | `ubuntu-24.04` | 🔄 CI |
| 26 | Android 5.0+ (API 21) | x86 | Android NDK r27 | `libnextssl.so` | clang (NDK) | `ubuntu-24.04` | 🔄 CI |

> **CI artifact path**: `bin/android/<variant>/`

> Build command:
> ```
> cmake -B build \
>   -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
>   -DANDROID_ABI=arm64-v8a \
>   -DANDROID_PLATFORM=android-24
> ```

---

## iOS

Built as static library (`.a`) because iOS prohibits dynamic frameworks from  
third-party binaries in the App Store.

| # | Target | Architecture | ABI | Binary Name | Build Host | Status |
|---|--------|--------------|-----|-------------|------------|--------|
| 27 | iOS device (iPhone/iPad) | arm64 | Apple Clang + Xcode 15 | `libnextssl.a` | `macos-14` | 🔄 CI |
| 28 | iOS Simulator (M-chip Mac) | arm64 | Apple Clang + Xcode 15 | `libnextssl.a` | `macos-14` | 🔄 CI |
| 29 | iOS Simulator (Intel Mac) | x86\_64 | Apple Clang + Xcode 15 | `libnextssl.a` | `macos-13` | 🔄 CI |

> **CI artifact path**: `bin/ios/<variant>/`

> Build command example (device):
> ```
> cmake -B build \
>   -DCMAKE_SYSTEM_NAME=iOS \
>   -DCMAKE_OSX_SYSROOT=iphoneos \
>   -DNEXTSSL_SHARED=OFF
> ```

---

## Summary

| Platform | Variants | Pre-built | CI | Planned | Optional |
|----------|----------|-----------|----|---------|----------|
| Windows | 6 | 1 | 5 | 0 | 0 |
| Linux glibc | 8 | 0 | 8 | 0 | 0 |
| Linux musl | 3 | 0 | 3 | 0 | 0 |
| macOS | 3 | 0 | 3 | 0 | 0 |
| WASM | 2 | 0 | 2 | 0 | 0 |
| Android | 4 | 0 | 4 | 0 | 0 |
| iOS | 3 | 0 | 3 | 0 | 0 |
| **Total** | **29** | **1** | **28** | **0** | **0** |

---

## Build Requirements

| Toolchain | Install |
|-----------|---------|
| MSVC 2022 | Visual Studio 2022 Build Tools (component `VC.Tools.x86.x64`) |
| MinGW-w64 | `winget install GnuWin32.Make` + MSYS2 `mingw-w64-x86_64-gcc` |
| GCC 12 (Linux) | `apt-get install gcc-12 build-essential cmake` |
| GCC ARM64 cross | `apt-get install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu` |
| GCC ARMv7 cross | `apt-get install gcc-arm-linux-gnueabihf` |
| GCC RISC-V cross | `apt-get install gcc-riscv64-linux-gnu` |
| GCC s390x cross | `apt-get install gcc-s390x-linux-gnu binutils-s390x-linux-gnu libc6-dev-s390x-cross` |
| GCC ppc64le cross | `apt-get install gcc-powerpc64le-linux-gnu binutils-powerpc64le-linux-gnu libc6-dev-ppc64el-cross` |
| GCC loongarch64 cross | `apt-get install gcc-14-loongarch64-linux-gnu binutils-loongarch64-linux-gnu libc6-dev-loong64-cross` |
| Zig musl cross | `apt-get install zig` |
| Apple Clang | Xcode Command Line Tools (`xcode-select --install`) |
| Emscripten | `git clone https://github.com/emscripten-core/emsdk && ./emsdk install latest` |
| Android NDK | Android Studio → SDK Manager → NDK r27 |
| wasi-sdk | https://github.com/WebAssembly/wasi-sdk/releases |

---

## File Naming Convention

```
bin/
  win/
    x86_64/     nextssl.dll  nextssl.lib
    x86/        nextssl.dll  nextssl.lib
    arm64/      nextssl.dll  nextssl.lib
  linux/
    x86_64/     libnextssl.so
    x86/        libnextssl.so
    arm64/      libnextssl.so
    armv7/      libnextssl.so
    riscv64/    libnextssl.so
  macos/
    x86_64/     libnextssl.dylib
    arm64/      libnextssl.dylib
    universal/  libnextssl.dylib
  web/
    libnextssl.wasm
    libnextssl.js
```

> The output directory is set automatically by `CMakeLists.txt` based on
> `CMAKE_SYSTEM_PROCESSOR` and the host OS detection.  Cross-compile jobs
> pass `-DCMAKE_SYSTEM_PROCESSOR=<arch>` explicitly to override the default.
