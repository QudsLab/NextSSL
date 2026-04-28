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
| 4 | Windows 10/11 | x86 / i686 (32-bit) | MinGW-w64 (GCC 13, `-m32`) | `nextssl.dll` | `libnextssl.dll.a` | `windows-2022` | 📋 Planned |
| 5 | Windows 11 | arm64 / AArch64 | MSVC 2022 (`-A ARM64`, cross) | `nextssl.dll` | `nextssl.lib` | `windows-2022` | 🔄 CI |
| 6 | Windows 11 | arm / ARMv7 (32-bit) | MSVC 2022 (`-A ARM`, cross) | `nextssl.dll` | `nextssl.lib` | `windows-2022` | 📋 Planned |

> **Output path** (MSVC / MinGW native): `bin/win/x86_64/`  
> **Output path** (MSVC ARM64 cross): `bin/win/arm64/`  
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
| 12 | Linux (glibc 2.35+) | s390x (IBM Z) | `s390x-linux-gnu-gcc` (cross) | `libnextssl.so` | `ubuntu-22.04` | 📋 Planned |
| 13 | Linux (glibc 2.35+) | ppc64le (Power) | `powerpc64le-linux-gnu-gcc` (cross) | `libnextssl.so` | `ubuntu-22.04` | 📋 Planned |
| 14 | Linux (glibc 2.35+) | loongarch64 | `loongarch64-linux-gnu-gcc` (cross) | `libnextssl.so` | `ubuntu-22.04` | 📋 Planned |

> **Output path**: `bin/linux/<arch>/`  
> **Cross-compile**: sets `-DCMAKE_SYSTEM_PROCESSOR=<arch> -DCMAKE_C_COMPILER=<triple>-gcc`.

---

## Linux — musl (Alpine / static-pie)

| # | OS | Architecture | ABI / Toolchain | Binary Name | Build Host | Status |
|---|----|--------------|-----------------|-----------  |------------|--------|
| 15 | Linux musl | x86\_64 | `musl-gcc` / Alpine cross | `libnextssl.so` | Alpine container | 📋 Planned |
| 16 | Linux musl | arm64 / AArch64 | `aarch64-linux-musl-gcc` | `libnextssl.so` | Alpine container | 📋 Planned |
| 17 | Linux musl | armv7 | `armv7l-linux-musleabihf-gcc` | `libnextssl.so` | Alpine container | 📋 Planned |

> **Note**: musl builds require passing `-DCMAKE_C_FLAGS=-static` or building  
> inside an Alpine Docker image (`docker/linux/`).

---

## macOS

| # | OS | Architecture | ABI / Toolchain | Binary Name | Build Host | Status |
|---|----|--------------|-----------------|-----------  |------------|--------|
| 18 | macOS 13 (Ventura) | x86\_64 (Intel) | Apple Clang 15 | `libnextssl.dylib` | `macos-13` | 🔄 CI |
| 19 | macOS 14 (Sonoma) | arm64 (M1/M2/M3) | Apple Clang 15 | `libnextssl.dylib` | `macos-14` | 🔄 CI |
| 20 | macOS 13/14 | universal (fat) | Apple Clang + `lipo` | `libnextssl.dylib` | `macos-14` | 🔄 CI |

> **Output path**: `bin/macos/x86_64/`, `bin/macos/arm64/`, `bin/macos/universal/`  
> **Universal build**: builds x86\_64 + arm64 separately, then merges with `lipo -create`.

---

## WebAssembly (WASM)

| # | Target | Runtime | ABI / Toolchain | Binary Name | JS Glue | Build Host | Status |
|---|--------|---------|-----------------|-------------|---------|------------|--------|
| 21 | Emscripten (wasm32) | Browser / Node.js | Emscripten 3.x (`emcmake`) | `libnextssl.wasm` | `libnextssl.js` | `ubuntu-22.04` | 🔄 CI |
| 22 | WASI (wasm32-wasi) | Wasmtime / WasmEdge | wasi-sdk 20 | `libnextssl.wasm` | — | `ubuntu-22.04` | 📋 Planned |

> **Output path**: `bin/web/`  
> **Toolchain file**: `build/platform/wasm.cmake`

---

## Android (Optional)

Built via Android NDK.  Not included in default CI jobs.

| # | OS | Architecture | ABI | Binary Name | NDK | Build Host | Status |
|---|----|--------------|----|-------------|-----|------------|--------|
| 23 | Android 7.0+ (API 24) | arm64-v8a | Android NDK r27 | `libnextssl.so` | clang (NDK) | `ubuntu-22.04` | 🔵 Optional |
| 24 | Android 5.0+ (API 21) | armeabi-v7a | Android NDK r27 | `libnextssl.so` | clang (NDK) | `ubuntu-22.04` | 🔵 Optional |
| 25 | Android 7.0+ (API 24) | x86\_64 | Android NDK r27 | `libnextssl.so` | clang (NDK) | `ubuntu-22.04` | 🔵 Optional |
| 26 | Android 5.0+ (API 21) | x86 | Android NDK r27 | `libnextssl.so` | clang (NDK) | `ubuntu-22.04` | 🔵 Optional |

> Build command:
> ```
> cmake -B build \
>   -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
>   -DANDROID_ABI=arm64-v8a \
>   -DANDROID_PLATFORM=android-24
> ```

---

## iOS (Optional)

Built as static library (`.a`) because iOS prohibits dynamic frameworks from  
third-party binaries in the App Store.

| # | Target | Architecture | ABI | Binary Name | Build Host | Status |
|---|--------|--------------|-----|-------------|------------|--------|
| 27 | iOS device (iPhone/iPad) | arm64 | Apple Clang + Xcode 15 | `libnextssl.a` | `macos-14` | 🔵 Optional |
| 28 | iOS Simulator (M-chip Mac) | arm64 | Apple Clang + Xcode 15 | `libnextssl.a` | `macos-14` | 🔵 Optional |
| 29 | iOS Simulator (Intel Mac) | x86\_64 | Apple Clang + Xcode 15 | `libnextssl.a` | `macos-13` | 🔵 Optional |

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
| Windows | 6 | 1 | 3 | 2 | 0 |
| Linux glibc | 8 | 0 | 5 | 3 | 0 |
| Linux musl | 3 | 0 | 0 | 3 | 0 |
| macOS | 3 | 0 | 3 | 0 | 0 |
| WASM | 2 | 0 | 1 | 1 | 0 |
| Android | 4 | 0 | 0 | 0 | 4 |
| iOS | 3 | 0 | 0 | 0 | 3 |
| **Total** | **29** | **1** | **12** | **9** | **7** |

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
