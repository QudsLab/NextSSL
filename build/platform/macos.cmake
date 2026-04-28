# build/platform/macos.cmake — macOS CMake toolchain
#
# This file is loaded automatically by build/platform/macos.py if it exists.
# For a standard native macOS build (host == target arch) no changes are needed —
# CMake auto-detects Apple Clang from Xcode command-line tools.
#
# Uncomment and configure sections below only when you need:
#   - A specific Clang/GCC install (e.g. Homebrew LLVM)
#   - Universal binary (arm64 + x86_64 fat binary)
#   - Cross-compilation (rare on macOS)

# ── Uncomment to force Homebrew LLVM instead of Apple Clang ─────────────────
# set(CMAKE_C_COMPILER   /opt/homebrew/opt/llvm/bin/clang)
# set(CMAKE_CXX_COMPILER /opt/homebrew/opt/llvm/bin/clang++)

# ── Uncomment for universal binary (arm64 + x86_64) ─────────────────────────
# Note: CMAKE_OSX_ARCHITECTURES is also set in macos.py from the variant arg.
#       Override here only if you want to force universal regardless of variant.
# set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")

# ── Uncomment to target a specific minimum macOS version ─────────────────────
# set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0")

# ── Uncomment for cross-compile macOS → iOS (advanced) ───────────────────────
# set(CMAKE_SYSTEM_NAME iOS)
# set(CMAKE_OSX_SYSROOT iphoneos)
