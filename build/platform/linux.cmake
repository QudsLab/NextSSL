# build/platform/linux.cmake — Linux CMake toolchain
#
# This file is loaded automatically by build/platform/linux.py if it exists.
# For a standard native Linux build (host == target, same arch) no changes are
# needed here — CMake auto-detects GCC/Clang from PATH.
#
# Uncomment and configure sections below only when you need:
#   - A specific compiler version
#   - Cross-compilation (e.g. x86_64 host → arm64 target)

# ── Uncomment to force a specific GCC version ────────────────────────────────
# set(CMAKE_C_COMPILER   gcc-13)
# set(CMAKE_CXX_COMPILER g++-13)

# ── Uncomment for cross-compile x86_64 → arm64 (requires aarch64 toolchain) ─
# set(CMAKE_SYSTEM_NAME Linux)
# set(CMAKE_SYSTEM_PROCESSOR aarch64)
# set(CMAKE_C_COMPILER   aarch64-linux-gnu-gcc)
# set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
# set(CMAKE_AR           aarch64-linux-gnu-ar)
# set(CMAKE_RANLIB       aarch64-linux-gnu-ranlib)
# set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
# set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
# set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# ── Uncomment for cross-compile x86_64 → armv7 (32-bit ARM) ─────────────────
# set(CMAKE_SYSTEM_NAME Linux)
# set(CMAKE_SYSTEM_PROCESSOR armv7)
# set(CMAKE_C_COMPILER   arm-linux-gnueabihf-gcc)
# set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)
