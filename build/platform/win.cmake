# build/platform/win.cmake — Windows CMake toolchain
#
# This file is loaded automatically by build/platform/win.py.
# For a standard native Windows build (host == target) no changes are needed —
# CMake auto-detects GCC/MSVC from PATH.

# ── Uncomment to force MinGW GCC on Windows ──────────────────────────────────
# set(CMAKE_C_COMPILER   "C:/msys64/ucrt64/bin/gcc.exe")
# set(CMAKE_CXX_COMPILER "C:/msys64/ucrt64/bin/g++.exe")
# set(CMAKE_AR           "C:/msys64/ucrt64/bin/ar.exe")
# set(CMAKE_RANLIB       "C:/msys64/ucrt64/bin/ranlib.exe")
# set(CMAKE_RC_COMPILER  "C:/msys64/ucrt64/bin/windres.exe")

# ── Uncomment for cross-compile (Linux/macOS host → Windows target) ──────────
# set(CMAKE_SYSTEM_NAME Windows)
# set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
# set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
# set(CMAKE_AR           x86_64-w64-mingw32-ar)
# set(CMAKE_RANLIB       x86_64-w64-mingw32-ranlib)
# set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)
# set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
# set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
# set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
