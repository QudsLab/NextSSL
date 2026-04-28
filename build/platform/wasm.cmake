# wasm.cmake — Emscripten toolchain file for NextSSL WASM build
#
# Usage (via emcmake, recommended):
#   emcmake cmake ../.. -G Ninja -DCMAKE_BUILD_TYPE=Release
#
# Usage (manually, if emcmake not on PATH):
#   cmake ../.. -G Ninja -DCMAKE_TOOLCHAIN_FILE=../../build/wasm.cmake
#
# Output: bin/web/libnextssl.wasm + libnextssl.js (JS glue)

# Tell CMake we're cross-compiling to WASM
set(CMAKE_SYSTEM_NAME Emscripten)
set(CMAKE_SYSTEM_VERSION 1)

# Emscripten provides these automatically when invoked via emcmake.
# Only set them explicitly when calling cmake directly without emcmake.
if(DEFINED ENV{EMSCRIPTEN})
    set(EMSCRIPTEN_ROOT "$ENV{EMSCRIPTEN}")
else()
    # Try common install locations
    foreach(candidate
        "$ENV{EMSDK}/upstream/emscripten"
        "C:/emsdk/upstream/emscripten"
        "$ENV{USERPROFILE}/emsdk/upstream/emscripten")
        if(EXISTS "${candidate}/emcc")
            set(EMSCRIPTEN_ROOT "${candidate}")
            break()
        endif()
    endforeach()
endif()

if(DEFINED EMSCRIPTEN_ROOT)
    set(CMAKE_C_COMPILER   "${EMSCRIPTEN_ROOT}/emcc")
    set(CMAKE_CXX_COMPILER "${EMSCRIPTEN_ROOT}/em++")
    set(CMAKE_AR           "${EMSCRIPTEN_ROOT}/emar")
    set(CMAKE_RANLIB       "${EMSCRIPTEN_ROOT}/emranlib")
endif()

set(CMAKE_EXECUTABLE_SUFFIX ".js")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".wasm")
