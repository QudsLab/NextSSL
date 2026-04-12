cmake_minimum_required(VERSION 3.16)
project(nextssl VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ─────────────────────────────────────────────────────────────────
# Feature flags (all default ON for full build, can be toggled)
# ─────────────────────────────────────────────────────────────────
option(ENABLE_ML_KEM    "Enable ML-KEM (Kyber) KEM family"     ON)
option(ENABLE_ML_DSA    "Enable ML-DSA (Dilithium) sign family" ON)
option(ENABLE_FALCON    "Enable Falcon sign family"             ON)
option(ENABLE_HQC       "Enable HQC KEM family"                 ON)
option(ENABLE_MCELIECE  "Enable McEliece KEM family"            ON)
option(ENABLE_SPHINCS   "Enable SPHINCS+ sign family"           ON)

option(ENABLE_GMSSL     "Enable GmSSL (SM2/SM3/SM4)"            OFF)
option(ENABLE_ED448     "Enable Ed448 / X448"                   ON)
# balloon, pomelo, makwa are always built (no opt-out).

option(NEXTSSL_SHARED   "Build as shared library (.dll/.so)"    ON)

# ─────────────────────────────────────────────────────────────────
# Output directory:  <root>/bin/<os>/<arch>/
# ─────────────────────────────────────────────────────────────────
if(WIN32)
    set(_NEXTSSL_OS "win")
elseif(APPLE)
    set(_NEXTSSL_OS "macos")
else()
    set(_NEXTSSL_OS "linux")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    set(_NEXTSSL_ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    set(_NEXTSSL_ARCH "arm64")
else()
    set(_NEXTSSL_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(_BIN_DIR "${PROJECT_SOURCE_DIR}/bin/${_NEXTSSL_OS}/${_NEXTSSL_ARCH}")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${_BIN_DIR}")  # .dll on Windows
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${_BIN_DIR}")  # .so on Linux/macOS
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${_BIN_DIR}")  # .a / .lib

# ─────────────────────────────────────────────────────────────────
# Compile definitions from feature flags
# ─────────────────────────────────────────────────────────────────
set(NEXTSSL_DEFS NEXTSSL_BUILDING_DLL)

if(ENABLE_ML_KEM)
    list(APPEND NEXTSSL_DEFS ENABLE_ML_KEM)
endif()
if(ENABLE_ML_DSA)
    list(APPEND NEXTSSL_DEFS ENABLE_ML_DSA)
endif()
if(ENABLE_FALCON)
    list(APPEND NEXTSSL_DEFS ENABLE_FALCON)
endif()
if(ENABLE_HQC)
    list(APPEND NEXTSSL_DEFS ENABLE_HQC)
endif()
if(ENABLE_MCELIECE)
    list(APPEND NEXTSSL_DEFS ENABLE_MCELIECE)
endif()
if(ENABLE_SPHINCS)
    list(APPEND NEXTSSL_DEFS ENABLE_SPHINCS)
endif()
if(ENABLE_GMSSL)
    list(APPEND NEXTSSL_DEFS NEXTSSL_HAS_GMSSL)
endif()
if(ENABLE_ED448)
    list(APPEND NEXTSSL_DEFS HAVE_ED448 HAVE_CURVE448)
endif()
list(APPEND NEXTSSL_DEFS NEXTSSL_HAS_BALLOON NEXTSSL_HAS_POMELO NEXTSSL_HAS_MAKWA)
list(APPEND NEXTSSL_DEFS ENABLE_SCRYPT ENABLE_YESCRYPT ENABLE_CATENA ENABLE_LYRA2)

# ─────────────────────────────────────────────────────────────────
# Source root
# ─────────────────────────────────────────────────────────────────
set(SRC "${CMAKE_SOURCE_DIR}/src")

# ─────────────────────────────────────────────────────────────────
# SOURCE COLLECTION — single glob over all of src/, then exclude
# platform-specific, broken, or duplicate files so nothing is missed
# when new subdirectories are added.
# ─────────────────────────────────────────────────────────────────
file(GLOB_RECURSE NEXTSSL_SOURCES "${SRC}/*.c")

# ── ARM-only files (require arm_neon.h — not available on x86) ──
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64|arm")
    list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/aarch64/")
    list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/pqc/common/keccak2x/")
endif()

# ── PQC avx2/ — pqc_main.c only uses ref/ APIs; avx2/ = dead code on Windows
#    McEliece avx2: uses ELF-only .hidden ASM directives (unsupported on COFF)
#    ML-KEM/ML-DSA/Falcon/SPHINCS+ avx2: build requires -mavx2 but all callers
#    use the ref/ namespace — exclude to avoid dead-code linker noise and errors
list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/pqc/.*/avx2/")

# ── Duplicate definitions (only one variant needed) ─────────────
# Argon2: opt.c is the optimised x86 version; ref.c is a duplicate
list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/memory_hard/ref\\.c$")
# Skein: skein_block.c is the primary; skeinBlockNo3F.c is a duplicate
list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/skeinBlockNo3F\\.c$")

# ── Memory-hard hashes ───────────────────────────────────────────────
# scrypt/yescrypt/catena/lyra2/balloon/pomelo/makwa always included via main GLOB.
# Exclusions still needed for files that conflict or are included via #include:  
# balloon/balloon.c: uses pthread_create — not needed; adapter calls hash_state_* directly
list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/memory_hard/balloon/balloon\\.c$")
# scrypt's original sha256.c requires cpusupport.h — use sha256_portable.c instead
list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/memory_hard/scrypt/sha256\\.c$")
# yescrypt's sha256.c uses same libcperciva_ namespace — scrypt's portable covers both
list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/memory_hard/yescrypt/sha256\\.c$")
# yescrypt's insecure_memzero.c duplicates scrypt's — share from scrypt
list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/memory_hard/yescrypt/insecure_memzero\\.c$")
# yescrypt-platform.c is #include'd by yescrypt-opt.c, not compiled separately
list(FILTER NEXTSSL_SOURCES EXCLUDE REGEX "/yescrypt-platform\\.c$")


# scrypt/yescrypt/catena/lyra2/balloon/pomelo/makwa always included via main GLOB

# ─────────────────────────────────────────────────────────────────
# Library target
# ─────────────────────────────────────────────────────────────────
if(NEXTSSL_SHARED)
    add_library(nextssl SHARED ${NEXTSSL_SOURCES})
else()
    add_library(nextssl STATIC ${NEXTSSL_SOURCES})
endif()

target_compile_definitions(nextssl PRIVATE ${NEXTSSL_DEFS})

target_include_directories(nextssl PUBLIC
    "${SRC}/root"
)
target_include_directories(nextssl PRIVATE
    "${SRC}"
    "${SRC}/common"
    "${SRC}/common/encoding"
    "${SRC}/common/sanitizer"
    "${SRC}/hash"
    "${SRC}/hash/interface"
    "${SRC}/hash/fast"
    "${SRC}/hash/blake"
    "${SRC}/hash/legacy"
    "${SRC}/hash/memory_hard"
    "${SRC}/hash/skein"
    "${SRC}/hash/sponge"
    "${SRC}/hash/adapters"
    "${SRC}/hash/generic"
    "${SRC}/hash/root_functions"
    "${SRC}/seed"
    "${SRC}/seed/hash"
    "${SRC}/seed/random"
    "${SRC}/seed/rng"
    "${SRC}/seed/drbg"
    "${SRC}/seed/udbf"
    "${SRC}/modern"
    "${SRC}/modern/symmetric"
    "${SRC}/modern/aead"
    "${SRC}/modern/mac"
    "${SRC}/modern/kdf"
    "${SRC}/modern/encoding"
    "${SRC}/modern/curve_math"
    "${SRC}/modern/asymmetric"
    "${SRC}/modern/asymmetric/rsa"
    "${SRC}/modern/asymmetric/micro_ecc"
    "${SRC}/pow"
    "${SRC}/pow/core"
    "${SRC}/pow/client"
    "${SRC}/pow/server"
    "${SRC}/pow/dhcm"
    "${SRC}/pqc"
    "${SRC}/pqc/common"
    "${SRC}/root/hash"
    "${SRC}/root/seed"
    "${SRC}/root/modern"
    "${SRC}/root/pqc"
    "${SRC}/root/pow"
)

if(ENABLE_GMSSL)
    target_include_directories(nextssl PRIVATE "${SRC}/modern/asymmetric/sm2")
endif()
target_include_directories(nextssl PRIVATE "${SRC}/hash/memory_hard/balloon")

# ─────────────────────────────────────────────────────────────────
# BLAKE3 SIMD — disable intrinsics on non-x86 or when unavailable
# ─────────────────────────────────────────────────────────────────
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i686|i386")
    set_source_files_properties("${SRC}/hash/blake/blake3_avx2.c"   PROPERTIES COMPILE_FLAGS "-mavx2")
    set_source_files_properties("${SRC}/hash/blake/blake3_avx512.c" PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512vl")
    set_source_files_properties("${SRC}/hash/blake/blake3_sse2.c"   PROPERTIES COMPILE_FLAGS "-msse2")
    set_source_files_properties("${SRC}/hash/blake/blake3_sse41.c"  PROPERTIES COMPILE_FLAGS "-msse4.1")
    # PQC Keccak-4x AVX2 (used by ML-KEM, ML-DSA, Falcon, HQC, SPHINCS+ ref/)
    set_source_files_properties(
        "${SRC}/pqc/common/keccak4x/KeccakP-1600-times4-SIMD256.c"
        PROPERTIES COMPILE_FLAGS "-mavx2")
else()
    # Non-x86: disable SIMD dispatch, use portable fallback only
    target_compile_definitions(nextssl PRIVATE
        BLAKE3_NO_AVX2 BLAKE3_NO_AVX512 BLAKE3_NO_SSE2 BLAKE3_NO_SSE41)
endif()

# ─────────────────────────────────────────────────────────────────
# Compiler warnings / optimization
# ─────────────────────────────────────────────────────────────────
if(MSVC)
    target_compile_options(nextssl PRIVATE /W3 /wd4996)
else()
    target_compile_options(nextssl PRIVATE
        -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
        -Wno-missing-field-initializers
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Debug>:-g -O0>
    )
    # Strip debug symbols in Release → smaller DLL
    target_link_options(nextssl PRIVATE
        $<$<CONFIG:Release>:-Wl,-s>
    )
endif()

# ─────────────────────────────────────────────────────────────────
# On Windows link ws2_32 (needed by some network/random code)
# ─────────────────────────────────────────────────────────────────
if(WIN32)
    target_link_libraries(nextssl PRIVATE ws2_32 bcrypt)
endif()

# ─────────────────────────────────────────────────────────────────
# Install rules
# ─────────────────────────────────────────────────────────────────
install(TARGETS nextssl
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
install(FILES "${SRC}/root/nextssl.h" "${SRC}/root/nextssl_export.h"
    DESTINATION include/nextssl
)

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────
message(STATUS "NextSSL build configuration:")
message(STATUS "  Type        : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Shared lib  : ${NEXTSSL_SHARED}")
message(STATUS "  ML-KEM      : ${ENABLE_ML_KEM}")
message(STATUS "  ML-DSA      : ${ENABLE_ML_DSA}")
message(STATUS "  Falcon      : ${ENABLE_FALCON}")
message(STATUS "  HQC         : ${ENABLE_HQC}")
message(STATUS "  McEliece    : ${ENABLE_MCELIECE}")
message(STATUS "  SPHINCS+    : ${ENABLE_SPHINCS}")
message(STATUS "  GmSSL       : ${ENABLE_GMSSL}")
message(STATUS "  Ed448/X448  : ${ENABLE_ED448}")
message(STATUS "  Balloon     : ON (always)")
message(STATUS "  Pomelo      : ON (always)")
message(STATUS "  Makwa       : ON (always)")
