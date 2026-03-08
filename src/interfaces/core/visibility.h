/**
 * @file interfaces/core/visibility.h
 * @brief NEXTSSL_CORE_API visibility proxy for core-layer headers.
 *
 * Core-layer aggregate headers include this file as "../visibility.h".
 * It guarantees NEXTSSL_CORE_API is defined (hidden symbol on ELF targets,
 * empty on MSVC / unknown compilers) without requiring a full config.h pull.
 */

#ifndef NEXTSSL_CORE_VISIBILITY_H
#define NEXTSSL_CORE_VISIBILITY_H

/* Include root visibility for full API macro set (NEXTSSL_BASE_API etc.) */
#include "../visibility.h"

#ifndef NEXTSSL_CORE_API
#  if defined(_WIN32) || defined(_WIN64)
#    define NEXTSSL_CORE_API
#  elif defined(__GNUC__) || defined(__clang__)
#    define NEXTSSL_CORE_API __attribute__((visibility("hidden")))
#  else
#    define NEXTSSL_CORE_API
#  endif
#endif

#endif /* NEXTSSL_CORE_VISIBILITY_H */
