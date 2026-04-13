/* nextssl_export.h — Single Definition of the NEXTSSL_API Export Macro
 *
 * Include this header (directly or via nextssl.h) instead of redefining
 * __declspec(dllexport) in each subsystem file.
 */
#ifndef NEXTSSL_EXPORT_H
#define NEXTSSL_EXPORT_H

#if defined(_WIN32) || defined(_WIN64)
#  ifdef NEXTSSL_BUILDING_DLL
#    define NEXTSSL_API __declspec(dllexport)
#  else
#    define NEXTSSL_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define NEXTSSL_API __attribute__((visibility("default")))
#else
#  define NEXTSSL_API
#endif

#endif /* NEXTSSL_EXPORT_H */
