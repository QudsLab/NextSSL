/**
 * @file stub_all.c
 * @brief Combined lite variant stub implementation  
 * NOTE: Minimal stub - primitives not yet fully integrated
 */
#include <stddef.h>
#include <stdint.h>
#define NEXTSSL_API __declspec(dllexport)
NEXTSSL_API int nextssl_stub_function(void) { return -99; }
