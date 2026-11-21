/* NextSSL compat stub (not upstream). Lyra2.c includes <omp.h> unconditionally, but with
 * nPARALLEL=1 (build.rs) every OpenMP use sits inside `#if (nPARALLEL > 1)` and is not compiled.
 * The stub lets compilers without OpenMP headers (clang in the sanitizer and wasm builds) build it. */
#ifndef NEXTSSL_COMPAT_OMP_H
#define NEXTSSL_COMPAT_OMP_H
#endif
