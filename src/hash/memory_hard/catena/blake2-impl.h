/*
 * Catena-local blake2-impl.h — helper macros for catena's blake2b.
 * Copied from argon2's blake2-impl.h (CC0/Apache 2.0) with catena prefix.
 */
#ifndef CATENA_BLAKE2_IMPL_H
#define CATENA_BLAKE2_IMPL_H

#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#define BLAKE2_INLINE __inline
#elif defined(__GNUC__) || defined(__clang__)
#define BLAKE2_INLINE __inline__
#else
#define BLAKE2_INLINE
#endif

#if (defined(__BYTE_ORDER__) &&                                                \
     (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) ||                           \
    defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || defined(__MIPSEL__) ||  \
    defined(__AARCH64EL__) || defined(__amd64__) || defined(__i386__) ||        \
    defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64) ||               \
    defined(_M_ARM)
#ifndef NATIVE_LITTLE_ENDIAN
#define NATIVE_LITTLE_ENDIAN
#endif
#endif

static BLAKE2_INLINE uint32_t load32(const void *src) {
#if defined(NATIVE_LITTLE_ENDIAN)
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t *p = (const uint8_t *)src;
    uint32_t w = *p++;
    w |= (uint32_t)(*p++) << 8;
    w |= (uint32_t)(*p++) << 16;
    w |= (uint32_t)(*p++) << 24;
    return w;
#endif
}

static BLAKE2_INLINE uint64_t load64(const void *src) {
#if defined(NATIVE_LITTLE_ENDIAN)
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) << 8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    w |= (uint64_t)(*p++) << 48;
    w |= (uint64_t)(*p++) << 56;
    return w;
#endif
}

static BLAKE2_INLINE void store32(void *dst, uint32_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)(w);
    *p++ = (uint8_t)(w >> 8);
    *p++ = (uint8_t)(w >> 16);
    *p++ = (uint8_t)(w >> 24);
#endif
}

static BLAKE2_INLINE void store64(void *dst, uint64_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)(w);
    *p++ = (uint8_t)(w >> 8);
    *p++ = (uint8_t)(w >> 16);
    *p++ = (uint8_t)(w >> 24);
    *p++ = (uint8_t)(w >> 32);
    *p++ = (uint8_t)(w >> 40);
    *p++ = (uint8_t)(w >> 48);
    *p++ = (uint8_t)(w >> 56);
#endif
}

static BLAKE2_INLINE uint64_t rotr64(const uint64_t w, const unsigned c) {
    return (w >> c) | (w << (64 - c));
}

static BLAKE2_INLINE void secure_zero_memory(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) *p++ = 0;
}

#endif /* CATENA_BLAKE2_IMPL_H */
