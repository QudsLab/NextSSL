/* MSVC stand-in for <sys/param.h> (not an upstream file; on the include path on MSVC only).
 * lookup3.c includes it only to learn the byte order through __BYTE_ORDER. Without it the upstream
 * takes its portable byte-by-byte path (HASH_LITTLE_ENDIAN 0), which gives the same hashlittle()
 * output as the word path; the KAT checks it. */
#pragma once
