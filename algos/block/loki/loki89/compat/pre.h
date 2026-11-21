/* ours, NOT upstream: force-included before every source of this crate.
 * The historic C here assumes a 32 bit `long`. The standard headers are pulled in first, then `long` is redefined to
 * `int` (32 bit on every supported target) for the upstream sources only; shim.c undefines it again after its includes.
 * LITTLE_ENDIAN is what the sources test for their (optional) byte swapping; all supported targets are little endian. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#define long int
