/* ours: replaces libosmocore's crypt/gprs_cipher.h (plugin registry) for gea.c. Enum values are copied from the upstream header. */
#pragma once
#include <stdint.h>
enum gprs_ciph_algo {
	GPRS_ALGO_GEA0 = 0,
	GPRS_ALGO_GEA1 = 1,
	GPRS_ALGO_GEA2 = 2,
	GPRS_ALGO_GEA3 = 3,
	GPRS_ALGO_GEA4 = 4,
	_GPRS_ALGO_NUM
};
enum gprs_cipher_direction {
	GPRS_CIPH_MS2SGSN = 0,
	GPRS_CIPH_SGSN2MS = 1,
};
/* upstream gprs_cipher_key_length(): GEA4 uses a 16 byte key, the others 8; a constant expression so gea.c's array stays a C array */
#define gprs_cipher_key_length(algo) ((algo) == GPRS_ALGO_GEA4 ? 16 : 8)
