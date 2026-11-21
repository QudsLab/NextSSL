/*
	SHA3

	Copyright(C) 2017 by Toshiba Corporation. All rights reserved.
*/

#ifndef __SHA3_H__
#define __SHA3_H__

#include <stdint.h>

#define SHA3_224(result, data, datalen) keccack(result, 224 / 8, data, datalen, 1152 / 8, 0x06)
#define SHA3_256(result, data, datalen) keccack(result, 256 / 8, data, datalen, 1088 / 8, 0x06)
#define SHA3_384(result, data, datalen) keccack(result, 384 / 8, data, datalen, 832 / 8, 0x06)
#define SHA3_512(result, data, datalen) keccack(result, 512 / 8, data, datalen, 576 / 8, 0x06)

#define SHAKE128(result, resultlen, data, datalen) keccack(result, resultlen,data, datalen, 1344 / 8, 0x1f)
#define SHAKE256(result, resultlen, data, datalen) keccack(result, resultlen,data, datalen, 1088 / 8, 0x1f)

void keccack(uint8_t *result, uint32_t resultlen, const uint8_t *data, uint32_t datalen, uint32_t rate, uint8_t padchar);

#endif
