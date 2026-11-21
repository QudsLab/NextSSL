#ifndef GLOBAL_H_
#define GLOBAL_H_


/* Data types mandated by the API (see http://csrc.nist.gov/groups/ST/hash/documents/SHA3-C-API.pdf) */
typedef unsigned char BitSequence;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;
typedef unsigned long long DataLength;

/* typedefs for 32 and 64 bits unsigned integers, as in C99. They should be replaced
 * by including stdint.h when available, or changed to the suitable values for a
 * given platform. 
 */
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#endif /*GLOBAL_H_*/
