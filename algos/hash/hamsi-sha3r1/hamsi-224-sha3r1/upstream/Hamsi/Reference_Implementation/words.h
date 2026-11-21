#ifndef __WORDS_H__
#define __WORDS_H__

typedef unsigned char  Byte;            //  8 bits
typedef unsigned int   Word;            // 32 bits
typedef unsigned long long int U64;     // 64 bits
typedef unsigned int   Row __attribute__ ((vector_size (16))); // 128 bits

#endif
