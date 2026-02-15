#ifndef RISTRETTO255_H
#define RISTRETTO255_H

#include <stddef.h>

#define RISTRETTO255_BYTES 32
#define RISTRETTO255_SCALARBYTES 32
#define RISTRETTO255_HASHBYTES 64

int ristretto255_is_valid_point(const unsigned char *p);
int ristretto255_add(unsigned char *r, const unsigned char *p, const unsigned char *q);
int ristretto255_sub(unsigned char *r, const unsigned char *p, const unsigned char *q);
int ristretto255_from_hash(unsigned char *p, const unsigned char *r);

#endif
