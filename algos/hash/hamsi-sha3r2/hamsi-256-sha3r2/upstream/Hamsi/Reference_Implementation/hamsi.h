#ifndef __HAMSI_H__
#define __HAMSI_H__

#include "words.h"

int hash256(const int ROUNDS, Word*chainVal, const Byte*d, int lastiter);
int hash512(const int ROUNDS, Word*chainVal, const Byte*d, int lastiter);

#endif
