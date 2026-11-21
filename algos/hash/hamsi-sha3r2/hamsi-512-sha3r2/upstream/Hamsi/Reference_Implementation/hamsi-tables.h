#ifndef __HAMSI_TABLES_H__
#define __HAMSI_TABLES_H__

#include "words.h"

// round constants
extern const Word alpha[2][4][8];

// IV's
extern const Word iv224[8];
extern const Word iv256[8];
extern const Word iv384[16];
extern const Word iv512[16];

// expansion tables
extern const Word T256[4][256][8];
extern const Word T512[8][256][16];

#endif
