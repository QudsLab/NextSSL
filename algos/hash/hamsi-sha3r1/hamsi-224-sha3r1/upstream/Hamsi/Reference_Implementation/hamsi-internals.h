#ifndef __HAMSI_INTERNALS_H__
#define __HAMSI_INTERNALS_H__

#include "hamsi.h"
#include "words.h"
#include "hamsi-tables.h"

void Mix(Word* a,Word* b,Word* c,Word* d);

void subst256(Word s[5][4]);
void subst512(Word s[5][8]);

void diffuse256(Word s[5][4]);
void diffuse512(Word s[5][8]);

#endif
