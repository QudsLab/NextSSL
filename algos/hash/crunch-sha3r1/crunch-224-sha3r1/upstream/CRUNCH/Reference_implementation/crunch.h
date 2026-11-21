#include "crunch_type.h" 

extern HashReturn Init(hashState *state, int hashbitlen);
extern HashReturn Final(hashState *state, BitSequence *hash);
extern HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen);
extern HashReturn Hash(int hashbitlen,const BitSequence *data,DataLength databitlen,BitSequence *hashval);

