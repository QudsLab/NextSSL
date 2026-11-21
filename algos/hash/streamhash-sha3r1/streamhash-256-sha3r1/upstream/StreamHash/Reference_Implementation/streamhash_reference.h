/* streamhash_reference.h by Michal Trojnara 2007-2008 */

typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum { SUCCESS=0, FAIL=1, BAD_HASHLEN=2 } HashReturn;

typedef struct {
    int hashbitlen, bitlen, tablen;
    unsigned int tabval[16];
    BitSequence bitval; /* unprocessed bits */
} hashState;

HashReturn Init(hashState *state, int hashbitlen);
HashReturn Update(hashState *state, const BitSequence *data,
        DataLength databitlen);
HashReturn Final(hashState *state, BitSequence *hashval);
HashReturn Hash(int hashbitlen, const BitSequence *data,
        DataLength databitlen, BitSequence *hashval);

/* end of streamhash_reference.h */
