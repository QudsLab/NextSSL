extern HashReturn Init_384();
extern HashReturn Update_384(const BitSequence * data,DataLength databitlen);
extern HashReturn Final_384(BitSequence *hash);
extern HashReturn Hash_384(const BitSequence *data,DataLength databitlen,BitSequence *hashval);

