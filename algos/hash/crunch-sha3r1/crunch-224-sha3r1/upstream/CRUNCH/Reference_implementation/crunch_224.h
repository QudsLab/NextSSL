
extern HashReturn Init_224();
extern HashReturn Update_224(const BitSequence * data,DataLength databitlen);
extern HashReturn Final_224(BitSequence *hash);
extern HashReturn Hash_224(const BitSequence *data,DataLength databitlen,BitSequence *hashval);
