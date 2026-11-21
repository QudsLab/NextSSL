extern HashReturn Init_512();
extern HashReturn Update_512(const BitSequence * data,DataLength databitlen);
extern HashReturn Final_512(BitSequence *hash);
extern HashReturn Hash_512(const BitSequence *data,DataLength databitlen,BitSequence *hashval);

