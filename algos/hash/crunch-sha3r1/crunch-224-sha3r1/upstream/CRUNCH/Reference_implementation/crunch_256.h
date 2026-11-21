extern HashReturn Init_256();
extern HashReturn Update_256(const BitSequence * data,DataLength databitlen);
extern HashReturn Final_256(BitSequence *hash);
extern HashReturn Hash_256(const BitSequence *data,DataLength databitlen,BitSequence *hashval);

