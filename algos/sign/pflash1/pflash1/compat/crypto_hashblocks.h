/* NextSSL compat header (not upstream code). With NS_SUP_NAME defined (support wrapper unit) it maps crypto_hashblocks onto that SUPERCOP lib. */
#ifdef NS_SUP_NAME
#define crypto_hashblocks NS_SUP_NAME
#define crypto_hashblocks_STATEBYTES NS_SUP_PFX(STATEBYTES)
#define crypto_hashblocks_BLOCKBYTES NS_SUP_PFX(BLOCKBYTES)
int crypto_hashblocks(unsigned char *,const unsigned char *,unsigned long long);
#else
#endif
