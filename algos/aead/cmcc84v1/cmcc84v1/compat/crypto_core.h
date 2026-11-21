/* NextSSL compat header (not upstream code). With NS_SUP_NAME defined (support wrapper unit) it maps crypto_core onto that SUPERCOP lib. */
#ifdef NS_SUP_NAME
#define crypto_core NS_SUP_NAME
#define crypto_core_OUTPUTBYTES NS_SUP_PFX(OUTPUTBYTES)
#define crypto_core_INPUTBYTES NS_SUP_PFX(INPUTBYTES)
#define crypto_core_KEYBYTES NS_SUP_PFX(KEYBYTES)
#define crypto_core_CONSTBYTES NS_SUP_PFX(CONSTBYTES)
int crypto_core(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
#else
#endif
