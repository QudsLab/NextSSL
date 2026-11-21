/* NextSSL compat header (not upstream code). With NS_SUP_NAME defined (support wrapper unit) it maps crypto_verify onto that SUPERCOP lib. */
#ifdef NS_SUP_NAME
#define crypto_verify NS_SUP_NAME
#define crypto_verify_BYTES NS_SUP_PFX(BYTES)
int crypto_verify(const unsigned char *,const unsigned char *);
#else
#endif
