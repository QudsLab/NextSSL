/* NextSSL compat header (not upstream code). With NS_SUP_NAME defined (support wrapper unit) it maps crypto_xof onto that SUPERCOP lib. */
#ifdef NS_SUP_NAME
#define crypto_xof NS_SUP_NAME
#define crypto_xof_NOOVERLAP NS_SUP_PFX(NOOVERLAP)
int crypto_xof(unsigned char *,long long,const unsigned char *,long long);
#else
#endif
