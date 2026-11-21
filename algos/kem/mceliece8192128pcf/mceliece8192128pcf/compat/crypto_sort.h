/* NextSSL compat header (not upstream code). With NS_SUP_NAME defined (support wrapper unit) it maps crypto_sort onto that SUPERCOP lib. */
#ifdef NS_SUP_NAME
#define crypto_sort NS_SUP_NAME
#define crypto_sort_BYTES NS_SUP_PFX(BYTES)
void crypto_sort(void *,long long);
#else
#endif
