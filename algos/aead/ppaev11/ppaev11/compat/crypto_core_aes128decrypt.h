/* NextSSL compat header (not upstream code): SUPERCOP lib crypto_core_aes128decrypt built from core_aes128decrypt/api.h (implementation ref). */
#ifndef NS_CRYPTO_CORE_AES128DECRYPT_H
#define NS_CRYPTO_CORE_AES128DECRYPT_H
#define crypto_core_aes128decrypt_OUTPUTBYTES 16
#define crypto_core_aes128decrypt_INPUTBYTES 16
#define crypto_core_aes128decrypt_KEYBYTES 16
#define crypto_core_aes128decrypt_CONSTBYTES 0

#ifndef crypto_core_aes128decrypt_IMPLEMENTATION
#define crypto_core_aes128decrypt_IMPLEMENTATION "ref"
#endif
int crypto_core_aes128decrypt(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
#endif
