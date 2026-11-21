/* NextSSL compat header (not upstream code): SUPERCOP lib crypto_core_aes128encrypt built from core_aes128encrypt/api.h (implementation ref). */
#ifndef NS_CRYPTO_CORE_AES128ENCRYPT_H
#define NS_CRYPTO_CORE_AES128ENCRYPT_H
#define crypto_core_aes128encrypt_OUTPUTBYTES 16
#define crypto_core_aes128encrypt_INPUTBYTES 16
#define crypto_core_aes128encrypt_KEYBYTES 16
#define crypto_core_aes128encrypt_CONSTBYTES 0

#ifndef crypto_core_aes128encrypt_IMPLEMENTATION
#define crypto_core_aes128encrypt_IMPLEMENTATION "ref"
#endif
int crypto_core_aes128encrypt(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);
#endif
