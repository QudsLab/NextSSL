#include "aes_cmac.h"
#include "../../cipher/aes_core/aes_internal.h"

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT void AES_CMAC( const uint8_t* key,
               const void* data, const size_t dataSize, block_t mac )
{
    block_t K1 = { 0 }, K2;
    memcpy( mac, K1, sizeof K1 );

    getSubkeys( &doubleBblock, 1, key, K1, K2 );
    cMac( K1, K2, data, dataSize, mac );
    AES_burn();
}
