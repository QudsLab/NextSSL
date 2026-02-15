#include "aes_poly1305.h"
#include "../../cipher/aes_core/aes_internal.h"

#define PL (BLOCKSIZE + 1)

static void addLblocks( const uint8_t* x, const uint8_t len, uint8_t* y )
{
    int a, i;
    for (i = a = 0; i < len; a >>= 8)
    {
        a += x[i] + y[i];
        y[i++] = (uint8_t) a;
    }
}

static void modP1305( uint8_t* block, int32_t q )
{
    if (q < 4)  return;

    block[PL - 1] &= 3;

    for (q = (q >> 2) * 5; q; q >>= 8)
    {
        q += *block;
        *block++ = (uint8_t) q;
    }
}

static void mulLblocks( const uint8_t* x, uint8_t* y )
{
    uint8_t n = PL, result[PL] = { 0 };
    while (n--)
    {
        uint8_t s = 8 * (n != 0), i;
        int32_t m = 0, y_n = y[n];

        for (i = 0; i < sizeof result; ++i)
        {
            m >>= 8;
            m += (y_n * x[i] + result[i]) << s;
            result[i] = (uint8_t) m;
        }
        modP1305( result, m );
    }
    memcpy( y, result, sizeof result );
}

void AES_Poly1305( const uint8_t* keys, const block_t nonce,
                   const void* data, const size_t dataSize, block_t mac )
{
    uint8_t r[PL], rk[PL] = { 1 }, c[PL] = { 0 }, poly[PL] = { 0 }, s = PL - 1;
    count_t q = (dataSize - 1) / BLOCKSIZE;
    const char* pos = (const char*) data + dataSize;

    AES_setkey( keys );
    rijndaelEncrypt( nonce, mac );
    AES_burn();

    if (!dataSize)  return;

    memcpy( r, keys + KEYSIZE, s );
    for (r[s] = 0; s > 3; s -= 3)
    {
        r[s--] &= 0xFC;
        r[s  ] &= 0x0F;
    }
    s = dataSize - BLOCKSIZE * q;
    do
    {
        memcpy( c, pos -= s, s );
        c[s] = 1;
        s = BLOCKSIZE;
        mulLblocks( r, rk );
        mulLblocks( rk, c );
        addLblocks( c, PL, poly );
        modP1305( poly, poly[s] );

    } while (q--);

    q = poly[s] * 4;
    if (poly[0] > 0xFA && q == 12)
    {
        for (q = 1; poly[q] == 0xFF; ++q);
    }
    modP1305( poly, q / 4 );

    addLblocks( poly, BLOCKSIZE, mac );
}
