#include "aes_ocb.h"
#include "../../cipher/aes_core/aes_internal.h"

#define OCB_NONCE_LEN    12
#define OCB_TAG_LEN      16

static void nop( const block_t x, block_t y ) {}

static void getDelta( const count_t index,
                      const block_t Ld, const block_t delta0, block_t delta )
{
    count_t mask, bit = 1;
    block_t L;

    memcpy( L, Ld, sizeof L );
    memcpy( delta, delta0, BLOCKSIZE );

    while ((mask = index - bit) < index)
    {
        doubleBblock( L );
        mask &= bit <<= 1;
        if (!mask)
        {
            xorBlock( L, delta );
        }
    }
}

static void OCB_cipher( const uint8_t* key, const uint8_t* nonce,
                        const size_t ptextLen,
                        const void* aData, const size_t aDataLen,
                        const size_t dataSize, void* data, block_t tag )
{
    fmix_t cipher = ptextLen ? &rijndaelEncrypt : &rijndaelDecrypt;

    block_t offset[4] = { { 0 } };
    uint8_t *y;
    uint8_t *Ld = offset[0], *Ls = offset[1], *kt = offset[2], *del = offset[3];
    count_t n = nonce[OCB_NONCE_LEN - 1] % 64, i;
    uint8_t const s = 8 - n % 8, *x = kt + n / 8;

    memcpy( kt + BLOCKSIZE - OCB_NONCE_LEN, nonce, OCB_NONCE_LEN );
    kt[0 ] |= OCB_TAG_LEN << 4;
    kt[LAST - OCB_NONCE_LEN] |= 1;
    kt[LAST] &= 0xC0;

    getSubkeys( &doubleBblock, 0, key, Ls, Ld );
    rijndaelEncrypt( kt, kt );
    memcpy( del, kt + 1, HB );
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        del[i] ^= kt[i];
        kt[i] = (x[i] << 8 | x[i + 1]) >> s;
    }

    xMac( data, ptextLen, NULL, &nop, tag );
    i = 0, n = dataSize / BLOCKSIZE;

    for (y = data; i < n; y += BLOCKSIZE)
    {
        getDelta( ++i, Ld, kt, del );
        xorBlock( del, y );
        cipher( y, y );
        xorBlock( del, y );
    }
    if (n == 0)
    {
        del = kt;
        kt = offset[3];
    }
    if ((i = dataSize % BLOCKSIZE) != 0)
    {
        tag[i] ^= 0x80;
        xorBlock( Ls, del );
        mixThenXor( &rijndaelEncrypt, del, kt, y, i, y );
    }

    xMac( data, dataSize - ptextLen, NULL, &nop, tag );
    cMac( Ld, NULL, del, BLOCKSIZE, tag );

    i = 0, n = aDataLen / BLOCKSIZE;

    for (x = (uint8_t*)aData; i < n; x += BLOCKSIZE)
    {
        getDelta( ++i, Ld, x, del );
        rijndaelEncrypt( del, del );
        xorBlock( del, tag );
    }
    if ((i = aDataLen % BLOCKSIZE) != 0)
    {
        memset( kt, 0, BLOCKSIZE );
        getDelta( n, Ld, kt, del );
        cMac( NULL, Ls, x, i, del );
        xorBlock( del, tag );
    }
    AES_burn();
}

void AES_OCB_encrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* pntxt, const size_t ptextLen, void* crtxt )
{
    block_t tag = { 0 };
    uint8_t* auth = (uint8_t*) crtxt + ptextLen;

    memcpy( crtxt, pntxt, ptextLen );
    OCB_cipher( key, nonce, ptextLen, aData, aDataLen, ptextLen, crtxt, tag );
    memcpy( auth, tag, OCB_TAG_LEN );
}

char AES_OCB_decrypt( const uint8_t* key, const uint8_t* nonce,
                      const void* aData, const size_t aDataLen,
                      const void* crtxt, const size_t crtxtLen, void* pntxt )
{
    block_t tag = { 0 };
    uint8_t const* auth = (uint8_t*) crtxt + crtxtLen;

    memcpy( pntxt, crtxt, crtxtLen );
    OCB_cipher( key, nonce, 0, aData, aDataLen, crtxtLen, pntxt, tag );

    if (memcmp_s( auth, tag, OCB_TAG_LEN ))
    {
        SABOTAGE( pntxt, crtxtLen );
        return M_AUTHENTICATION_ERROR;
    }
    return M_RESULT_SUCCESS;
}
