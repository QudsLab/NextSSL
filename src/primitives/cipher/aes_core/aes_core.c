#include "aes_internal.h"

/* S-boxes and constants */
static const char sbox[256] =
    "c|w{\362ko\3050\01g+\376\327\253v\312\202\311}""\372YG\360\255\324\242\257"
    "\234\244r\300\267\375\223&6\?\367\3144\245\345\361q\3301\25\4\307#\303\030"
    "\226\5\232\a\22\200\342\353\'\262u\t\203,\32\33nZ\240R;\326\263)\343/\204S"
    "\321\0\355 \374\261[j\313\2769JLX\317\320\357\252\373CM3\205E\371\02\177P<"
    "\237\250Q\243@\217\222\2358\365\274\266\332!\20\377\363\322\315\f\023\354_"
    "\227D\27\304\247~=d]\31s`\201O\334\"*\220\210F\356\270\24\336^\v\333\3402:"
    "\nI\06$\\\302\323\254b\221\225\344y\347\3107m\215\325N\251lV\364\352ez\256"
    "\b\272x%.\034\246\264\306\350\335t\37K\275\213\212p>\265fH\3\366\16a5W\271"
    "\206\301\035\236\341\370\230\21i\331\216\224\233\036\207\351\316U(\337\214"
    "\241\211\r\277\346BhA\231-\17\260T\273\26";

static const char rsbox[256] =
    "R\tj\32506\2458\277@\243\236\201\363\327\373|\3439\202\233/\377\2074\216CD"
    "\304\336\351\313T{\2242\246\302#=\356L\225\vB\372\303N\b.\241f(\331$\262v["
    "\242Im\213\321%r\370\366d\206h\230\026\324\244\\\314]e\266\222lpHP\375\355"
    "\271\332^\25FW\247\215\235\204\220\330\253\0\214\274\323\n\367\344X\05\270"
    "\263E\6\320,\036\217\312?\17\2\301\257\275\3\1\023\212k:\221\21AOg\334\352"
    "\227\362\317\316\360\264\346s\226\254t\"\347\2555\205\342\3717\350\34u\337"
    "nG\361\32q\35)\305\211o\267b\16\252\30\276\33\374V>K\306\322y \232\333\300"
    "\376x\315Z\364\037\335\2503\210\a\3071\261\22\20Y\'\200\354_`Q\177\251\031"
    "\265J\r-\345z\237\223\311\234\357\240\340;M\256*\365\260\310\353\273<\203S"
    "\231a\027+\004~\272w\326&\341i\024cU!\f}";

static uint8_t RoundKey[BLOCKSIZE * ROUNDS + KEYSIZE];

#define SBoxValue(x)       ( sbox[x])
#define InvSBoxValue(x)    (rsbox[x])

static uint8_t xtime( uint8_t x )
{
    return (x > 0x7f) * 0x1b ^ (x << 1);
}

static uint8_t mixG8( uint8_t a, uint8_t b, uint8_t c, uint8_t d )
{
    b ^= a;
    d ^= b ^ c;
    c ^= a;
    a ^= d;
    c ^= xtime( d );
    b ^= xtime( c );
    a ^= xtime( b );
    return a;
}

void KeyExpansion( const uint8_t* key )
{
    uint8_t rcon = 1, i;
    memcpy( RoundKey, key, KEYSIZE );

    for (i = KEYSIZE; i < BLOCKSIZE * (ROUNDS + 1); i += 4)
    {
        switch (i % KEYSIZE)
        {
        case 0:
            memcpy( &RoundKey[i], &RoundKey[i - KEYSIZE], KEYSIZE );
            if (4 / Nk && !rcon)
            {
                rcon = 0x1b;
            }
            RoundKey[i    ] ^= SBoxValue( RoundKey[i - 3] ) ^ rcon;
            RoundKey[i + 1] ^= SBoxValue( RoundKey[i - 2] );
            RoundKey[i + 2] ^= SBoxValue( RoundKey[i - 1] );
            RoundKey[i + 3] ^= SBoxValue( RoundKey[i - 4] );
            rcon <<= 1;
            break;
#if AES___== 256
        case 48 - KEYSIZE:
            RoundKey[i    ] ^= SBoxValue( RoundKey[i - 4] );
            RoundKey[i + 1] ^= SBoxValue( RoundKey[i - 3] );
            RoundKey[i + 2] ^= SBoxValue( RoundKey[i - 2] );
            RoundKey[i + 3] ^= SBoxValue( RoundKey[i - 1] );
            break;
#endif
        default:
            XOR32BITS( RoundKey[ i - 4 ], RoundKey[ i ] );
            break;
        }
    }
}

static void AddRoundKey( const uint8_t round, block_t state )
{
    xorBlock( RoundKey + BLOCKSIZE * round, state );
}

static void SubBytes( block_t state )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        state[i] = SBoxValue( state[i] );
    }
}

static void ShiftRows( state_t state )
{
    uint8_t tmp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = tmp;

    tmp         = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = tmp;
    tmp         = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = tmp;

    tmp         = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = tmp;
}

static void MixColumns( state_t state )
{
    uint8_t C[4], i;
    for (i = 0; i < Nb; ++i)
    {
        COPYDWORD( state[i], C[0] );
        C[3] ^= C[1];
        C[1] ^= C[0];
        C[0] ^= C[2];
        C[2]  = xtime( C[0] );
        C[0] ^= xtime( C[1] );
        C[1]  = xtime( C[3] );

        state[i][0] ^= C[0] ^= C[3];
        state[i][1] ^= C[0] ^= C[2];
        state[i][2] ^= C[0] ^= C[1];
        state[i][3] ^= C[0] ^= C[2];
    }
}

void rijndaelEncrypt( const block_t input, block_t output )
{
    uint8_t r;
    state_t* mat = (void*) output;

    if (input != output)   memcpy( mat, input, BLOCKSIZE );

    for (r = 0; r != ROUNDS; )
    {
        AddRoundKey( r, output );
        SubBytes( output );
        ShiftRows( *mat );
        ++r != ROUNDS ? MixColumns( *mat ) : AddRoundKey( ROUNDS, output );
    }
}

static void InvSubBytes( block_t state )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        state[i] = InvSBoxValue( state[i] );
    }
}

static void InvShiftRows( state_t state )
{
    uint8_t tmp = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = tmp;

    tmp         = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = tmp;
    tmp         = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = tmp;

    tmp         = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = tmp;
}

static void InvMixColumns( state_t state )
{
    uint8_t C[4], i;
    for (i = 0; i < Nb; ++i)
    {
        COPYDWORD( state[i], C[0] );
        state[i][0] = mixG8( C[0], C[1], C[2], C[3] );
        state[i][1] = mixG8( C[1], C[2], C[3], C[0] );
        state[i][2] = mixG8( C[2], C[3], C[0], C[1] );
        state[i][3] = mixG8( C[3], C[0], C[1], C[2] );
    }
}

void rijndaelDecrypt( const block_t input, block_t output )
{
    uint8_t r;
    state_t* mat = (void*) output;

    if (input != output)   memcpy( mat, input, BLOCKSIZE );

    for (r = ROUNDS; r != 0; )
    {
        r-- != ROUNDS ? InvMixColumns( *mat ) : AddRoundKey( ROUNDS, output );
        InvShiftRows( *mat );
        InvSubBytes( output );
        AddRoundKey( r, output );
    }
}

/* Helpers */
void xorBlock( const block_t src, block_t dest )
{
    uint8_t i;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        dest[i] ^= src[i];
    }
}

void mixThenXor( fmix_t mix, const block_t B, block_t f,
                        const uint8_t* X, uint8_t n, uint8_t* Y )
{
    if (n == 0)  return;

    mix( B, f );
    while (n--)
    {
        Y[n] = f[n] ^ X[n];
    }
}

void xMac( const void* data, const size_t dataSize,
                  const block_t seed, fmix_t mix, block_t result )
{
    uint8_t const* x;
    count_t n = dataSize / BLOCKSIZE;

    for (x = data; n--; x += BLOCKSIZE)
    {
        xorBlock( x, result );
        mix( seed, result );
    }
    if ((n = dataSize % BLOCKSIZE) > 0)
    {
        while (n--)
        {
            result[n] ^= x[n];
        }
        mix( seed, result );
    }
}

char padBlock( const uint8_t len, block_t block )
{
    uint8_t n = BLOCKSIZE - len, *p = &block[len];
    memset( p, 0, n );
    return len; /* Default zero padding */
}

void copyLint( block_t block, size_t num, uint8_t pos )
{
    do
        block[pos++] = (uint8_t) num;
    while (num >>= 8);
}

void xorBEint( uint8_t* buff, size_t num, uint8_t pos )
{
    do
        buff[pos--] ^= (uint8_t) num;
    while (num >>= 8);
}

void incBlock( block_t block, uint8_t index )
{
    do
        if (++block[index])
            break;
    while ((index < 4 && ++index < 4) || --index > 8);
}

void doubleBblock( block_t array )
{
    int c = 0, i;
    for (i = BLOCKSIZE; i > 0; c >>= 8)
    {
        c |= array[--i] << 1;
        array[i] = (uint8_t) c;
    }
    array[LAST] ^= c * 0x87;
}

void doubleLblock( block_t array )
{
    int i, c = 0;
    for (i = 0; i < BLOCKSIZE; c >>= 8)
    {
        c |= array[i] << 1;
        array[i++] = (uint8_t) c;
    }
    array[0] ^= c * 0x87;
}

void divideBblock( block_t array )
{
    unsigned i, c = 0;
    for (i = 0; i < BLOCKSIZE; ++i)
    {
        c = c << 8 | array[i];
        array[i] = c >> 1;
    }
    if (c & 1)  array[0] ^= 0xe1;
}

void mulGF128( const block_t x, block_t y )
{
    uint8_t b, i;
    block_t result = { 0 };

    for (i = 0; i < BLOCKSIZE; ++i)
    {
        for (b = 0x80; b; b >>= 1)
        {
            if (x[i] & b)
            {
                xorBlock( y, result );
            }
            divideBblock( y );
        }
    }
    memcpy( y, result, sizeof result );
}

void divideLblock( block_t array )
{
    unsigned c = 0, i;
    for (i = BLOCKSIZE; i--; )
    {
        c = c << 8 | array[i];
        array[i] = c >> 1;
    }
    if (c & 1)  array[LAST] ^= 0xe1;
}

void dotGF128( const block_t x, block_t y )
{
    uint8_t b, i;
    block_t result = { 0 };

    for (i = BLOCKSIZE; i--; )
    {
        for (b = 0x80; b; b >>= 1)
        {
            divideLblock( y );
            if (x[i] & b)
            {
                xorBlock( y, result );
            }
        }
    }
    memcpy( y, result, sizeof result );
}

void cMac( const block_t K1, const block_t K2,
                  const void* data, const size_t dataSize, block_t mac )
{
    const uint8_t s = dataSize ? (dataSize - 1) % BLOCKSIZE + 1 : 0;
    const uint8_t *k = K1, *ps = s ? (uint8_t*) data + dataSize - s : &s;

    xMac( data, dataSize - s, mac, &rijndaelEncrypt, mac );
    if (s < BLOCKSIZE)
    {
        mac[s] ^= 0x80;
        k = K2;
    }
    xorBlock( k, mac );
    xMac( ps, s + !s, mac, &rijndaelEncrypt, mac );
}

void getSubkeys( fdouble_t gfdouble, const char quad,
                        const uint8_t* key, block_t D, block_t Q )
{
    AES_setkey( key );
    rijndaelEncrypt( D, D );
    if (quad)
    {
        gfdouble( D );
    }
    memcpy( Q, D, BLOCKSIZE );
    gfdouble( Q );
}

uint8_t memcmp_s( const void* src, const void* dest, const uint8_t len )
{
    const volatile char *p1 = src, *p2 = (const volatile char*) dest;
    volatile uint8_t result = 0;
    uint8_t i;
    for (i = 0; i != len; i++)
    {
        result |= p1[i] ^ p2[i];
    }
    return result;
}

void AES_burn(void)
{
    memset(RoundKey, 0, sizeof(RoundKey));
}
