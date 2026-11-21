/* chi-common.c: CHI hash common functions */

/*
THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE AND AGAINST
INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <assert.h>
#include <string.h>

#include "chi.h"

/*
 * Step constants
 */
const WORD64
K[] = {
    0x9B05688C2B3E6C1FULL, 0xDBD99E6FF3C90BDCULL,
    0x4DBC64712A5BB168ULL, 0x767E27C3CF76C8E7ULL,
    0x21EE9AC5EF4C823AULL, 0xB36CCFC1204A9BD8ULL,
    0x754C8A7FB36BD941ULL, 0xCF20868F04A825E9ULL,
    0xABB379E0A8838BB0ULL, 0x12D8B70A5959E391ULL,
    0xB59168FA9F69E181ULL, 0x15C7D4918739F18FULL,
    0x4B547673EA8D68E0ULL, 0x3CED7326FCD0EF81ULL,
    0x09F1D77309998460ULL, 0x1AF3937415E91F32ULL,
    0x1F83D9ABFB41BD6BULL, 0x23C4654C2A217583ULL,
    0x2842012131573F2AULL, 0xA59916ACA3991FCAULL,
    0xEC1B7C06FD19D256ULL, 0x1EC785BCDC8BAF26ULL,
    0x69CA4E0FF2E6BDD8ULL, 0xCA2575EE6C950D0EULL,
    0x5BCF66D2FB3D99F6ULL, 0x9D6D08C7BBCA18F3ULL,
    0xEEF64039F2175E83ULL, 0x00ED5AEBAA2AB6E0ULL,
    0x5040712FC29AD308ULL, 0x6DAFE433438D2C43ULL,
    0xBD7FAA3F06C71F15ULL, 0x03B5AA8CE9B6A4DDULL,
    0x5BE0CD19137E2179ULL, 0x867F5E3B72221265ULL,
    0x43B6CBE0D67F4A20ULL, 0xDB99D767CB0E4933ULL,
    0xDC450DBC469248BDULL, 0xFE1E5E4876100D6FULL,
    0xB799D29EA1733137ULL, 0x16EA7ABCF92053C4ULL,
    0xBE3ECE968DBA92ACULL, 0x18538F84D82C318BULL,
    0x38D79F4E9C8A18C0ULL, 0xA8BBC28F1271F1F7ULL,
    0x2796E71067D2C8CCULL, 0xDE1BF2334EDB3FF6ULL,
    0xB094D782A857F9C1ULL, 0x639B484B0C1DAED1ULL,
    0xCBBB9D5DC1059ED8ULL, 0xE7730EAFF25E24A3ULL,
    0xF367F2FC266A0373ULL, 0xFE7A4D34486D08AEULL,
    0xD41670A136851F32ULL, 0x663914B66B4B3C23ULL,
    0x1B9E3D7740A60887ULL, 0x63C11D86D446CB1CULL,
    0xD167D2469049D628ULL, 0xDDDBB606B9A49E38ULL,
    0x557F1C8BEE68A7F7ULL, 0xF99DC58B50F924BDULL,
    0x205ACC9F653512A5ULL, 0x67C66344E4BAB193ULL,
    0x18026E467960D0C8ULL, 0xA2F5D84DAECA8980ULL,
    0x629A292A367CD507ULL, 0x98E67012D90CBB6DULL,
    0xEED758D1D18C7E35ULL, 0x031C02E4437DC71EULL,
    0x79B63D6482198EB7ULL, 0x936A9D7E8C9E4B33ULL,
    0xB30CA682C3E6C65DULL, 0xCC442382BA4262FAULL,
    0x51179BA5A1D37FF6ULL, 0x7202BDE7A98EEA51ULL,
    0x2B9F65D1DF9C610FULL, 0xF56B742B0AF1CE83ULL,
    0xF9989D199B75848BULL, 0xD142F19D8B46D578ULL,
    0x7A7580514D75EA33ULL, 0xB74F9690808E704DULL
};

/*
 * Initial state values for different bit lengths
 */
const WORD64
_224_init[] = {
    0xA54FF53A5F1D36F1ULL, 0xCEA7E61FC37A20D5ULL,
    0x4A77FE7B78415DFCULL, 0x8E34A6FE8E2DF92AULL,
    0x4E5B408C9C97D4D8ULL, 0x24A05EEE29922401ULL
};

const WORD64
_256_init[] = {
    0x510E527FADE682D1ULL, 0xDE49E330E42B4CBBULL,
    0x29BA5A455316E0C6ULL, 0x5507CD18E9E51E69ULL,
    0x4F9B11C81009A030ULL, 0xE3D3775F155385C6ULL
};

const WORD64
_384_init[] = {
    0xA54FF53A5F1D36F1ULL, 0xCEA7E61FC37A20D5ULL,
    0x4A77FE7B78415DFCULL, 0x8E34A6FE8E2DF92AULL,
    0x4E5B408C9C97D4D8ULL, 0x24A05EEE29922401ULL,
    0x5A8176CFFC7C2224ULL, 0xC3EDEBDA29BEC4C8ULL,
    0x8A074C0F4D999610ULL
};

const WORD64
_512_init[] = {
    0x510E527FADE682D1ULL, 0xDE49E330E42B4CBBULL,
    0x29BA5A455316E0C6ULL, 0x5507CD18E9E51E69ULL,
    0x4F9B11C81009A030ULL, 0xE3D3775F155385C6ULL,
    0x489221632788FB30ULL, 0x41921DB8FEEB38C2ULL,
    0x9AF94A7C48BBD5B6ULL
};

/*
 * Byte i of 64 bit x.  i==0 returns top byte.
 */
#define BYTE(x, i) ((BitSequence)(((x) >> (8 * (7 - i))) & 0xFF))

#define WORD2BYTE(w, b)         \
    do {                        \
        (b)[7] = BYTE(w, 7);    \
        (b)[6] = BYTE(w, 6);    \
        (b)[5] = BYTE(w, 5);    \
        (b)[4] = BYTE(w, 4);    \
        (b)[3] = BYTE(w, 3);    \
        (b)[2] = BYTE(w, 2);    \
        (b)[1] = BYTE(w, 1);    \
        (b)[0] = BYTE(w, 0);    \
    } while(0)

/*
 * Hashes the bytes in hs_DataBuffer.  Either calls te 256 or 512 hash.
 *
 * state    The current state.
 * final    1 for final block in hash, 0 for intermediate blocks.
 */
static void
hash
(
    hashState   *state,
    int         final
)
{
    switch (state->hs_HashBitLen)
    {
    case 224:
    case 256:
        _256_update(state, final);
        break;

    case 384:
    case 512:
        _512_update(state, final);
        break;
    }
}

/*
 * Small routine for incrementing total input data length by hs_DataLen.
 *
 * Parameters:
 *      state       A structure that holds the hashState information
 *
 * Returns:
 *      SUCCESS         - on success.
 *      TOO_MUCH_DATA   - on overflow.
 */
static INLINE HashReturn
inc_total_len
(
    hashState   *state
)
{
    uint64_t    old_len;

    old_len = state->hs_TotalLenLow;
    state->hs_TotalLenLow += state->hs_DataLen;
    if (old_len > state->hs_TotalLenLow)
    {
        switch (state->hs_HashBitLen)
        {
        case 224:
        case 256:
            return TOO_MUCH_DATA;

        case 384:
        case 512:
            if (++state->hs_TotalLenHigh == 0)
                return TOO_MUCH_DATA;
        }
    }

    return SUCCESS;
}

/*
 * Initializes a hashState with the intended hash length of this particular
 * instantiation.
 *
 * Additionally, any data independent setup is performed.
 *
 * Parameters:
 *     state        A structure that holds the hashState information
 *     hashbitlen   An integer value that indicates the length of the hash
 *                  output in bits.
 *
 * Returns:
 *     SUCCESS        - on success
 *     BAD_HASHBITLEN - hashbitlen is invalid (e.g., unknown value)
 *
 */
HashReturn
Init
(
    hashState   *state,
    int         hashbitlen
)
{
    if (state == NULL)
       return BAD_STATE;

    switch (hashbitlen)
    {
    default:
        return BAD_HASHLEN;

    case 224:
        memcpy(state->hs_State.small, _224_init, _256_STATE_N * sizeof(WORD64));
        state->hs_MessageLen = _256_MSG_BLK_LEN;
        break;

    case 256:
        memcpy(state->hs_State.small, _256_init, _256_STATE_N * sizeof(WORD64));
        state->hs_MessageLen = _256_MSG_BLK_LEN;
        break;

    case 384:
        memcpy(state->hs_State.large, _384_init, _512_STATE_N * sizeof(WORD64));
        state->hs_MessageLen = _512_MSG_BLK_LEN;
        break;

    case 512:
        memcpy(state->hs_State.large, _512_init, _512_STATE_N * sizeof(WORD64));
        state->hs_MessageLen = _512_MSG_BLK_LEN;
        break;
    }

    state->hs_HashBitLen = (HashBitLen)hashbitlen;
    state->hs_DataLen      = 0;
    state->hs_TotalLenLow  = 0;
    state->hs_TotalLenHigh = 0;
   
    return SUCCESS;
}

/*
 * Process the supplied data.
 *
 * Parameters:
 *    state         A structure that holds the hashState information
 *    data          The data to be hashed
 *    databitlen    The length, in bits, of the data to be hashed
 *
 * Returns:
 *    SUCCESS  - on success
 *    BAD_DATA - data is NULL, or call made to update and previous
 *               call passed in a partial byte.
 *
 */
HashReturn Update
(
    hashState           *state,
    const BitSequence   *data,
    DataLength          databitlen
)
{
    HashReturn          ret;
    uint32_t            cs;
    /*
     * cs       Amount of data copied out of data into hash block.
     */

    if (state == NULL)
       return BAD_STATE;
    if (data == NULL)
        return BAD_DATA;

    /*
     * Handle partial bytes only if last call to update
     */
    if ((state->hs_DataLen & 0x7) != 0)
        return BAD_DATA;

    while (databitlen > 0)
    {
        cs = MIN((uint32_t)databitlen, state->hs_MessageLen - state->hs_DataLen);

        memcpy(state->hs_DataBuffer+state->hs_DataLen / 8, data, (cs + 7) / 8);
        data += cs / 8;
        databitlen -= cs;
        state->hs_DataLen += cs;

        if (state->hs_DataLen >= (uint32_t)state->hs_MessageLen)
        {
            /*
             * Hash hs_DataBuffer
             */
            hash(state, 0);
            ret = inc_total_len(state);
            if (ret != SUCCESS)
                return ret;
            state->hs_DataLen = 0;
        }
    }

    return SUCCESS;
}

/*
 * Perform any post processing and output filtering required and return
 * the final hash value.
 *
 * Parameters:
 *     state    A structure that holds the hashState information
 *     hashval  The storage for the final hash value to be returned
 *
 * Returns:
 *     SUCCESS - on success
 *
 */
HashReturn
Final
(
    hashState   *state,
    BitSequence *hashval
)
{
    HashReturn  ret;
    uint32_t    whole_bytes;
    uint32_t    last_byte_bits;
    uint32_t    left_over_bytes;
    uint32_t    length_bytes;
    /*
     * whole_bytes      Number of whole bytes in last block with data in them.
     * last_byte_bits   Number of bits in last byte in last block with data in
     *                  them.
     * left_over_bytes  The number of bytes in the last message block that
     *                  have padding & the message length in them.
     * length_bytes     The number of bytes to use right at the end of the
     *                  message to store the message length.
     */

    if (state == NULL)
       return BAD_STATE;
    if (hashval == NULL)
       return BAD_HASHVALPTR;

    ret = inc_total_len(state);
    if (ret != SUCCESS)
        return ret;

    switch (state->hs_HashBitLen)
    {
    case 224:
    case 256:
        length_bytes = sizeof (WORD64);
        break;

    default: /* Suppress compiler warning. */
        assert(0);
    case 384:
    case 512:
        length_bytes = sizeof (WORD64) * 2;
        break;
    }

    whole_bytes = state->hs_DataLen / 8;
    last_byte_bits = state->hs_DataLen % 8;
   
    /*
     * Padding
     *
     * Append a 1 to end of buffer and pad byte with zeros.
     */
    state->hs_DataBuffer[whole_bytes] &= ~((1 << (7-last_byte_bits)) - 1);
    state->hs_DataBuffer[whole_bytes] |= (1 << (7-last_byte_bits));

    /*
     * Skip to end of byte
     */
    state->hs_DataLen += (8 - last_byte_bits);

    left_over_bytes = (state->hs_MessageLen - state->hs_DataLen) / 8;

    if (left_over_bytes < length_bytes)
    {
        /*
         * length doesn't fit in the end of this block.  Pad this block to the
         * end using zeros then write the length in the next block.
         */
        memset(state->hs_DataBuffer + state->hs_DataLen/8, 0, left_over_bytes);
        hash(state, 0);
        state->hs_DataLen = 0;
        left_over_bytes = state->hs_MessageLen / 8;
    }

    memset(state->hs_DataBuffer + state->hs_DataLen / 8, 0, left_over_bytes);

    /*
     * Write 64 bit or 128 bit message length.
     */
    whole_bytes = state->hs_MessageLen / 8 - length_bytes;
    if (length_bytes == sizeof (WORD64) * 2)
    {
        WORD2BYTE(state->hs_TotalLenHigh, state->hs_DataBuffer + whole_bytes);
        whole_bytes += sizeof (WORD64);
    }
    else
    {
        assert(state->hs_TotalLenHigh == 0);
        if (state->hs_TotalLenHigh != 0)
            return BAD_STATE;
    }

    WORD2BYTE(state->hs_TotalLenLow, state->hs_DataBuffer + whole_bytes);
    state->hs_DataLen = state->hs_MessageLen;

    /*
     * Hash final block
     * */
    hash(state, 1);
    state->hs_DataLen = 0;

    /*
     * Write hash output into buffer in network byte order.
     */
    switch (state->hs_HashBitLen)
    {
    case 224:
        WORD2BYTE(state->hs_State.large[0],hashval);
        WORD2BYTE(state->hs_State.large[1],hashval + 8);
        WORD2BYTE(state->hs_State.large[3],hashval + 16);
        hashval[24] = BYTE(state->hs_State.large[4], 0);
        hashval[25] = BYTE(state->hs_State.large[4], 1);
        hashval[26] = BYTE(state->hs_State.large[4], 2);
        hashval[27] = BYTE(state->hs_State.large[4], 3);
        break;

    case 256:
        WORD2BYTE(state->hs_State.large[0],hashval);
        WORD2BYTE(state->hs_State.large[1],hashval + 8);
        WORD2BYTE(state->hs_State.large[3],hashval + 16);
        WORD2BYTE(state->hs_State.large[4],hashval + 24);
        break;

    case 384:
        WORD2BYTE(state->hs_State.large[0],hashval);
        WORD2BYTE(state->hs_State.large[1],hashval + 8);
        WORD2BYTE(state->hs_State.large[2],hashval + 16);
        WORD2BYTE(state->hs_State.large[3],hashval + 24);
        WORD2BYTE(state->hs_State.large[4],hashval + 32);
        WORD2BYTE(state->hs_State.large[5],hashval + 40);
        break;

    case 512:
        WORD2BYTE(state->hs_State.large[0],hashval);
        WORD2BYTE(state->hs_State.large[1],hashval + 8);
        WORD2BYTE(state->hs_State.large[2],hashval + 16);
        WORD2BYTE(state->hs_State.large[3],hashval + 24);
        WORD2BYTE(state->hs_State.large[4],hashval + 32);
        WORD2BYTE(state->hs_State.large[5],hashval + 40);
        WORD2BYTE(state->hs_State.large[6],hashval + 48);
        WORD2BYTE(state->hs_State.large[7],hashval + 56);
        break;
    }

    return SUCCESS;
}

/*
 * Hash the supplied data and provide the resulting hash value. Set return
 * code as appropriate.
 *
 * Parameters:
 *    hashbitlen    The length in bits of the desired hash value
 *    data          The data to be hashed
 *    databitlen    The length, in bits, of the data to be hashed
 *    hashval       The resulting hash value of the provided data
 *
 * Returns:
 *    SUCCESS - on success
 *    FAIL – arbitrary failure
 *    BAD_HASHLEN – unknown hashbitlen requested
 */
HashReturn
Hash
(
    int                 hashbitlen,
    const BitSequence   *data,
    DataLength          databitlen,
    BitSequence         *hashval
)
{
    hashState           hs;
    HashReturn          ret_code;

    if ((ret_code = Init(&hs, hashbitlen)) != SUCCESS)
        return ret_code;

    if ((ret_code = Update(&hs, data, databitlen)) != SUCCESS)
        return ret_code;

    ret_code = Final(&hs, hashval);

    return ret_code;
}

