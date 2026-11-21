/* chi.h: CHI hash */

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
#ifndef _CHI_H
#define _CHI_H

/*
 * Startard sizes
 */
#if defined(_WIN32) || defined(_WIN64)
    typedef unsigned __int32 uint32_t;
    typedef unsigned __int64 uint64_t;
#else
#   include <stdint.h>
#endif

typedef uint32_t WORD32;
typedef uint64_t WORD64;

/*
 * Function inlining
 */
#if !defined(USE_INLINE) && !defined(DONT_USE_INLINE)
#   define USE_INLINE
#endif

#ifdef USE_INLINE
#   if defined(_WIN32) || defined(_WIN64)
#       define INLINE __inline
#   else
#       define INLINE inline
#   endif
#else
#   define INLINE
#endif

/*
 * Fundamental algorithm constants.
 */
#define _256_STEPS      20      /* Steps in 256 bit hash.                     */
#define _512_STEPS      40      /* Steps in 512 bit hash.                     */
#define _256_STATE_N    6       /* The number of words in the internal state
                                 * for the 256 bit hash.
                                 */
#define _512_STATE_N    9       /* The number of words in the internal state
                                 * for the 512 bit hash.
                                 */
#define _256_MSG_N      (_256_MSG_BLK_LEN / 64)
                                /* The length in 64 bit ints of the message
                                 * block in bits for the 256 bit hash.
                                 */
#define _512_MSG_N      (_512_MSG_BLK_LEN / 64)
                                /* The length in 64 bit ints of the message
                                 * block in bits for the 256 bit hash.
                                 */

/*
 * Valid message block lengths.
 * */
typedef enum {
    _256_MSG_BLK_LEN = 512,
    _512_MSG_BLK_LEN = 1024
} MsgBlkLen;
/*
 * _256_MSG_BLK_LEN     The length in bits of the message block for the 256
 *                      bit hash.
 * _512_MSG_BLK_LEN     The length in bits of the message block for the 512
 *                      bit hash.
 */

/*
 * Valid hash bit lengths.
 */
typedef enum {
    _224_HASH_BIT_LEN = 224,
    _256_HASH_BIT_LEN = 256,
    _384_HASH_BIT_LEN = 384,
    _512_HASH_BIT_LEN = 512
} HashBitLen;

/*
 * Standard MIN macro
 */
#define MIN(x, y)  ((x) < (y) ? (x) : (y))

/*
 * Step constants
 */
extern const WORD64 K[];
extern const WORD64 _224_init[];
extern const WORD64 _256_init[];
extern const WORD64 _384_init[];
extern const WORD64 _512_init[];

/*
 * Local function declarations
 */
extern void _256_update();
extern void _512_update();

/* NIST API */

/*
 * BitSequence type for Message Data
 */
typedef unsigned char BitSequence;

/*
 * DataLength type big, for big data lengths!.
 */
typedef unsigned long long DataLength;

/*
 * Error code for external Interface
 */
typedef enum {
    SUCCESS       = 0,
    FAIL          = 1,
    BAD_HASHLEN   = 2,
    BAD_STATE     = 3,
    BAD_DATA      = 4,
    TOO_MUCH_DATA = 5,
    BAD_HASHVALPTR
} HashReturn;
/*
 * BAD_STATE            State either NULL or corrupted.
 * BAD_DATA             Either NULL passed for data or Update called with
 *                      a partial byte, then called again with more data.
 * TOO_MUCH_DATA        Very unlikely case that too much data was passed to
 *                      hash function.
 * BAD_HASHVALPTR       Pointer for returning hash value invalid.
 */

/*
 * Structure that stores the hash state.
 */
typedef struct {
    union {
        WORD64 small[_256_STATE_N];
        WORD64 large[_512_STATE_N];
        WORD32 small32[2*_256_STATE_N];
        WORD32 large32[2*_512_STATE_N];
    } hs_State;                     /* Contents of internal state             */

    HashBitLen  hs_HashBitLen;      /* Length of the Hash.  Passed into Init. */
    MsgBlkLen   hs_MessageLen;      /* Length of message block in bits.  This
                                     * is set in Init depending on hashbitlen
                                     * to _256_MSG_LENGTH for 224,256 bit hash
                                     * and _512_MSG_LENGTH for 384,512 bit
                                     * hash.
                                     */
    uint64_t    hs_TotalLenLow;     /* Total length of message in bits.  Does
                                     * not include length of padding.
                                     */
    uint64_t    hs_TotalLenHigh;    /* For exceedingly long messages.
                                     */
    uint32_t    hs_DataLen;         /* Number of unprocess bits in
                                     * hs_DataBuffer.
                                     */
    BitSequence hs_DataBuffer[128]; /* Buffer for accumulating message.       */
} hashState;

/*
 * External Interface
 */
HashReturn Init(hashState*, int); 
HashReturn Update(hashState*, const BitSequence*, DataLength); 
HashReturn Final(hashState*, BitSequence*); 
HashReturn Hash(int, const BitSequence*, DataLength, BitSequence*);

#endif /* _CHI_H */
