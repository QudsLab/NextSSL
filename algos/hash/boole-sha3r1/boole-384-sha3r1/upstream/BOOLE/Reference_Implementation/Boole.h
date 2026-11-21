/* $Id: $ */
/* Boole: Boole hash, stream cipher and MAC header file */

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

#ifdef _WIN32
#define inline __inline
#endif

#ifndef _BLE_DEFINED
#define _BLE_DEFINED 1

/* Get nice, portable integer size constants */
#include <limits.h>
#if __STDC_VERSION__ >= 199901
#include <stdint.h>
#endif

/*
 * Definitions for Boole, and the SHA-3 interface.
 * WORDSIZE defines the variant of Boole.
 */
#ifndef WORDSIZE
#define WORDSIZE 64
#endif

/*
 * The following section is intended to define "WORD" to be an
 * appropriate unsigned integer type with WORDSIZE bits, and to define
 * some macros that work properly with WORDs even on machines where
 * the native integer type is larger. This is really hard stuff to get right.
 */
#if WORDSIZE == 16
#   define WORDSHIFT 4
#   if __STDC_VERSION__ >= 199901
#       define WORD uint16_t
#       define WORD_MAX UINT16_MAX
#   elif defined(_WIN32) || defined(_WIN64)
#       define WORD unsigned __int16
#       define WORD_MAX _UI16_MAX
#   else
#       define WORD unsigned short
#       define WORD_MAX USHORT_MAX
#   endif

#   if WORD_MAX == 0xFFFF
#       define ROTL(w,x) (((w) << (x))|((w) >> (16 - (x))))
#       define ROTR(w,x) (((w) >> (x))|((w) << (16 - (x))))
#   else
#       define ROTL(w,x) (((w) << (x))|(((w) & 0xFFFF) >> (16 - (x))))
#       define ROTR(w,x) ((((w) & 0xFFFF) >> (x))|((w) << (16 - (x))))
#   endif
/* end WORDSIZE 16 */

#elif WORDSIZE == 32
#   define WORDSHIFT 5
#   if __STDC_VERSION__ >= 199901 
#       define WORD uint32_t 
#       define WORD_MAX UINT32_MAX
#   elif defined(_WIN32) || defined(_WIN64)
#       define WORD unsigned __int32
#       define WORD_MAX _UI32_MAX
#   elif UINT_MAX >= 0xFFFFFFFF 
#       define WORD unsigned int
#       define WORD_MAX UINT_MAX
#   else
#       define WORD unsigned long
#       define WORD_MAX ULONG_MAX
#   endif

#   if WORD_MAX == 0xFFFFFFFF
#       define ROTL(w,x) (((w) << (x))|((w) >> (32 - (x))))
#       define ROTR(w,x) (((w) >> (x))|((w) << (32 - (x))))
#   else
#       define ROTL(w,x) (((w) << (x))|(((w) & 0xFFFFFFFF) >> (32 - (x))))
#       define ROTR(w,x) ((((w) & 0xFFFFFFFF) >> (x))|((w) << (32 - (x))))
#   endif
/* end WORDSIZE 32 */

#elif WORDSIZE == 64
#   define WORDSHIFT 6
#   if __STDC_VERSION__ >= 199901 
#       define WORD uint64_t 
#       define WORD_MAX UINT64_MAX
#   elif defined(_WIN32) || defined(_WIN64)
#       define WORD unsigned __int64
#       define WORD_MAX _UI64_MAX
#   elif UINT_MAX >= 0xFFFFFFFFFFFFFFFF
#       define WORD unsigned int
#       define WORD_MAX UINT_MAX
#   elif ULONG_MAX >= 0xFFFFFFFFFFFFFFFF
#       define WORD unsigned long
#       define WORD_MAX ULONG_MAX
#   else
#       define WORD unsigned long long
#       define WORD_MAX ULLONG_MAX
#   endif

#   if WORD_MAX == 0xFFFFFFFFFFFFFFFF
#     define ROTL(w,x) (((w) << (x))|((w) >> (64 - (x))))
#     define ROTR(w,x) (((w) >> (x))|((w) << (64 - (x))))
#   else
#     define ROTL(w,x) (((w) << (x))|(((w) & 0xFFFFFFFFFFFFFFFF) >> (64 - (x))))
#     define ROTR(w,x) ((((w) & 0xFFFFFFFFFFFFFFFF) >> (x))|((w) << (64 - (x))))
#   endif
/* end WORDSIZE 64 */

#else
#   error invalid WORDSIZE specified
#endif

/*
 * important definitions
 */
#define N	16 /* number of register elements, and diffusion iterations */

#define UCHAR unsigned char
typedef unsigned char	BitSequence;
typedef unsigned long long DataLength;
typedef enum {
	SUCCESS = 0,
	FAIL = 1,
	WARN_HASHBITLEN = 2, /* warning when length greater than expected security */
	BAD_TERMINATION = 3, /* update called after odd-sized call to update */
	BAD_NEEDNONCE = 4, /* attempt to use MAC/stream without nonce */
} HashReturn;

/*
 * state structure for hash/MAC
 */
typedef struct {
    int		hashbitlen;	/* number of bits of output -- 0 for stream */
    DataLength	nbits;		/* bits of input seen so far */
    WORD	R[N];		/* Working storage for the shift register */
    WORD	xsum;		/* XOR sum of input words */
    WORD	lsum;		/* rotating addition sum of input words */
    WORD	rsum;		/* rotating addition sum of input words */
    /* the following handle non-whole-word input/output */
    WORD	bbuf;		/* partial word buffer */
    int		nbuf;		/* number of part-word bits buffered */
    /* the following used for circular buffer fast implementation only */
    int		z;		/* current zero position */
} hashState;

/*
 * state structure for stream cipher (including hash/MAC)
 */
typedef struct {
    hashState	h;		/* includes state for hash/MAC */
    hashState	s;		/* state for stream cipher only */
    WORD	initR[N];	/* copy of post-key register to avoid rekey */
    int		neednonce;	/* nonce must be called */
} ble_ctx;

/*
 * some other useful definitions for WORDs
 */
#define BPW	(WORDSIZE/8)	/* Bytes per WORD */
#define BYTESIN(x) (((x)+7)>>3) /* how many bytes are needed for x bits */
#define WORDMASK ((WORD)(WORDSIZE-1)) /* mask for low order bits */

/*
 * external non SHA-3 interface definitions (for stream and MAC)
 */
HashReturn ble_key(ble_ctx *c, const UCHAR key[], int keylen, int maclen); /* set key */
HashReturn ble_nonce(ble_ctx *c, const UCHAR nonce[], int nlen); /* set Init Vector */
HashReturn ble_stream(ble_ctx *c, UCHAR *buf, int nbits); /* stream cipher */
HashReturn ble_macdata(ble_ctx *c, UCHAR *buf, int nbits); /* accumulate MAC */
HashReturn ble_encrypt(ble_ctx *c, UCHAR *buf, int nbits); /* enc+MAC */
HashReturn ble_decrypt(ble_ctx *c, UCHAR *buf, int nbits); /* dec+MAC */
HashReturn ble_mac(ble_ctx *c, BitSequence *hashval); /* finalize MAC */

/*
 * external interface definitions for SHA-3
 */
HashReturn Init(hashState *state, int hashbitlen);
HashReturn Update(hashState *state, const BitSequence *data,
	DataLength databitlen);
HashReturn Final(hashState *state, BitSequence *hashval);
HashReturn Hash(int hashbitlen, const BitSequence *data,
	DataLength databitlen, BitSequence *hashval);

#endif /* _BLE_DEFINED */
