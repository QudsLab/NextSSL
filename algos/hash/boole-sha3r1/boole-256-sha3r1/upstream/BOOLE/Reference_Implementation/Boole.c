/* $Id: $ */
/* Boole: Boole hash, stream cipher and MAC -- reference implementation */
 
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

/* interface */
#include <stdlib.h>
#include <string.h>
#include "Boole.h"

#define INITSUM 0x6996c53a	/* initial value of sums */

/* some useful macros -- machine independent little-endian */
#define Byte(x,i) ((UCHAR)(((x) >> (8*(i))) & 0xFF))

#if WORDSIZE == 64
#define BYTE2WORD(b) ( \
	(((WORD)(b)[7] & 0xFF)<<56) | \
	(((WORD)(b)[6] & 0xFF)<<48) | \
	(((WORD)(b)[5] & 0xFF)<<40) | \
	(((WORD)(b)[4] & 0xFF)<<32) | \
	(((WORD)(b)[3] & 0xFF)<<24) | \
	(((WORD)(b)[2] & 0xFF)<<16) | \
	(((WORD)(b)[1] & 0xFF)<<8) | \
	(((WORD)(b)[0] & 0xFF)))
#elif WORDSIZE == 32
#define BYTE2WORD(b) ( \
	(((WORD)(b)[3] & 0xFF)<<24) | \
	(((WORD)(b)[2] & 0xFF)<<16) | \
	(((WORD)(b)[1] & 0xFF)<<8) | \
	(((WORD)(b)[0] & 0xFF)))
#else
#define BYTE2WORD(b) ( \
	(((WORD)(b)[1] & 0xFF)<<8) | \
	(((WORD)(b)[0] & 0xFF)))
#endif

#if WORDSIZE == 64
#define XORWORD(w, b) { \
	(b)[7] ^= Byte(w,7); \
	(b)[6] ^= Byte(w,6); \
	(b)[5] ^= Byte(w,5); \
	(b)[4] ^= Byte(w,4); \
	(b)[3] ^= Byte(w,3); \
	(b)[2] ^= Byte(w,2); \
	(b)[1] ^= Byte(w,1); \
	(b)[0] ^= Byte(w,0); \
    }
#elif WORDSIZE == 32
#define XORWORD(w, b) { \
	(b)[3] ^= Byte(w,3); \
	(b)[2] ^= Byte(w,2); \
	(b)[1] ^= Byte(w,1); \
	(b)[0] ^= Byte(w,0); \
    }
#else
#define XORWORD(w, b) { \
	(b)[1] ^= Byte(w,1); \
	(b)[0] ^= Byte(w,0); \
    }
#endif

/* Nonlinear transform (sbox) of a word.
 * There are two slightly different combinations.
 */
#if WORDSIZE == 16
inline static WORD
sbox1(WORD w)
{
    w ^= ROTL(w, 9)  | ROTL(w, 13);
    w ^= ~ROTL(w, 10) | ROTL(w, 15);
    return w;
}

inline static WORD
sbox2(WORD w)
{
    w ^= ROTL(w, 3)  | ROTL(w, 14);
    w ^= ~ROTL(w, 9) | ROTL(w, 10);
    return w;
}

#elif WORDSIZE == 32
inline static WORD
sbox1(WORD w)
{
    w ^= ROTL(w, 5)  | ROTL(w, 7);
    w ^= ROTL(w, 19) | ROTL(w, 22);
    return w;
}

inline static WORD
sbox2(WORD w)
{
    w ^= ROTL(w, 7)  | ROTL(w, 22);
    w ^= ROTL(w, 5) | ROTL(w, 19);
    return w;
}

#elif WORDSIZE == 64
inline static WORD
sbox1(WORD w)
{
    w ^= INITSUM;
    w ^= ROTL(w, 34)  | ROTL(w, 42);
    w ^= ROTL(w, 20)  | ROTL(w, 55);
    w ^= (w << 3) | ROTL(w, 60);
    return w;
}

inline static WORD
sbox2(WORD w)
{
    w ^= INITSUM;
    w ^= ROTR(w, 35)  | ROTR(w, 46);
    w ^= ROTR(w, 27)  | ROTR(w, 52);
    w ^= (w >> 5) | ROTR(w, 55);
    return w;
}
#endif

/* cycle the contents of the register
 */
static void
cycle(hashState *c)
{
    WORD	t;
    int		i;

    /* nonlinear feedback function */
    t = c->R[12] ^ c->R[13];
    t = sbox1(t) ^ ROTL(c->R[0], 1);
    /* shift register */
    for (i = 1; i < N; ++i)
	c->R[i-1] = c->R[i];
    c->R[N-1] = t;
    /* feed forward */
    t = sbox2(c->R[2] ^ c->R[15]);
    c->R[0] ^= t;
}

/* Incorporate data word into the state
 */
static void
datacycle(hashState *c, WORD i)
{
    c->xsum ^= i;
    c->lsum = sbox1(c->lsum) ^ i;
    c->rsum ^= c->lsum;
    c->lsum = ROTL(c->lsum, 1);
    c->rsum = ROTR(c->rsum, 1);
    c->R[3] ^= c->lsum; /* becomes input to sbox1 before shift */
    c->R[13] ^= c->rsum; /* becomes input to sbox2 after register shift */
    cycle(c);
}

/* Return a stream word from the state
 */
static WORD
streamcycle(hashState *c)
{
    cycle(c);
    return c->R[0] ^ c->R[8] ^ c->R[12];
}

/* "soft reset" -- used whenever transitioning between input/output modes.
 * Basically sets the ancillary variables to a sane state.
 */
static void
ble_softreset(hashState *c)
{
    c->nbits = 0;
    c->xsum = 0;
    c->lsum = (WORD) INITSUM; /* truncates in 16-bit case */
    c->rsum = (WORD) ROTL((WORD)INITSUM, 8); /* truncates in 16-bit case */
    c->nbuf = 0; /* no bits buffered for input or output */
    c->bbuf = 0; /* don't care */
}

/* initialise to known state for hash or pre-keying
 */
static void
ble_initstate(hashState *c)
{
    int		i;

    c->R[0] = sbox1((WORD)1);
    for (i = 1; i < N; ++i)
	c->R[i] = sbox1(c->R[i-1]);
    /* reasonable values for everything else */
    ble_softreset(c);
}

/* Diffuse changes through the register
 */
static void
ble_diffuse(hashState *c)
{
    int		i;

    for (i = 0; i < N; ++i)
	cycle(c);
}

/* Having accumulated data, finish absorbing it.
 */
static void
ble_finish(hashState *c)
{
    int		i;
    DataLength	nbits;

    /* handle any previously buffered input bits or bytes */
    if (c->nbuf != 0) {
	datacycle(c, c->bbuf);
	/* hash finalization calls this twice... only do it once. */
	c->nbuf = 0;
    }
    
    /* Perturb the state to mark end of input.
     * c->nbits is exactly how many bits of input there were.
     * No further padding or disambiguation is necessary, so
     * long as this goes into the state.
     * The accumulated data is incorporated in a way that
     * can't otherwise be duplicated, frustrating extension
     * attacks.
     * Note also that since the register and the other data
     * words are dependent on the same data, this disturbance
     * is not easily invertible.
     */
    nbits = c->nbits;
    for (i = 0; i < sizeof(DataLength)/BPW; ++i) {
	c->R[i] ^= (WORD)nbits;
	/* shifting twice below is a crock to avoid a compiler warning
	 * in the 64-bit case.
	 */
	nbits >>= WORDSIZE/2;
	nbits >>= WORDSIZE/2;
    }
    /* everything else is already WORD sized. */
    c->R[4] ^= c->hashbitlen;
    for (i = 4; i < N; i += 3) {
	c->R[i] ^= c->lsum;
	c->R[i+1] ^= c->xsum;
	c->R[i+2] ^= c->rsum;
    }

    ble_diffuse(c);
}

/* XOR pseudo-random bytes into buffer (stream cipher).
 * c->nbuf is how many unused bits remain in c->bbuf.
 */
HashReturn
ble_gen(hashState *c, UCHAR *buf, int nbits)
{
    UCHAR       *endbuf;

    /* handle any previously buffered bits */
    if ((c->nbuf & 0x7) != 0) {
	/* attempt to generate more stream after partial bytes */
	return BAD_TERMINATION;
    }
    while (c->nbuf != 0 && nbits >= 8) {
	*buf++ ^= c->bbuf & 0xFF;
	c->bbuf >>= 8;
	c->nbuf -= 8;
	nbits -= 8;
    }

    /* handle whole words */
    endbuf = &buf[(nbits & ~WORDMASK) >> 3];
    while (buf < endbuf)
    {
	c->bbuf = streamcycle(c);
	XORWORD(c->bbuf, buf);
	buf += BPW;
    }

    /* handle any trailing bits */
    nbits &= WORDMASK;
    if (nbits != 0) {
	c->bbuf = streamcycle(c);
	c->nbuf = WORDSIZE;
	/* whole bytes */
	while (nbits >= 8) {
	    *buf++ ^= c->bbuf & 0xFF;
	    c->bbuf >>= 8;
	    c->nbuf -= 8;
	    nbits -= 8;
	}
	if (nbits != 0) {
	    /* partial byte left -- clobber bbuf, it can't be used again */
	    c->bbuf &= (0xFF & (0xFF00 >> nbits));
	    *buf ^= c->bbuf & 0xFF;
	    c->nbuf -= nbits;
	}
    }
    return SUCCESS;
}

/* accumulate words into hash/MAC
 * c->nbuf is how much space remains in c->bbuf.
 */
static HashReturn
ble_update(hashState *c, const UCHAR *buf, DataLength nbits)
{
    const UCHAR *endbuf;
    WORD	t; /* used for partial byte tailings */

    /* handle any previously buffered bits */
    if ((c->nbuf & 0x7) != 0) {
	/* attempt to accumulate more data after partial bytes */
	return BAD_TERMINATION;
    }

    /* account for the bits */
    c->nbits += nbits;

    /* handle any previously buffered bytes */
    if (c->nbuf != 0) {
	while (c->nbuf != 0 && nbits >= 8) {
	    c->bbuf ^= (WORD)(*buf++) << (WORDSIZE - c->nbuf);
	    c->nbuf -= 8;
	    nbits -= 8;
	}
	if (c->nbuf != 0) {
	    /* not a whole word yet */
	    if (nbits != 0) {
		t = *buf & (0xFF00 >> nbits);
		c->bbuf ^= t << (WORDSIZE - c->nbuf);
		c->nbuf -= nbits;
	    }
	    return SUCCESS;
	}
	/* whole word gathered now */
	datacycle(c, c->bbuf);
    }

    /* handle whole words */
    endbuf = &buf[(nbits & ~WORDMASK) >> 3];
    while (buf < endbuf)
    {
	datacycle(c, BYTE2WORD(buf));
	buf += BPW;
    }

    /* handle any trailing bits */
    nbits &= WORDMASK;
    if (nbits != 0) {
	c->bbuf = 0;
	c->nbuf = WORDSIZE;
	while (nbits >= 8) {
	    /* buffer whole bytes */
	    c->bbuf ^= (WORD)(*buf++) << (WORDSIZE - c->nbuf);
	    c->nbuf -= 8;
	    nbits -= 8;
	}
	if (nbits != 0) {
	    /* partial byte to buffer still */
	    t = *buf & (0xFF00 >> nbits);
	    c->bbuf ^= t << (WORDSIZE - c->nbuf);
	    c->nbuf -= nbits;
	}
    }

    return SUCCESS;
}

/* ===== S T R E A M / M A C ===== */

/* Published "key" interface for stream/MAC
 */
HashReturn
ble_key(ble_ctx *c, const UCHAR key[], int keylen, int maclen)
{
    int		i;

    ble_initstate(&c->h);
    c->h.hashbitlen = maclen;
    c->s.hashbitlen = 0;
    ble_update(&c->h, key, (DataLength)keylen);
    ble_finish(&c->h); 
    ble_softreset(&c->h);
    /* save state of register */
    for (i = 0; i < N; ++i)
	c->initR[i] = c->h.R[i];
    c->neednonce = 1;
    if (maclen <= 0 || maclen > 8*WORDSIZE)
	return WARN_HASHBITLEN;
    return SUCCESS;
}

/* Published "nonce" interface
 * Set up the two sets of registers identically, but with
 * the initial register reversed for the stream cipher.
 * This leads to significantly different initial states.
 */
HashReturn
ble_nonce(ble_ctx *c, const UCHAR nonce[], int noncelen)
{
    int		i;

    for (i = 0; i < N; ++i)
	c->s.R[15 - i] = c->h.R[i] = c->initR[i];
    ble_softreset(&c->h);
    ble_softreset(&c->s);
    ble_update(&c->h, nonce, (DataLength)noncelen);
    ble_finish(&c->h); 
    ble_softreset(&c->h);
    ble_update(&c->s, nonce, (DataLength)noncelen);
    ble_finish(&c->s); 
    ble_softreset(&c->s);
    c->neednonce = 0;
    return SUCCESS;
}

/* published stream interface
 */
HashReturn
ble_stream(ble_ctx *c, UCHAR *buf, int nbits)
{
    if (c->neednonce)
	return BAD_NEEDNONCE;
    return ble_gen(&c->s, buf, nbits);
}

/* published MAC accumulation interface
 */
HashReturn
ble_macdata(ble_ctx *c, UCHAR *buf, int nbits)
{
    if (c->neednonce)
	return BAD_NEEDNONCE;
    return ble_update(&c->h, buf, (DataLength)nbits);
}

/* published encryption interface -- MAC based on ciphertext
 */
HashReturn
ble_encrypt(ble_ctx *c, UCHAR *buf, int nbits)
{
    HashReturn	ret;

    if (c->neednonce)
	return BAD_NEEDNONCE;
    if ((ret = ble_gen(&c->s, buf, nbits)) != SUCCESS)
	return ret;
    return ble_update(&c->h, buf, (DataLength)nbits);
}

/* published decryption interface -- MAC based on ciphertext
 */
HashReturn
ble_decrypt(ble_ctx *c, UCHAR *buf, int nbits)
{
    HashReturn	ret;

    if (c->neednonce)
	return BAD_NEEDNONCE;
    if ((ret = ble_update(&c->h, buf, (DataLength)nbits)) != SUCCESS)
	return ret;
    return ble_gen(&c->s, buf, nbits);
}

/* published MAC finalization interface
 */
HashReturn
ble_mac(ble_ctx *c, BitSequence *hashval)
{
    if (c->neednonce)
	return BAD_NEEDNONCE;
    ble_finish(&c->h);
    memset(hashval, 0, BYTESIN(c->h.hashbitlen));
    return ble_gen(&c->h, hashval, c->h.hashbitlen);
}

/* ====== H A S H ====== */

/* Published hash "Init" interface
 */
HashReturn
Init(hashState *c, int hashbitlen)
{
    ble_initstate(c);
    c->hashbitlen = hashbitlen;
    if (hashbitlen <= 0 || hashbitlen > 8*WORDSIZE)
	return WARN_HASHBITLEN;
    return SUCCESS;
}

/* Published hash Update interface
 */
HashReturn
Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
    return ble_update(state, data, databitlen);
}

/* Published hash Finalization interface
 */
HashReturn
Final(hashState *state, BitSequence *hashval)
{
    if (state->hashbitlen <= 0)
	return WARN_HASHBITLEN;
    ble_finish(state);
    ble_finish(state); /* not a typo, do it twice! */
    memset(hashval, 0, BYTESIN(state->hashbitlen));
    return ble_gen(state, hashval, state->hashbitlen);
}

/* Published "all in one" interface
 */
HashReturn
Hash(int hashbitlen, const BitSequence *data,
        DataLength databitlen, BitSequence *hashval)
{
    HashReturn	ret;
    hashState	s;
    HashReturn	warn = SUCCESS;

    if ((ret = Init(&s, hashbitlen)) != SUCCESS) {
	if (ret == WARN_HASHBITLEN)
	    warn = ret;
	else
	    return ret;
    }
    if ((ret = Update(&s, data, databitlen)) != SUCCESS)
	return ret;
    if ((ret = Final(&s, hashval)) != SUCCESS)
	return ret;
    return warn;
}
