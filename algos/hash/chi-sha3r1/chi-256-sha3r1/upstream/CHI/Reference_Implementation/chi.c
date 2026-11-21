/* chi.c: CHI hash main implementation */

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
#include <string.h>
#include <stdio.h>

#include "chi.h"

/*
 * Regardless of endian-ness converts a byte to / from a big endian array of
 * bytes.
 */
#define BYTE2WORD(b) (                          \
          (((WORD64)(b)[0] & 0xFF) << 56)       \
        | (((WORD64)(b)[1] & 0xFF) << 48)       \
        | (((WORD64)(b)[2] & 0xFF) << 40)       \
        | (((WORD64)(b)[3] & 0xFF) << 32)       \
        | (((WORD64)(b)[4] & 0xFF) << 24)       \
        | (((WORD64)(b)[5] & 0xFF) << 16)       \
        | (((WORD64)(b)[6] & 0xFF) << 8)        \
        | (((WORD64)(b)[7] & 0xFF))             \
    )

/*
 * Rotate WORD32 to the right by r
 */
static INLINE WORD32
rotr32
(
    WORD32  X,
    int     r
)
{
    return (X >> r) | (X << (32 - r));
}

/*
 * Rotate WORD64 to the right by r
 */
INLINE WORD64
rotr64
(
    WORD64  X,
    int     r
)
{
    return (X >> r) | (X << (64 - r));
}

/*
 * Rotate Upper and Lower 32 bits of WORD64 to
 * the right by r1 and r2 respectively.
 */
INLINE WORD64
drotr32
(
    WORD64  X,
    int     r1,
    int     r2
)
{
    return (WORD64)rotr32((WORD32)(X >> 32), r1) << 32 | rotr32((WORD32)X, r2);
}

/*
 * Byte swap
 */
INLINE WORD64
swap8
(
    WORD64 X
)
{
    X = (X & 0xFFFFFFFF00000000ULL) >> 32 | (X & 0x00000000FFFFFFFFULL) << 32;
    X = (X & 0xFFFF0000FFFF0000ULL) >> 16 | (X & 0x0000FFFF0000FFFFULL) << 16;
    X = (X & 0xFF00FF00FF00FF00ULL) >>  8 | (X & 0x00FF00FF00FF00FFULL) <<  8;

    return X;
}

/*
 * Swap the Upper and Lower 32 bits of WORD64
 */
INLINE WORD64
swap32
(
    WORD64 X
)
{
    return rotr64(X, 32);
}

static INLINE WORD64
map0
(
    WORD64  R,
    WORD64  S,
    WORD64  T,
    WORD64  U
)
{
    return    ( R & ~S &  T &  U)
            | (     ~S & ~T & ~U)
            | (~R      & ~T &  U)
            | (~R &  S &  T     )
            | ( R      & ~T & ~U);
}

static INLINE WORD64
map1
(
    WORD64  R,
    WORD64  S,
    WORD64  T,
    WORD64  U
)
{
    return    ( R &  S &  T & ~U)
            | ( R & ~S & ~T & ~U)
            | (~R & ~S &  T     )
            | (      S & ~T &  U)
            | (~R           &  U);
}

static INLINE WORD64
map2
(
    WORD64  R,
    WORD64  S,
    WORD64  T,
    WORD64  U
)
{
    return    (~R & ~S &  T &  U)
            | (~R &  S &  T & ~U)
            | (      S & ~T &  U)
            | ( R      & ~T & ~U)
            | ( R &  S      &  U)
            | ( R & ~S      & ~U);
}

/*
 * Non-linear MAP function.
 */
static INLINE void
map
(
    WORD64  R,
    WORD64  S,
    WORD64  T,
    WORD64  U,
    WORD64  *X,
    WORD64  *Y,
    WORD64  *Z,
    int     i
)
{
    WORD64  M[3];

    M[0] = map0(R, S, T, U);
    M[1] = map1(R, S, T, U);
    M[2] = map2(R, S, T, U);

    *X = M[(i + 0) % 3];
    *Y = M[(i + 1) % 3];
    *Z = M[(i + 2) % 3];
}

/*
 * CHI-256
 */
#define _256_MAP map

INLINE WORD64
_256_theta0
(
    WORD64  X
)
{
    return drotr32(X, 21, 21) ^ drotr32(X, 26, 26) ^ drotr32(X, 30, 30);
}

INLINE WORD64
_256_theta1
(
    WORD64  X
)
{
    return drotr32(X, 14, 14) ^ drotr32(X, 24, 24) ^ drotr32(X, 31, 31);
}

static INLINE WORD64
_256_mu0
(
    WORD64  X
)
{
    return rotr64(X, 36) ^ rotr64(X, 18) ^ (X >> 1);
}

static INLINE WORD64
_256_mu1
(
    WORD64  X
)
{
    return rotr64(X, 59) ^ rotr64(X, 37) ^ (X >> 10);
}

void
_256_message_expansion
(
    WORD64  *W
)
{
    int     i;

    for (i = 8; i < 2 * _256_STEPS; ++i)
        W[i] = W[i - 8] ^ _256_mu0(W[i - 7]) ^ _256_mu1(W[i - 2]);
}

static INLINE void
_256_premix
(
    WORD64  A,
    WORD64  B,
    WORD64  D,
    WORD64  E,
    WORD64  *preR,
    WORD64  *preS,
    WORD64  *preT,
    WORD64  *preU
)
{
    *preR = drotr32(B, 8, 8)          ^ drotr32(swap32(D),  5,  1);
    *preS = A                         ^ drotr32(swap32(D), 18, 17);
    *preT = drotr32(swap32(A), 7, 26) ^ drotr32(D, 14, 22);
    *preU = drotr32(A, 17, 12)        ^ drotr32(swap32(E),  2, 23);
}

static INLINE void
_256_datainput
(
    WORD64  preR,
    WORD64  preS,
    WORD64  preT,
    WORD64  preU,
    WORD64  V0,
    WORD64  V1,
    WORD64  *R,
    WORD64  *S,
    WORD64  *T,
    WORD64  *U
)
{
    *R = preR ^ V0;
    *S = preS ^ V1;
    *T = preT ^ _256_theta0(V0);
    *U = preU ^ _256_theta1(V1);
}

static INLINE void
_256_postmix
(
    WORD64  X,
    WORD64  Y,
    WORD64  Z,
    WORD64  *XX,
    WORD64  *YY,
    WORD64  *ZZ,
    WORD64  *AA,
    WORD64  *DD
)
{
    *XX = X;
    *YY = swap8(drotr32(Y, 5, 5));
    *ZZ = swap32(Z);
    *AA = rotr64(*XX + *YY, 16);
    *DD = rotr64(*YY + *ZZ, 48);
}

/*
 * 256 bit update routine.  Called from hash().
 *
 * Parameters:
 *      state   The hash state.
 *      final   1 for the final block in the hash, 0 for intermediate blocks.
 */
void
_256_update
(
    hashState   *state,
    int         final
)
{
    int         i;

    WORD64      W[2*_256_STEPS];
    WORD64      A, B, C, D, E, F;
    WORD64      preR, preS, preT, preU;
    WORD64      V0, V1;
    WORD64      R, S, T, U;
    WORD64      X, Y, Z, XX, YY, ZZ;
    WORD64      AA, DD, newA, newD;

    A = state->hs_State.small[0];
    B = state->hs_State.small[1];
    C = state->hs_State.small[2];
    D = state->hs_State.small[3];
    E = state->hs_State.small[4];
    F = state->hs_State.small[5];

    if (final)
    {
        A = rotr64(A, 1);
        B = rotr64(B, 1);
        C = rotr64(C, 1);
        D = rotr64(D, 1);
        E = rotr64(E, 1);
        F = rotr64(F, 1);
    }

    for (i = 0; i < _256_MSG_N; ++i)
        W[i] = BYTE2WORD(state->hs_DataBuffer + 8 * i);
    _256_message_expansion(W);

    for (i = 0; i < _256_STEPS; ++i)
    {
        _256_premix(A, B, D, E, &preR, &preS, &preT, &preU);
        V0 = W[2*i  ] ^ K[2*i  ];
        V1 = W[2*i+1] ^ K[2*i+1];
        _256_datainput(preR, preS, preT, preU, V0, V1, &R, &S, &T, &U);
        _256_MAP(R, S, T, U, &X, &Y, &Z, i);
        _256_postmix(X, Y, Z, &XX, &YY, &ZZ, &AA, &DD);

        newA = AA ^ F;
        newD = DD ^ C;
        
        /*
         * Shift
         */
        F = E; E = D; D = newD;
        C = B; B = A; A = newA;
    }

    state->hs_State.small[0] = rotr64(state->hs_State.small[0], 1) ^ A;
    state->hs_State.small[1] = rotr64(state->hs_State.small[1], 1) ^ B;
    state->hs_State.small[2] = rotr64(state->hs_State.small[2], 1) ^ C;
    state->hs_State.small[3] = rotr64(state->hs_State.small[3], 1) ^ D;
    state->hs_State.small[4] = rotr64(state->hs_State.small[4], 1) ^ E;
    state->hs_State.small[5] = rotr64(state->hs_State.small[5], 1) ^ F;
}


/*
 * CHI-512
 */
#define _512_MAP map

INLINE WORD64
_512_theta0
(
    WORD64  X
)
{
    return rotr64(X,  5) ^ rotr64(X,  6) ^ rotr64(X, 43);
}

INLINE WORD64
_512_theta1
(
    WORD64  X
)
{
    return rotr64(X, 20) ^ rotr64(X, 30) ^ rotr64(X, 49);
}

static INLINE WORD64
_512_mu0
(
    WORD64  X
)
{
    return rotr64(X, 36) ^ rotr64(X, 18) ^ (X >> 1);
}

static INLINE WORD64
_512_mu1
(
    WORD64  X
)
{
    return rotr64(X, 60) ^ rotr64(X, 30) ^ (X >> 3);
}

void
_512_message_expansion
(
    WORD64  *W
)
{
    int     i;

    for (i = 16; i < 2 * _512_STEPS; ++i)
    {
        W[i] = W[i - 16]
             ^ W[i -  7]
             ^ _512_mu0(W[i - 15])
             ^ _512_mu1(W[i - 2]);
    }
}

static INLINE void
_512_premix
(
    WORD64 A,
    WORD64 B,
    WORD64 D,
    WORD64 E,
    WORD64 G,
    WORD64 P,
    WORD64 *preR,
    WORD64 *preS,
    WORD64 *preT,
    WORD64 *preU
)
{
    *preR = rotr64(B, 11) ^ rotr64(D,  8) ^ rotr64(G, 13);
    *preS = A             ^ rotr64(D, 21) ^ rotr64(G, 29);
    *preT = rotr64(A, 11) ^ rotr64(D, 38) ^ P;
    *preU = rotr64(A, 26) ^ rotr64(E, 40) ^ rotr64(G, 50);
}

static INLINE void
_512_datainput
(
    WORD64 preR,
    WORD64 preS,
    WORD64 preT,
    WORD64 preU,
    WORD64 V0,
    WORD64 V1,
    WORD64 *R,
    WORD64 *S,
    WORD64 *T,
    WORD64 *U
)
{
    *R = preR ^ V0;
    *S = preS ^ V1;
    *T = preT ^ _512_theta0(V0);
    *U = preU ^ _512_theta1(V1);
}

static INLINE void
_512_postmix
(
    WORD64 X,
    WORD64 Y,
    WORD64 Z,
    WORD64 *XX,
    WORD64 *YY,
    WORD64 *ZZ,
    WORD64 *AA,
    WORD64 *DD,
    WORD64 *GG
)
{
    WORD64 temp;

    *XX = X;
    *YY = swap8(rotr64(Y, 31));
    *ZZ = swap32(Z);

    temp = *XX + *YY;
    *AA = rotr64(temp, 16);

    temp = *YY + *ZZ;
    *DD = rotr64(temp, 48);

    temp = *ZZ + (*XX << 1);
    *GG = temp;
}

/*
 * 512 bit update routine.  Called from hash().
 *
 * Parameters:
 *      state   The hash state.
 *      final   1 for the final block in the hash, 0 for intermediate blocks.
 */
void
_512_update
(
    hashState   *state,
    int         final
)
{
    int         i;

    WORD64      W[2*_512_STEPS];
    WORD64      A, B, C, D, E, F, G, P, Q;
    WORD64      preR, preS, preT, preU;
    WORD64      V0, V1;
    WORD64      R, S, T, U;
    WORD64      X, Y, Z, XX, YY, ZZ;
    WORD64      AA, DD, GG, newA, newD, newG;

    A = state->hs_State.large[0];
    B = state->hs_State.large[1];
    C = state->hs_State.large[2];
    D = state->hs_State.large[3];
    E = state->hs_State.large[4];
    F = state->hs_State.large[5];
    G = state->hs_State.large[6];
    P = state->hs_State.large[7];
    Q = state->hs_State.large[8];

    if (final)
    {
        A = rotr64(A, 1);
        B = rotr64(B, 1);
        C = rotr64(C, 1);
        D = rotr64(D, 1);
        E = rotr64(E, 1);
        F = rotr64(F, 1);
        G = rotr64(G, 1);
        P = rotr64(P, 1);
        Q = rotr64(Q, 1);
    }

    for (i = 0; i < _512_MSG_N; ++i)
        W[i] = BYTE2WORD(state->hs_DataBuffer + 8*i);
    _512_message_expansion(W);

    for (i = 0; i < _512_STEPS; ++i)
    {
        _512_premix(A, B, D, E, G, P, &preR, &preS, &preT, &preU);
        V0 = W[2*i  ] ^ K[2*i  ];
        V1 = W[2*i+1] ^ K[2*i+1];
        _512_datainput(preR, preS, preT, preU, V0, V1, &R, &S, &T, &U);
        _512_MAP(R, S, T, U, &X, &Y, &Z, i);
        _512_postmix(X, Y, Z, &XX, &YY, &ZZ, &AA, &DD, &GG);

        newA = AA ^ Q;
        newD = DD ^ C;
        newG = GG ^ F;
        
        /*
         * Shift
         */
        Q = P; P = G; G = newG;
        F = E; E = D; D = newD;
        C = B; B = A; A = newA;
    }

    state->hs_State.large[0] = rotr64(state->hs_State.large[0], 1) ^ A;
    state->hs_State.large[1] = rotr64(state->hs_State.large[1], 1) ^ B;
    state->hs_State.large[2] = rotr64(state->hs_State.large[2], 1) ^ C;
    state->hs_State.large[3] = rotr64(state->hs_State.large[3], 1) ^ D;
    state->hs_State.large[4] = rotr64(state->hs_State.large[4], 1) ^ E;
    state->hs_State.large[5] = rotr64(state->hs_State.large[5], 1) ^ F;
    state->hs_State.large[6] = rotr64(state->hs_State.large[6], 1) ^ G;
    state->hs_State.large[7] = rotr64(state->hs_State.large[7], 1) ^ P;
    state->hs_State.large[8] = rotr64(state->hs_State.large[8], 1) ^ Q;
}
