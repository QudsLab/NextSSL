/*
 *	Name:  SHA3_ref.h
 *
 *  Date:  10/30/08
 *
 *  Version:
 *
 *  Abstract:
 *		This file includes constants, definitions, and initialized parameters 
 *		to perform the SANDstorm Hash Algorithm
 *
 *  History:
 *
 *  Authors: Sandia National Laboratories
 *		Rich Schroeppel
 *		Tim Draelos
 *		Sean Malone
 *		Andrea Walker
 *		Nathan Dauhtenhan
 *		Mark Torgerson
 */

/* Code control flags: 0 means off, 1 means on */
#define INTERMEDIATE_VALUES 0	// Print intermediate values
#define ASM_CODE 1				// In-line assembly code

#define	MAXBITS		512		/* Maximum number of bits for one run of the compression function */
#define	MAXBYTES	64		/* Maximum number of bytes for one run of the compression function */
#define	BYTELENGTH	8
#define L1SBLENGTH	10
#define L2SBLENGTH	100

/* Value to add extra security to the algorithm: Should be a value between 0 and 20. */
/*  Default is 0 */
#define TUNABLE_SECURITY_PARAMETER	0

/* A and B constansts used in G(x) function */
#define ACONST_256 0xA611186BUL
#define BCONST_256 0xBEE8390DUL
#define ACONST_512 0xa611186bae67496bull
#define BCONST_512 0xbee8390d43955aedull

/* C and D constants for initializing levels 2 and 3 */
#define CCONST_256 0x6135F68D4C0CBB6FULL
#define DCONST_256 0x79CC45195CF5B7A4ULL

/* masks used in the bit_mix function */
#define J3 0x3333333333333333ULL
#define J5 0x5555555555555555ULL
#define J6 0x6666666666666666ULL
const u128 J3_128 = {0x3333333333333333ULL, 0x3333333333333333ULL};
const u128 J5_128 = {0x5555555555555555ULL, 0x5555555555555555ULL};
const u128 J6_128 = {0x6666666666666666ULL, 0x6666666666666666ULL};

/* mask used to select low 32 bits of a 64-bit variable, b32 = 2^32 */
#define msk32 0xFFFFFFFFul
#define b32 0x100000000ull

/* Number of bits to rotate in message schedule and in round functions */
#define MS_ROT_BITS		27	
#define BITMIX_ROT_BITS	19	
#define R_ROT_BITS		25

/* 32-bit byte swap macro */
#define ROT_RIGHT32(x,n) (((x) >> n) | ((x) << (32 - n)))
#define bswap_32(x)		((ROT_RIGHT32((x), 24) & 0x00ff00ff) | (ROT_RIGHT32((x), 8) & 0xff00ff00))

typedef unsigned long long ULL;
typedef unsigned int UI;

#if INTERMEDIATE_VALUES == 1
	ULL GLOBAL_512_L1_BNUM;
	ULL GLOBAL_512_L2_BNUM;
	ULL GLOBAL_512_L3_BNUM;
	int print_flag = 0;
#endif

static const BitSequence WORDMASK = 0xFF;
static const BitSequence ORMASK = 0x01; 

// Constants to be used in initCompress for 224 and 256 bit compressions
DataLength levelOneToFourConst[4][5][4];
DataLength mainConstantInputWords[5][4];
DataLength initialVectorTempWords[5][4];

/* As specified in the write up document for SANDstorm 256 bit hash constants*/
DataLength static const constants_256[5][4] = {
	{0x6a09e667bb67ae85ull, 0x3c6ef372a54ff53aull, 0x510e527f9b05688cull, 0x1f83d9ab5be0cd19ull},
	{0xbb67ae853c6ef372ull, 0xa54ff53a510e527full, 0x9b05688c1f83d9abull, 0x5be0cd196a09e667ull},
	{0x3c6ef372a54ff53aull, 0x510e527f9b05688cull, 0x1f83d9ab5be0cd19ull, 0x6a09e667bb67ae85ull},
	{0xa54ff53a510e527full, 0x9b05688c1f83d9abull, 0x5be0cd196a09e667ull, 0xbb67ae853c6ef372ull},
	{0x510e527f9b05688cull, 0x1f83d9ab5be0cd19ull, 0x6a09e667bb67ae85ull, 0x3c6ef372a54ff53aull}
};
/* As specified in the write up document for SANDstorm 224 bit hash constants*/
DataLength static const constants_224[5][4] = {
	{0xc1059ed8367cd507ull, 0x3070dd17f70e5939ull, 0xffc00b3168581511ull, 0x64f98fa7befa4fa4ull},
	{0x367cd5073070dd17ull, 0xf70e5939ffc00b31ull, 0x6858151164f98fa7ull, 0xbefa4fa4c1059ed8ull},
	{0x3070dd17f70e5939ull, 0xffc00b3168581511ull, 0x64f98fa7befa4fa4ull, 0xc1059ed8367cd507ull},
	{0xf70e5939ffc00b31ull, 0x6858151164f98fa7ull, 0xbefa4fa4c1059ed8ull, 0x367cd5073070dd17ull},
	{0xffc00b3168581511ull, 0x64f98fa7befa4fa4ull, 0xc1059ed8367cd507ull, 0x3070dd17f70e5939ull}
};

// constants for initializing (super)blocks at various levels
// based on the SHA-384/512 initial-value constants, which are
// derived from the fractional part (in hex) of the square roots
// of the primes 2-19 (for SHA-512) and 23-53 (for SHA-384).
u128 sandwlvlc384[20] =
{ 0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
  0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
  0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
  0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,

                         0x629a292a367cd507ull,
  0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
  0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
  0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
  0xcbbb9d5dc1059ed8ull,

  0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
  0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
  0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
  0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,

                         0x152fecd8f70e5939ull,
  0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
  0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
  0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
  0x9159015a3070dd17ull,

  0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
  0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
  0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
  0x9159015a3070dd17ull, 0x152fecd8f70e5939ull };

u128 sandwlvlc512[20] =
{ 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
  0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,

                         0xbb67ae8584caa73bull,
  0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
  0x6a09e667f3bcc908ull,

  0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
  0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,

                         0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
  0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
  0x3c6ef372fe94f82bull,

  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
  0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
  0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull };

u128 sandwblkc = { 0x6135f68d4c0cbb6full, 0xb43b47a245778989ull };
u128 sandwblkd = { 0x79cc45195cf5b7a4ull, 0xaec4e7496801dbb9ull };

/* B constants used in the message schedule and the round functions */
static const ULL B[32] = {
	0x428a2f9871374491ULL, 0xb5c0fbcfe9b5dba5ULL, 0x3956c25b59f111f1ULL, 0x923f82a4ab1c5ed5ULL,
	0xd807aa9812835b01ULL, 0x243185be550c7dc3ULL, 0x72be5d7480deb1feULL, 0x9bdc06a7c19bf174ULL,
	0xe49b69c1efbe4786ULL, 0x0fc19dc6240ca1ccULL, 0x2de92c6f4a7484aaULL, 0x5cb0a9dc76f988daULL,
	0x983e5152a831c66dULL, 0xb00327c8bf597fc7ULL, 0xc6e00bf3d5a79147ULL, 0x06ca635114292967ULL,
	0x27b70a852e1b2138ULL, 0x4d2c6dfc53380d13ULL, 0x650a7354766a0abbULL, 0x81c2c92e92722c85ULL,
	0xa2bfe8a1a81a664bULL, 0xc24b8b70c76c51a3ULL, 0xd192e819d6990624ULL, 0xf40e3585106aa070ULL,
	0x19a4c1161e376c08ULL};

// constants for message schedule & round constants
// these are a subset of the SHA2 round constants for SHA-512
// fractional part (in hex) of the cube roots of the first fifty primes
// the leading digits aren't completely random, but it's good enough
u128 sandwmsc[] = {
  0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
  0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
  0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
  0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
  0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
  0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
  0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
  0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
  0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
  0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
  0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
  0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
  0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull };

/* SB(x) = x ^ AES_sbox[x] */
static const unsigned char fsbox[256] = {
	99, 125, 117, 120, 246, 110, 105, 194, 56, 8, 109, 32, 242, 218, 165, 121,
	218, 147, 219, 110, 238, 76, 81, 231, 181, 205, 184, 180, 128, 185, 108, 223,
	151, 220, 177, 5, 18, 26, 209, 235, 28, 140, 207, 218, 93, 245, 31, 58,
	52, 246, 17, 240, 44, 163, 51, 173, 63, 43, 186, 217, 215, 26, 140, 74,
	73, 194, 110, 89, 95, 43, 28, 231, 26, 114, 156, 248, 101, 174, 97, 203,
	3, 128, 82, 190, 116, 169, 231, 12, 50, 146, 228, 98, 22, 17, 6, 144,
	176, 142, 200, 152, 39, 40, 85, 226, 45, 144, 104, 20, 60, 81, 241, 199,
	33, 210, 50, 252, 230, 232, 78, 130, 196, 207, 160, 90, 108, 130, 141, 173,
	77, 141, 145, 111, 219, 18, 194, 144, 76, 46, 244, 182, 232, 208, 151, 252,
	240, 16, 221, 79, 182, 191, 6, 31, 222, 119, 34, 143, 66, 195, 149, 68,
	64, 147, 152, 169, 237, 163, 130, 251, 106, 122, 6, 201, 61, 56, 74, 214,
	87, 121, 133, 222, 57, 96, 248, 30, 212, 239, 78, 81, 217, 199, 16, 183,
	122, 185, 231, 237, 216, 99, 114, 1, 32, 20, 190, 212, 135, 112, 69, 69,
	160, 239, 103, 181, 156, 214, 32, 217, 185, 236, 141, 98, 90, 28, 195, 65,
	1, 25, 122, 242, 141, 60, 104, 115, 115, 247, 109, 2, 34, 184, 198, 48,
	124, 80, 123, 254, 75, 19, 180, 159, 185, 96, 215, 244, 76, 169, 69, 233};

/*===== Global variables used in ModMix =====*/
ULL MSd[33];	/* message schedule buffer*/
ULL ws[4];		/* hash state buffer */

void createMessageFromQueue(DataLength m[8], hashState *state);
void swapMessage(DataLength m[8]);
void createMessageFromBlock(DataLength M[8], DataLength input[5][4]);
void Do_Block_ModMix_Ref (ULL db[8], ULL block_buffer[5][4]);
void compress(hashState *state);
void initCompress(hashState *state);
void printPrevBlock(DataLength input[5][4], int level);
void print64BS(BitSequence bstmp[64], int id);
void printQueue(hashState *state, int id);
void printMessage(DataLength Mess[8]);
ULL F(ULL x);
ULL G(ULL x);
ULL Ch(ULL a, ULL b, ULL c);
ULL RotLeft(ULL n, int i);
ULL Rot32(ULL n);
ULL SB(ULL x);
ULL C(int i);
int mm(int i);
ULL Msg_M(int i);
void bit_mix();
void round_in(ULL buffer[4], int);
void round_out(ULL prev_block[4], ULL current_block[4]);
void round4_out(ULL current_block[4]);
void do_round(int round_num);
void block_init();
u128 k128(u64 hi, u64 lo);
u128 a128(u128 x, u128 y);
u128 x128(u128 x, u128 y);
u128 c128(u128 x);
u128 b128(u128 x, u128 y);
u128 r128(u128 x, int sh);
u128 m128(u64 x, u64 y);
u128 s128(u64 x);
u128 sandwf(u128 x);
u128 sandwg(u128 x);
u128 sb128(u128 x);
void mscpr(u128 *ms);
void sandwmsgsch(u128 *MS);
void sandwcmprs(u128 msg[], u128 prev[], int level, int xrnds);
void hstpr(hashState *hst);
void sandwdoit(hashState *hstate);
void sandwinit(hashState *hstate, int hashsize);
void sandwupdate(hashState *hstate, u64 bitsofdata, const unsigned char *data);
void sandwfinish(hashState *hstate);
void sandwprint(hashState *hstate);

