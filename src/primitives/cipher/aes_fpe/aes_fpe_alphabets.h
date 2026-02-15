#ifndef AES_FPE_ALPHABETS_H
#define AES_FPE_ALPHABETS_H

/* 
   Content from micro_fpe.h 
   Renamed to avoid conflict
*/

#define ALPHABET_IS_NON_ASCII  (CUSTOM_ALPHABET >= 10)

#if ALPHABET_IS_NON_ASCII
#include <locale.h>
#include <wchar.h>
#else
#define DIGITS01  "01"
#define LLETTERS  "abcdefghijklmnopqrstuvwxyz"
#define ULETTERS  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DECIMALS  DIGITS01"23456789"
#endif

#if !CUSTOM_ALPHABET
#define ALPHABET  DECIMALS
#define RADIX     10
#elif CUSTOM_ALPHABET == 1
#define ALPHABET  LLETTERS
#define RADIX     26
#elif CUSTOM_ALPHABET == 2
#define ALPHABET  "my Alphabet"
#define RADIX     11
#elif CUSTOM_ALPHABET == 3
#define ALPHABET  DIGITS01
#define RADIX     2
#elif CUSTOM_ALPHABET == 4
#define ALPHABET  DECIMALS LLETTERS
#define RADIX     36
#elif CUSTOM_ALPHABET == 5
#define ALPHABET  ULETTERS LLETTERS DECIMALS "+/"
#define RADIX     64
#elif CUSTOM_ALPHABET == 6
#define ALPHABET  DECIMALS ULETTERS LLETTERS "!#$%&()*+-;<=>?@^_`{|}~"
#define RADIX     85
#elif CUSTOM_ALPHABET == 7
#define ALPHABET  DECIMALS ULETTERS LLETTERS "+/"
#define RADIX     64
#elif CUSTOM_ALPHABET == 8
#define ALPHABET  DECIMALS LLETTERS
#define RADIX     26
#elif CUSTOM_ALPHABET == 9
#define ALPHABET  " !\"#$%&\'()*+,-./"DECIMALS":;<=>?@"ULETTERS"[\\]^_`"LLETTERS"{|}~"
#define RADIX     95
#elif CUSTOM_ALPHABET == 10
#define ALPHABET L"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφϕχψω"
#define RADIX    50
#elif CUSTOM_ALPHABET == 20
#define ALPHABET L"ءئؤآابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"
#define RADIX    36
#endif

#include <math.h>
#ifdef  MATH_ERRNO
#define LOGRDX  log2( RADIX )
#else
#define LOGRDX  (log( RADIX ) / log( 2 ))
#endif

#define MINLEN  (1 + (int) (19.931561 / LOGRDX))

#if FF_X == 3
#define MAXLEN  (2 * (int) (96.000001 / LOGRDX))
#endif

#endif
