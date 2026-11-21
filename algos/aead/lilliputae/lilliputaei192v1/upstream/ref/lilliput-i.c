/*
Implementation of the Lilliput-AE tweakable block cipher.

Authors, hereby denoted as "the implementer":
    Kévin Le Gouguec,
    2019.

For more information, feedback or questions, refer to our website:
https://paclido.fr/lilliput-ae

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file implements Lilliput-AE's nonce-respecting mode based on ΘCB3.
*/

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "lilliput-ae.h"
#include "lilliput-ae-utils.h"


static const uint8_t _0n[BLOCK_BYTES] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


static void _fill_msg_tweak(
    uint8_t       prefix,
    const uint8_t N[NONCE_BYTES],
    uint64_t      block_nb,
    uint8_t       tweak[TWEAK_BYTES]
)
{
    /* The 192-bit tweak is filled as follows:
     *
     * - bits   1- 68: block number
     *          1- 64: actual 64-bit block number
     *         64- 68: 0-padding
     * - bits  67-188: nonce
     * - bits 189-192: constant 4-bit prefix
     */

    for (size_t i=0; i<sizeof(block_nb); i++)
    {
        uint64_t mask = (uint64_t)0xff << 8*i;
        uint8_t b = (mask & block_nb) >> 8*i;

        tweak[i] = b;
    }

    tweak[sizeof(block_nb)] = lower_nibble(N[0]) << 4;

    for (size_t i=1; i<NONCE_BYTES; i++)
    {
        tweak[sizeof(block_nb)+i] = lower_nibble(N[i]) << 4 ^ upper_nibble(N[i-1]);
    }

    tweak[TWEAK_BYTES-1] = prefix << 4 ^ upper_nibble(N[NONCE_BYTES-1]);
}

static void _encrypt_message(
    const uint8_t key[KEY_BYTES],
    size_t        M_len,
    const uint8_t M[M_len],
    const uint8_t N[NONCE_BYTES],
    uint8_t       C[M_len+BLOCK_BYTES],
    uint8_t       Final[BLOCK_BYTES]
)
{
    size_t l = M_len / BLOCK_BYTES;
    size_t rest = M_len % BLOCK_BYTES;

    uint8_t tweak[TWEAK_BYTES];
    uint8_t checksum[BLOCK_BYTES];

    memset(tweak, 0, TWEAK_BYTES);
    memset(checksum, 0, BLOCK_BYTES);

    for (size_t j=0; j<l; j++)
    {
        xor_into(checksum, &M[j*BLOCK_BYTES]);
        _fill_msg_tweak(0x0, N, j, tweak);
        encrypt(key, tweak, &M[j*BLOCK_BYTES], &C[j*BLOCK_BYTES]);
    }

    if (rest == 0)
    {
        _fill_msg_tweak(0x1, N, l, tweak);
        encrypt(key, tweak, checksum, Final);
    }
    else
    {
        uint8_t M_rest[BLOCK_BYTES];
        uint8_t Pad[BLOCK_BYTES];

        pad10(rest, &M[l*BLOCK_BYTES], M_rest);
        xor_into(checksum, M_rest);

        _fill_msg_tweak(0x4, N, l, tweak);
        encrypt(key, tweak, _0n, Pad);
        xor_arrays(rest, &C[l*BLOCK_BYTES], &M[l*BLOCK_BYTES], Pad);

        _fill_msg_tweak(0x5, N, l+1, tweak);
        encrypt(key, tweak, checksum, Final);
    }
}

static void _decrypt_message(
    const uint8_t key[KEY_BYTES],
    size_t        C_len,
    const uint8_t C[C_len],
    const uint8_t N[NONCE_BYTES],
    uint8_t       M[C_len],
    uint8_t       Final[BLOCK_BYTES]
)
{
    size_t l = C_len / BLOCK_BYTES;
    size_t rest = C_len % BLOCK_BYTES;

    uint8_t tweak[TWEAK_BYTES];
    uint8_t checksum[BLOCK_BYTES];

    memset(tweak, 0, TWEAK_BYTES);
    memset(checksum, 0, BLOCK_BYTES);

    for (size_t j=0; j<l; j++)
    {
        _fill_msg_tweak(0x0, N, j, tweak);
        decrypt(key, tweak, &C[j*BLOCK_BYTES], &M[j*BLOCK_BYTES]);
        xor_into(checksum, &M[j*BLOCK_BYTES]);
    }

    if (rest == 0)
    {
        _fill_msg_tweak(0x1, N, l, tweak);
        encrypt(key, tweak, checksum, Final);
    }
    else
    {
        uint8_t M_rest[BLOCK_BYTES];
        uint8_t Pad[BLOCK_BYTES];

        _fill_msg_tweak(0x4, N, l, tweak);
        encrypt(key, tweak, _0n, Pad);
        xor_arrays(rest, &M[l*BLOCK_BYTES], &C[l*BLOCK_BYTES], Pad);

        pad10(rest, &M[l*BLOCK_BYTES], M_rest);
        xor_into(checksum, M_rest);

        _fill_msg_tweak(0x5, N, l+1, tweak);
        encrypt(key, tweak, checksum, Final);
    }
}

static void _generate_tag(
    const uint8_t Final[BLOCK_BYTES],
    const uint8_t Auth[BLOCK_BYTES],
    uint8_t       tag[TAG_BYTES]
)
{
    xor_arrays(TAG_BYTES, tag, Final, Auth);
}


void lilliput_ae_encrypt(
    size_t        message_len,
    const uint8_t message[message_len],
    size_t        auth_data_len,
    const uint8_t auth_data[auth_data_len],
    const uint8_t key[KEY_BYTES],
    const uint8_t nonce[NONCE_BYTES],
    uint8_t       ciphertext[message_len],
    uint8_t       tag[TAG_BYTES]
)
{
    uint8_t auth[BLOCK_BYTES];
    process_associated_data(key, auth_data_len, auth_data, auth);

    uint8_t final[BLOCK_BYTES];
    _encrypt_message(key, message_len, message, nonce, ciphertext, final);

    _generate_tag(final, auth, tag);
}

bool lilliput_ae_decrypt(
    size_t        ciphertext_len,
    const uint8_t ciphertext[ciphertext_len],
    size_t        auth_data_len,
    const uint8_t auth_data[auth_data_len],
    const uint8_t key[KEY_BYTES],
    const uint8_t nonce[NONCE_BYTES],
    const uint8_t tag[TAG_BYTES],
    uint8_t       message[ciphertext_len]
)
{
    uint8_t auth[BLOCK_BYTES];
    process_associated_data(key, auth_data_len, auth_data, auth);

    uint8_t final[BLOCK_BYTES];
    _decrypt_message(key, ciphertext_len, ciphertext, nonce, message, final);

    uint8_t effective_tag[TAG_BYTES];
    _generate_tag(final, auth, effective_tag);

    return memcmp(tag, effective_tag, TAG_BYTES) == 0;
}
