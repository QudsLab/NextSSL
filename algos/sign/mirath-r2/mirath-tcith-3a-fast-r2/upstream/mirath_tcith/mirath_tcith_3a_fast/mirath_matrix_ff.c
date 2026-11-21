
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "mirath_matrix_ff.h"
#include "mirath_parsing.h"

void mirath_matrix_init_zero(ff_t *matrix, const uint32_t n_rows, const uint32_t n_cols) {
    memset(matrix, 0, mirath_matrix_ff_bytes_size(n_rows, n_cols));
}

//
void mirath_matrix_ff_init_random(ff_t *matrix, const uint32_t n_rows, const uint32_t n_cols, mirath_prng_t *prng) {
    const uint32_t matrix_bytes = mirath_matrix_ff_bytes_size(n_rows, n_cols);
    mirath_prng(prng, matrix, matrix_bytes);

    mirath_matrix_set_to_ff(matrix, n_rows, n_cols);
}

void mirath_matrix_expand_seed_public_matrix(ff_t H[MIRATH_VAR_FF_H_BYTES], const seed_t seed_pk) {
    mirath_prng_t prng;
    mirath_prng_init(&prng, NULL, seed_pk, MIRATH_SECURITY_BYTES);
    mirath_matrix_ff_init_random(H, MIRATH_PARAM_M * MIRATH_PARAM_N - MIRATH_PARAM_K, MIRATH_PARAM_K, &prng);
}

void mirath_matrix_expand_seed_secret_matrix(ff_t S[MIRATH_VAR_FF_S_BYTES], ff_t C[MIRATH_VAR_FF_C_BYTES], const seed_t seed_sk){
    mirath_prng_t prng;
    mirath_prng_init(&prng, NULL, seed_sk, MIRATH_SECURITY_BYTES);
    mirath_matrix_ff_init_random(S, MIRATH_PARAM_M, MIRATH_PARAM_R, &prng);
    mirath_matrix_ff_init_random(C, MIRATH_PARAM_R, MIRATH_PARAM_N - MIRATH_PARAM_R, &prng);
    // // Todo: use pointers in the optimized version
    // mirath_prng_init(&prng, NULL, seed_sk, MIRATH_SECURITY_BYTES);
    // ff_t T[MIRATH_VAR_FF_S_BYTES + MIRATH_VAR_FF_C_BYTES];
    // mirath_prng(&prng, T, MIRATH_VAR_FF_S_BYTES + MIRATH_VAR_FF_C_BYTES);
    // memcpy(S, T, MIRATH_VAR_FF_S_BYTES);
    // memcpy(C, T + MIRATH_VAR_FF_S_BYTES, MIRATH_VAR_FF_C_BYTES);
    //
    // mirath_matrix_set_to_ff(S, MIRATH_PARAM_M, MIRATH_PARAM_R);
    // mirath_matrix_set_to_ff(C, MIRATH_PARAM_R, MIRATH_PARAM_N - MIRATH_PARAM_R);

}

void mirath_matrix_compute_y(ff_t y[MIRATH_VAR_FF_Y_BYTES],
                                    const ff_t S[MIRATH_VAR_FF_S_BYTES],
                                    const ff_t C[MIRATH_VAR_FF_C_BYTES],
                                    const ff_t H[MIRATH_VAR_FF_H_BYTES]) {

    ff_t e_A[MIRATH_VAR_FF_Y_BYTES] = {0};
    ff_t e_B[mirath_matrix_ff_bytes_size(MIRATH_PARAM_K, 1)] = {0};

    ff_t T[MIRATH_VAR_FF_T_BYTES] = {0};
    ff_t E[MIRATH_VAR_FF_E_BYTES] = {0};

    mirath_matrix_ff_product(T, S, C, MIRATH_PARAM_M, MIRATH_PARAM_R, MIRATH_PARAM_N - MIRATH_PARAM_R);
    mirath_matrix_ff_horizontal_concat(E, S, T, MIRATH_PARAM_M, MIRATH_PARAM_R, MIRATH_PARAM_N - MIRATH_PARAM_R);

    const uint32_t bytes_e_B = mirath_matrix_ff_bytes_size(MIRATH_PARAM_K, 1);

    memcpy(e_A, E, MIRATH_VAR_FF_Y_BYTES);
#if (OFF_E_A > 0)
    const uint8_t mask = (1 << (8 - OFF_E_A)) - 1;
    e_A[MIRATH_VAR_FF_Y_BYTES - 1] &= mask;

    for (uint32_t i = 0; i < bytes_e_B - 1 ; i++) {
        e_B[i] = ((E[MIRATH_VAR_FF_Y_BYTES - 1 + i]) >> (8 - OFF_E_A));
        e_B[i] ^= ((E[MIRATH_VAR_FF_Y_BYTES + i]) << (OFF_E_A));
    }
#if ((OFF_E_A + OFF_E_B) >= 8)
    e_B[bytes_e_B - 1] = ((E[MIRATH_VAR_FF_E_BYTES - 1]) >> (8 - OFF_E_A));
#else
    e_B[bytes_e_B - 1] = (E[MIRATH_VAR_FF_E_BYTES - 2] >> (8 - OFF_E_A));
    e_B[bytes_e_B - 1] ^= (E[MIRATH_VAR_FF_E_BYTES - 1] << OFF_E_A);
#endif
#else
    memcpy(e_B, E + MIRATH_VAR_FF_Y_BYTES, bytes_e_B);
#endif

    memset(y, 0, MIRATH_VAR_FF_Y_BYTES);
    mirath_matrix_ff_product(y, H, e_B, MIRATH_PARAM_M * MIRATH_PARAM_N - MIRATH_PARAM_K, MIRATH_PARAM_K, 1);

    mirath_vec_ff_add_arith(y, y, e_A, MIRATH_VAR_FF_Y_BYTES);
}

//Todo: remove the function below when it is possible
void mirath_tciht_compute_public_key(uint8_t *pk, const uint8_t *sk,
                                     const ff_t S[MIRATH_VAR_FF_S_BYTES],
                                     const ff_t C[MIRATH_VAR_FF_C_BYTES],
                                     const ff_t H[MIRATH_VAR_FF_H_BYTES]) {

    ff_t y[MIRATH_VAR_FF_Y_BYTES];

    mirath_matrix_compute_y(y, S, C, H);

    unparse_public_key(pk, sk + MIRATH_SECURITY_BYTES, y);
}

void mirath_matrix_decompress_secret_key(ff_t S[MIRATH_VAR_FF_S_BYTES],
                      ff_t C[MIRATH_VAR_FF_C_BYTES],
                      ff_t H[MIRATH_VAR_FF_H_BYTES],
                      uint8_t *pk,
                      const uint8_t *sk) {
    seed_t seed_sk;
    seed_t seed_pk;
    ff_t y[MIRATH_VAR_FF_Y_BYTES];

    parse_secret_key(seed_sk, seed_pk, sk);
    mirath_matrix_expand_seed_public_matrix(H, seed_pk);
    mirath_matrix_expand_seed_secret_matrix(S, C,seed_sk);
    mirath_matrix_compute_y(y, S, C, H);
    unparse_public_key(pk, seed_pk, y);
}

void mirath_matrix_decompress_pk(ff_t H[MIRATH_VAR_FF_H_BYTES], ff_t y[MIRATH_VAR_FF_Y_BYTES], const uint8_t *pk) {
    mirath_prng_t prng;
    seed_t seed_pk;
    parse_public_key(seed_pk, y, pk);
    mirath_prng_init(&prng, NULL, seed_pk, MIRATH_SECURITY_BYTES);
    mirath_matrix_ff_init_random(H, MIRATH_PARAM_M * MIRATH_PARAM_N - MIRATH_PARAM_K, MIRATH_PARAM_K, &prng);

}

void mirath_matrix_ff_copy(ff_t *matrix1, const ff_t *matrix2, const uint32_t n_rows, const uint32_t n_cols) {
    const uint32_t n_bytes = mirath_matrix_ff_bytes_size(n_rows, n_cols);
    memcpy(matrix1, matrix2, n_bytes);
}

void mirath_matrix_ff_neg(ff_t *matrix, const uint32_t n_rows, const uint32_t n_cols) {
    /* Nothing to do in characteristic 2. */

    /* Suppress 'unused parameter' warnings. */
    (void)(matrix); (void)(n_rows); (void)(n_cols);
}

void mirath_matrix_ff_add(ff_t *matrix1, const ff_t *matrix2, const ff_t *matrix3, uint32_t n_rows, uint32_t n_cols){
    mirath_matrix_ff_add_arith(matrix1, matrix2, matrix3, n_rows, n_cols);
}

void mirath_matrix_ff_add_multiple(ff_t *matrix1, ff_t scalar, const ff_t *matrix2,
    const uint32_t n_rows, const uint32_t n_cols) {
    mirath_matrix_ff_add_multiple_arith(matrix1, scalar, matrix2, n_rows, n_cols);
}

void mirath_matrix_ff_sub(ff_t *matrix1, const ff_t *matrix2, const ff_t *matrix3, uint32_t n_rows, uint32_t n_cols){
    mirath_matrix_ff_add_arith(matrix1, matrix2, matrix3, n_rows, n_cols);
}

void mirath_matrix_ff_sub_multiple(ff_t *matrix1, ff_t scalar, const ff_t *matrix2,
    const uint32_t n_rows, const uint32_t n_cols) {
    mirath_matrix_ff_add_multiple(matrix1, scalar, matrix2, n_rows, n_cols);
}

void mirath_matrix_ff_product(ff_t *result, const ff_t *matrix1, const ff_t *matrix2,
    const uint32_t n_rows1, const uint32_t n_cols1, const uint32_t n_cols2) {
    mirath_matrix_ff_product_arith(result, matrix1, matrix2, n_rows1, n_cols1, n_cols2);
}

void mirath_matrix_ff_horizontal_concat(ff_t *result, const ff_t *matrix1, const ff_t *matrix2,
                                        const uint32_t n_rows, const uint32_t n_cols1, const uint32_t n_cols2) {
    uint8_t *ptr;
    ptr = (uint8_t *)result;
    uint32_t off_ptr = 8;

    uint32_t n_rows_bytes = mirath_matrix_ff_bytes_size(n_rows, 1);
    const uint32_t on_col = 8 - ((8 * n_rows_bytes) - (4 * n_rows));

    uint8_t *col;

    col = (uint8_t *)matrix1;
    for (uint32_t j = 0; j < n_cols1; j++) {
        *ptr |= (*col << (8 - off_ptr));

        for (uint32_t i = 0; i < n_rows_bytes-1; i++) {
            ptr += 1;
            *ptr = (*col >> off_ptr);
            col += 1;
            *ptr |= (*col << (8 - off_ptr));
        }

        if (off_ptr <= on_col) {
            ptr += 1;
            *ptr = (*col >> off_ptr);
        }
        col += 1;
        off_ptr = 8 - ((on_col - off_ptr) % 8);
    }

    col = (uint8_t *)matrix2;
    for (uint32_t j = 0; j < n_cols2; j++) {
        *ptr |= (*col << (8 - off_ptr));

        for (uint32_t i = 0; i < n_rows_bytes-1; i++) {
            ptr += 1;
            *ptr = (*col >> off_ptr);
            col += 1;
            *ptr |= (*col << (8 - off_ptr));
        }

        if (off_ptr <= on_col) {
            ptr += 1;
            if (off_ptr < on_col) {
                *ptr = (*col >> off_ptr);
            }
        }
        col += 1;
        off_ptr = 8 - ((on_col - off_ptr) % 8);
    }
}

void mirath_matrix_ff_horizontal_split(ff_t *matrix1, ff_t *matrix2, const ff_t *matrix,
    const uint32_t n_rows, const uint32_t n_cols1, const uint32_t n_cols2) {
    const uint32_t n_bytes1 = mirath_matrix_ff_bytes_size(n_rows, n_cols1);
    const uint32_t n_bytes2 = mirath_matrix_ff_bytes_size(n_rows, n_cols2);

    if (matrix1 != NULL) {
        memcpy(matrix1, matrix, n_bytes1);
        memcpy(matrix2, matrix + n_bytes1, n_bytes2);
    }
    else {
        memcpy(matrix2, matrix + n_bytes1, n_bytes2);
    }
}

void _matrix_pack_nrows_even(uint8_t **dest, const uint32_t *bit_offset, const ff_t *matrix,
                             const uint32_t n_rows, const int n_cols) {

    /* the packing is done row-wise */
    uint32_t bo, n_bytes;

    if (bit_offset != NULL)
    {
        bo = *bit_offset;
    }
    else
    {
        bo = 0;
    }

    n_bytes = mirath_matrix_ff_bytes_size(n_rows, n_cols);

    if (bo)
    {
        /* Pack last entry of matrix (in column-major order) in the higher bits of dest[0]. */
        ((uint8_t *)*dest)[0] |= matrix[n_bytes - 1] & 0xf0;

        /* Pack all the bytes in matrix except the last one */
        memcpy(&(((uint8_t *)*dest)[1]), matrix, n_bytes - 1);

        /* Pack the second-to-last entry of matrix. */
        ((uint8_t *)*dest)[n_bytes] = matrix[n_bytes - 1] & 0x0f;
    }
    else
    {
        memcpy((uint8_t *)*dest, matrix, n_bytes);
    }

    *dest = &(((uint8_t *)*dest)[n_bytes]);
}

void _matrix_unpack_nrows_even(ff_t *matrix, uint8_t **source, const uint32_t *bit_offset,
                               const uint32_t n_rows, const int n_cols)
{
    uint32_t bo, n_bytes;

    if (bit_offset != NULL)
    {
        bo = *bit_offset;
    }
    else
    {
        bo = 0;
    }

    n_bytes = mirath_matrix_ff_bytes_size(n_rows, n_cols);

    if (bo)
    {
        /* Unpack all the bytes in matrix except the last one */
        memcpy(matrix, &(((uint8_t *)*source)[1]), n_bytes - 1); /* unpack all the bytes but the last one. */

        /* Unpack the last two entries of matrix. */
        matrix[n_bytes - 1] = (((uint8_t *)*source)[n_bytes] & 0x0f) | (((uint8_t *)*source)[0] & 0xf0);
    }
    else
    {
        memcpy(matrix, (uint8_t *)*source, n_bytes);
    }

    *source = &(((uint8_t *)*source)[n_bytes]);
}


/* Remove the last row of matrix and append it to matrix as additional column(s) */
void _matrix_pack_nrows_odd(uint8_t **dest, uint32_t *bit_offset, const ff_t *matrix,
                            const uint32_t n_rows, const uint32_t n_cols)
{
    assert((n_rows & 1) == 1);

    uint32_t j, bo, next_bo, matrix_height, matrix_height_x, n_bytes_not_in_last_row, n_bytes;
    uint32_t ad_bytes, jump_nbytes;
    uint8_t row_entry_j, row_entry_j_1;

    if (bit_offset != NULL)
    {
        bo = *bit_offset;
    }
    else
    {
        bo = 0;
    }

    matrix_height = (n_rows >> 1) + 1;
    matrix_height_x =  matrix_height - 1;
    n_bytes_not_in_last_row = matrix_height_x * n_cols;
    n_bytes = mirath_matrix_ff_bytes_size(n_rows, n_cols);

    /* Bytes that are not part of the last row. */
    for (j = 0u; j < n_cols; j++)
    {
        memcpy(&(((uint8_t *)*dest)[bo + j * matrix_height_x]), &matrix[matrix_height * j], matrix_height_x);
    }
    /* When n_cols is odd the maximum value of j is j_max = n_cols - 3, hence j_max + 1 = n_cols - 2.
     * Hence in the following loop wont add the entry n_cols - 1 (the last entry) of the last row.
     * When n_cols is even the maximum value of j is j_max = n_cols - 4, hence j_max + 1 = n_cols - 3.
     * Hence in the following loop wont add the entries n_cols - 2 and n_cols - 1 (the last entry) of the last row. */
    ad_bytes = bo;
    for (j = 0; (int)j < (int)n_cols - 2; j+=2)
    {
        row_entry_j = matrix[matrix_height * j + matrix_height_x] & 0x0f; /* j-th entry of the last row. */
        row_entry_j_1 = matrix[matrix_height * (j + 1) + matrix_height_x] & 0x0f; /* (j + 1)-th entry of the last row. */
        ((uint8_t *)*dest)[n_bytes_not_in_last_row + ad_bytes]  =  (row_entry_j_1 << 4) | row_entry_j;
        ad_bytes +=1;
    }
    /* When the is an odd number of columns and
     * bit_off_set = 1, we locate the last entry of matrix in higher bits
     * of the first byte of the source. Otherwise, if bit_off_set = 0, we locate ast entry of matrix
     * the next byte of dest. */
    if  (bo)
    {
        ((uint8_t *)*dest)[0]&= 0x0f;
        ((uint8_t *)*dest)[0] |= (matrix[n_bytes - 1] << 4);

        if ((n_cols & 1) == 0) /* case n_cols is even. */
        {
            /* Packing the second-last entry of the last row. */
            ((uint8_t *)*dest)[n_bytes_not_in_last_row + ad_bytes] = matrix[n_bytes - matrix_height - 1] & 0x0f;

        }
    }
    else
    {
        /* If n_cols is even and bo = 0,
         * we pack the entries n_cols - 2 and n_cols - 1
         * in the last row in the byte
         * of the current local buffer. */
        if ((n_cols & 1) == 0)
        {
            ((uint8_t *)*dest)[n_bytes_not_in_last_row + ad_bytes] = (matrix[n_bytes - 1] << 4) | matrix[n_bytes - matrix_height - 1];
        }
            /* Odd number of columns case. */
            /* In this case, we locate the last entry the next byte of dest. */
        else
        {
            ((uint8_t *)*dest)[n_bytes_not_in_last_row + ad_bytes] = matrix[n_bytes - 1] & 0x0f;
        }
    }

    jump_nbytes = matrix_height_x * n_cols + (n_cols >> 1);

    if (bo)
    {
        if ((n_cols & 1) == 0)
        {
            next_bo = 1;
        }
        else
        {
            next_bo = 0;
            jump_nbytes += (n_cols & 1);
        }
    }
    else
    {
        if ((n_cols & 1) == 0)
        {
            next_bo = 0;
        }
        else
        {
            next_bo = 1;
        }
    }

    if (bit_offset != NULL)
    {
        *bit_offset = next_bo;
    }

    *dest = &(((uint8_t *)*dest)[jump_nbytes]);
}

void _matrix_unpack_nrows_odd(ff_t *matrix, uint8_t **source, uint32_t *bit_offset,
                              const uint32_t n_rows, const uint32_t n_cols)
{
    assert((n_rows & 1) == 1);

    uint32_t j, bo, next_bo, matrix_height, matrix_height_x, n_bytes_not_in_last_row, n_bytes;
    uint32_t ad_bytes, jump_nbytes;
    uint8_t row_entries_j_and_j_1;

    if (bit_offset != NULL)
    {
        bo = *bit_offset;
    }
    else
    {
        bo = 0;
    }


    matrix_height = (n_rows >> 1) + 1;
    matrix_height_x =  matrix_height - 1;
    n_bytes_not_in_last_row = matrix_height_x * n_cols;
    n_bytes = mirath_matrix_ff_bytes_size(n_rows, n_cols);


    /* Bytes that are not part of the last row. */
    for (j = 0; j < n_cols; j++)
    {
        memcpy(&matrix[matrix_height * j], &(((uint8_t *)*source)[bo + j * matrix_height_x]), matrix_height_x);
    }

    /* When n_cols is odd the maximum value of j is j_max = n_cols - 3, hence j_max + 1 = n_cols - 2.
     * Hence in the following loop wont add the entry n_cols - 1 (the last entry) of the last row .
     * When n_cols is even the maximum value of j is j_max = n_cols - 4, hence j_max + 1 = n_cols - 3.
     * Hence in the following loop wont add the entries n_cols - 2 and n_cols - 1 (the last entry) of the last row. */
    ad_bytes = bo;
    for (j = 0; (int)j < (int)n_cols - 2; j+=2)
    {
        row_entries_j_and_j_1 = ((uint8_t *)*source)[n_bytes_not_in_last_row + ad_bytes];
        matrix[matrix_height * j + matrix_height_x] = row_entries_j_and_j_1 & 0x0f;
        matrix[matrix_height * (j + 1) + matrix_height_x] =  row_entries_j_and_j_1 >> 4;
        ad_bytes +=1;
    }
    /* When the is an odd number of columns and
     * bit_off_set = 1, we locate the last entry of matrix in higher bits
     * of the first byte of the source. Otherwise, if bit_off_set = 0, we locate ast entry of matrix
     * the next byte of dest. */
    if  (bo)
    {
        matrix[n_bytes - 1]  = ((uint8_t *)*source)[0] >> 4;

        if ((n_cols & 1) == 0) /* case n_rows is even. */
        {
            matrix[n_bytes - matrix_height - 1] = ((uint8_t *)*source)[n_bytes_not_in_last_row + ad_bytes] & 0x0f;
        }
    }
    else
    {
        /* If n_cols is even and bo = 0,
        * we unpack the last row in the byte of the current local buffer
        * into the entries n_cols - 2 and n_cols - 1
        * of the last row of matrix .*/
        if ((n_cols & 1) == 0)
        {
            row_entries_j_and_j_1 =  ((uint8_t *)*source)[n_bytes_not_in_last_row + ad_bytes];
            matrix[n_bytes - 1]  = row_entries_j_and_j_1 >> 4;
            matrix[n_bytes - matrix_height - 1] = row_entries_j_and_j_1 & 0x0f;
        }
            /* Odd number of columns case.
             * In this case, we locate the last entry the next byte of dest. */
        else
        {
            matrix[n_bytes -1 ] = ((uint8_t *)*source)[n_bytes_not_in_last_row + ad_bytes] & 0x0f;
        }

    }

    jump_nbytes = matrix_height_x * n_cols + (n_cols >> 1);

    if (bo)
    {
        if ((n_cols & 1) == 0)
        {
            next_bo = 1;
        }
        else
        {
            next_bo = 0;
            jump_nbytes +=  (n_cols & 1);
        }
    }
    else
    {
        if ((n_cols & 1) == 0)
        {
            next_bo = 0;
        }
        else
        {
            next_bo = 1;
        }
    }

    if (bit_offset != NULL)
    {
        *bit_offset = next_bo;
    }

    *source = &(((uint8_t *)*source)[jump_nbytes]);
}

void mirath_matrix_ff_unparse(uint8_t **dest, uint32_t *bit_offset, const ff_t *matrix,
                 const uint32_t n_rows, const uint32_t n_cols)
{
    /* An even number of rows. */
    if ((n_rows & 1) == 0)
    {
        _matrix_pack_nrows_even(dest, bit_offset, matrix, n_rows, n_cols);
    }
    else
    {
        _matrix_pack_nrows_odd(dest, bit_offset, matrix, n_rows, n_cols);
    }

}

void mirath_matrix_ff_parse(ff_t *matrix, uint8_t **source, uint32_t *bit_offset,
                   const uint32_t n_rows, const uint32_t n_cols)
{
    /* An even number of rows. */
    if ((n_rows & 1) == 0)
    {
        _matrix_unpack_nrows_even(matrix, source, bit_offset, n_rows, n_cols);
    }
    else
    {
        _matrix_unpack_nrows_odd(matrix, source, bit_offset, n_rows, n_cols);
    }
}


