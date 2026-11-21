/**
 * \file rbc_67_mat_fq.c
 * \brief Implementation of rbc_67_mat_fq.h
 */

#include "rbc_67_mat_fq.h"




/**
 * \fn void rbc_67_mat_fq_init(rbc_67_mat_fq* m, uint32_t rows, uint32_t columns)
 * \brief This function allocates the memory for a rbc_67_mat_fq.
 *
 * \param[out] m Pointer to the allocated rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat_fq
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_init(rbc_67_mat_fq* m, uint32_t rows, uint32_t columns) {
  uint32_t words = (columns + 63) / 64;
  *m = calloc(rows, sizeof(uint64_t *));
  (*m)[0] = calloc(rows * words, sizeof(uint64_t *));
  for(size_t i = 1 ; i < rows ; ++i) {
    (*m)[i] = (*m)[0] + (i * words);
  }
if (m == NULL) exit(EXIT_FAILURE);
}




/**
 * \fn void rbc_67_mat_fq_clear(rbc_67_mat_fq m)
 * \brief This function clears a rbc_67_mat_fq element.
 *
 * \param[out] m rbc_67_mat_fq
 * \param[in] size Row size of the rbc_67_mat
 */
void rbc_67_mat_fq_clear(rbc_67_mat_fq m) {
    free(m[0]);
    free(m);
}



/**
 * \fn void rbc_67_mat_fq_set(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t rows, uint32_t columns)
 * \brief This function copies a matrix over GF(q).
 *
 * \param[out] o rbc_67_mat_fq
 * \param[in] m Pointer to the allocated rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat_fq
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_set(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t rows, uint32_t columns) {
  uint32_t words = (columns + 63) / 64
;  for(size_t i = 0 ; i < rows ; ++i) {
    for(size_t j = 0 ; j < words ; ++j) {
      o[i][j] = m[i][j];
    }
  }
}




/**
 * \fn void rbc_67_mat_fq_set_zero(rbc_67_mat_fq m, uint32_t rows, uint32_t columns)
 * \brief This function sets a matrix over GF(q) to zero.
 *
 * \param[out] o rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat_fq
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_set_zero(rbc_67_mat_fq m, uint32_t rows, uint32_t columns) {
  uint32_t words = (columns + 63) / 64;
  for(size_t i = 0 ; i < rows ; ++i) {
    memset(m[i], 0, words * sizeof(uint64_t));
  }
}




/**
 * \fn void rbc_67_mat_fq_set_identity(rbc_67_mat_fq m, uint32_t rows, uint32_t columns)
 * \brief This function sets a matrix over GF(q) to zero.
 *
 * \param[out] o rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat_fq
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_set_identity(rbc_67_mat_fq m, uint32_t rows, uint32_t columns) {
  uint32_t words = (columns + 63) / 64;
  for(size_t i = 0 ; i < rows ; ++i) {
    memset(m[i], 0, words * sizeof(uint64_t));
    m[i][i / 64] = (uint64_t)1 << (i % 64);
  }
}




/**
 * \fn void rbc_67_mat_fq_set_transpose(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t rows, uint32_t columns)
 * \brief This function transpose matrices over GF(q).
 *
 * \param[out] o rbc_67_mat_fq equal to \f$ m ^ T \f$
 * \param[in] m rbc_67_mat_fq 
 * \param[in] rows Row size of the rbc_67_mat_fq
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_set_transpose(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t rows, uint32_t columns) {
  uint64_t m_ij;
  rbc_67_mat_fq_set_zero(o, columns, rows);
  for(size_t i = 0 ; i < rows ; ++i) {
    for(size_t j = 0 ; j < columns ; ++j) {
      m_ij = (m[i][j / 64] >> (j % 64)) & 1;
      o[j][i / 64] ^= (m_ij << (i % 64));
    }
  }
}




/**
 * \fn void rbc_67_mat_fq_from_string(rbc_67_mat_fq m, uint32_t rows, cols, const uint8_t* str)
 * \brief This function parses a string into a matrix of finite field elements.
 *
 * \param[out] m rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] cols Column size of the rbc_67_mat
 * \param[in] str String to parse
 */
void rbc_67_mat_fq_from_string(rbc_67_mat_fq m, uint32_t rows, uint32_t cols, const uint8_t* str) {
    uint32_t bytes1 = cols / 8;
    uint32_t bytes2 = cols % 8;
    uint32_t index = bytes1 * rows;

    rbc_67_mat_fq_set_zero(m, rows, cols);

    for(size_t i = 0 ; i < rows ; i++) {
        memcpy(m[i], str + i * bytes1, bytes1);
    }

    uint8_t k = 0;
    for(size_t i = 0 ; i < rows ; i++) {
        for(size_t j = 1 ; j <= bytes2 ; j++) {
            uint8_t bit = (str[index] >> k % 8) & 0x01;
            m[i][(cols - j) / RBC_67_INTEGER_LENGTH] |= (rbc_67_elt_uint)bit << ((cols - j) % RBC_67_INTEGER_LENGTH);
            k++;
            if(k % 8 == 0) index++;
        }
    }
}



/**
 * \fn void rbc_67_mat_fq_set_random(seedexpander_shake_t* ctx, rbc_67_mat_fq o, uint32_t rows, uint32_t cols)
 * \brief This function parses a string into a matrix of finite field elements.
 *
 * \param[out] ctx Seed
 * \param[out] o rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] cols Column size of the rbc_67_mat
 */
void rbc_67_mat_fq_set_random(seedexpander_shake_t* ctx, rbc_67_mat_fq o, uint32_t rows, uint32_t cols) {
    uint32_t random_size = (rows * cols + 7) / 8;
    uint8_t random[random_size];
    seedexpander_shake_get_bytes(ctx, random, random_size);

    // We mask the random bit-string to ensure the correct amount of random bits
    uint8_t mask = (1 << (rows * cols) % 8) - 1;
    if (((rows * cols) % 8) == 0) { mask = 0xff; }
    random[random_size - 1] &= mask;

    rbc_67_mat_fq_from_string(o, rows, cols, random);
}



/**
 * \fn void rbc_67_mat_fq_to_string(uint8_t* str, const rbc_67_mat_fq m, uint32_t rows, cols)
 * \brief This function parses a matrix of finite field elements into a string.
 *
 * \param[out] str Output string
 * \param[in] m rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] cols Column size of the rbc_67_mat
 */
void rbc_67_mat_fq_to_string(uint8_t* str, const rbc_67_mat_fq m, uint32_t rows, uint32_t cols) {
    uint32_t bytes1 = cols / 8;
    uint32_t bytes2 = cols % 8;
    uint32_t index = bytes1 * rows;
    uint32_t str_size = ((rows * cols) % 8 == 0) ? (rows * cols) / 8 : (rows * cols) / 8 + 1;

    memset(str, 0, str_size);

    for(size_t i = 0 ; i < rows ; i++) {
        memcpy(str + i * bytes1, m[i], bytes1);
    }

    uint8_t k = 0;
    for(size_t i = 0 ; i < rows ; i++) {
        for(size_t j = 1 ; j <= bytes2 ; j++) {
            uint8_t bit = (uint8_t)(m[i][(cols - j) / RBC_67_INTEGER_LENGTH] >> ((cols - j) % RBC_67_INTEGER_LENGTH)) & 0x01;
            *(str + index) |= (bit << k % 8);
            k++;
            if(k % 8 == 0) index++;
        }
    }
}



/**
 * \fn void rbc_67_mat_fq_add(rbc_67_mat_fq o, const rbc_67_mat_fq a, const rbc_67_mat_fq b, uint32_t rows, uint32_t columns)
 * \brief This functions adds two matrices over GF(q).
 *
 * \param[out] o rbc_67_mat equal to \f$ a + b \f$
 * \param[in] a rbc_67_mat_fq
 * \param[in] b rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat_fq, and Row size of the rbd_vec
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_add(rbc_67_mat_fq o, const rbc_67_mat_fq a, const rbc_67_mat_fq b, uint32_t rows, uint32_t columns) {
  size_t block = (columns + 63) / 64;  for(size_t j = 0 ; j < rows; ++j) {
    for(size_t k = 0 ; k < block; ++k) {
      o[j][k] = a[j][k] ^ b[j][k];
    }
  }
}

/**
 * \fn void rbc_67_mat_fq_mul(rbc_67_mat_fq o, const rbc_67_mat_fq m1, const rbc_67_mat_fq m2, uint32_t rows1, uint32_t columns1_rows2, uint32_t columns2)
 * \brief This functions multiplies matrices over GF(q).
 *
 * \param[out] o rbc_67_mat_fq equal to \f$ m1 \times m2 \f$
 * \param[in] m1 rbc_67_mat_fq
 * \param[in] m2 rbc_67_mat_fq
 * \param[in] rows1 Row size of m1
 * \param[in] columns1_rows2 Column and row sizes of m1 and m2, respectively
 * \param[in] columns2 Column size of m2
 */
void rbc_67_mat_fq_mul(rbc_67_mat_fq o, const rbc_67_mat_fq m1, const rbc_67_mat_fq m2, uint32_t rows1, uint32_t columns1_rows2, uint32_t columns2) {
  uint64_t acc;
  rbc_67_mat_fq t2;
  rbc_67_mat_fq_init(&t2, columns2, columns1_rows2);
  rbc_67_mat_fq_set_transpose(t2, m2, columns1_rows2, columns2);
  rbc_67_mat_fq_set_zero(o, rows1, columns2);
  for(size_t i = 0 ; i < rows1 ; ++i) {
    for(size_t j = 0 ; j < columns2 ; ++j) {
      acc = 0;
      for(size_t k = 0 ; k < ((columns1_rows2 + 63) / 64) ; ++k) {
        acc ^= (m1[i][k] & t2[j][k]);
      }
      o[i][j / 64] ^= ((uint64_t)__builtin_popcountll(acc) & 0x1) << (j % 64);
    }
  }
  rbc_67_mat_fq_clear(t2);
}




/**
 * \fn void rbc_67_mat_fq_mul_by_vec_left(rbc_67_vec o, const rbc_67_mat_fq m, const rbc_67_vec v, uint32_t rows, uint32_t columns)
 * \brief This functions multiplies a matrix over GF(q) by a vector over GF(q^m).
 *
 * \param[out] o rbc_67_vec equal to \f$ v \times m \f$
 * \param[in] m rbc_67_mat_fq
 * \param[in] v rbc_67_vec
 * \param[in] rows Row size of the rbc_67_mat_fq, and Row size of the rbd_vec
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_mul_by_vec_left(rbc_67_vec o, const rbc_67_mat_fq m, const rbc_67_vec v, uint32_t rows, uint32_t columns) {
  rbc_67_elt tmp, acc;
  uint64_t mask;
  for(size_t j = 0 ; j < columns ; ++j) {
    rbc_67_elt_set_zero(acc);
    for(size_t k = 0 ; k < rows ; ++k) {
      mask = (uint64_t)(m[k][j / 64] >> (j % 64));
      mask = -(mask & 1);
      for(size_t l = 0 ; l < RBC_67_ELT_SIZE; ++l) {
        tmp[l] = v[k][l] & mask;
      }
      rbc_67_elt_add(acc, acc, tmp);
    }
  rbc_67_elt_set(o[j], acc);
  }
}




/**
 * \fn void rbc_67_mat_fq_mul_by_vec_right(rbc_67_vec o, const rbc_67_mat_fq m, const rbc_67_vec v, uint32_t rows, uint32_t columns)
 * \brief This functions multiplies a matrix over GF(q) by a vector over GF(q^m).
 *
 * \param[out] o rbc_67_vec equal to \f$ m \times v \f$
 * \param[in] m rbc_67_mat_fq
 * \param[in] v rbc_67_vec
 * \param[in] rows Row size of the rbc_67_mat_fq
 * \param[in] columns Column size of the rbc_67_mat_fq, and Row size of the rbd_vec
 */
void rbc_67_mat_fq_mul_by_vec_right(rbc_67_vec o, const rbc_67_mat_fq m, const rbc_67_vec v, uint32_t rows, uint32_t columns) {
  rbc_67_elt tmp, acc;
  uint64_t mask;
  for(size_t i = 0 ; i < rows ; ++i) {
    rbc_67_elt_set_zero(acc);
    for(size_t j = 0 ; j < columns ; ++j) {
      mask = (uint64_t)(m[i][j / 64] >> (j % 64));
      mask = -(mask & 1);
      for(size_t l = 0 ; l < RBC_67_ELT_SIZE; ++l) {
        tmp[l] = v[j][l] & mask;
      }
      rbc_67_elt_add(acc, acc, tmp);
    }
  rbc_67_elt_set(o[i], acc);
  }
}




/**
 * \fn void rbc_67_mat_fq_mul_by_constant(rbc_67_mat o, const rbc_67_mat_fq m, const rbc_67_elt c, uint32_t rows, uint32_t columns)
 * \brief This functions multiplies a matrix over GF(q) by a element in GF(q^m).
 *
 * \param[out] o rbc_67_mat equal to \f$ c \times m \f$
 * \param[in] m rbc_67_mat_fq
 * \param[in] c rbc_67_elt
 * \param[in] rows Row size of the rbc_67_mat_fq, and Row size of the rbd_vec
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_mul_by_constant(rbc_67_mat o, const rbc_67_mat_fq m, const rbc_67_elt c, uint32_t rows, uint32_t columns) {
  rbc_67_elt tmp;
  uint64_t mask;
  for(size_t j = 0 ; j < columns ; ++j) {
    for(size_t k = 0 ; k < rows ; ++k) {
      mask = (uint64_t)(m[k][j / 64] >> (j % 64));
      mask = -(mask & 1);
      for(size_t l = 0 ; l < RBC_67_ELT_SIZE; ++l) {
        tmp[l] = c[l] & mask;
      }
      rbc_67_elt_set(o[k][j], tmp);
    }
  }
}




/**
 * \fn void rbc_67_mat_fq_minmax(rbc_67_mat_fq c1, uint64_t* x, rbc_67_mat_fq c2, uint64_t* y, uint32_t size)
 * \brief MinMax functions to swap matrices over GF(q) in the djb-sort.
 *
 * \param[in] c1 rbc_67_mat_fq of dimension 1 x size
 * \param[in] x permutation entry
 * \param[in] c2 rbc_67_mat_fq of dimension 1 x size
 * \param[in] k permutation entry
 * \param[in] n Column size of the rbc_67_mat_fq elements c1 and c2
 */
void rbc_67_mat_fq_minmax(rbc_67_mat_fq c1, uint64_t* x, rbc_67_mat_fq c2, uint64_t* y, uint32_t size) {
  int64_t a = *x;
  int64_t b = *y;
  int64_t ab = b ^ a;
  int64_t c = b - a;
  c ^= ab & (c ^ b);
  c >>= 63;
  uint64_t z;
  z = (uint64_t)(c & ab);
  *x = a ^ z;
  *y = b ^ z;
  uint64_t words = (size + 63)/64;
  for(size_t j = 0 ; j < words; ++j) {
    a = (*c1)[j];
    b = (*c2)[j];
    ab = a ^ b;
    z = (uint64_t)(c & ab);
    (*c1)[j] = a ^ z;
    (*c2)[j] = b ^ z;
  }
}




/**
 * \fn void rbc_67_mat_fq_set_inverse(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t size)
 * \brief This function inverses matrices over GF(q) via Gaussian elimination.
 *
 * \param[out] o rbc_67_mat_fq equal to \f$ m ^ {-1} \f$
 * \param[in] m rbc_67_mat_fq 
 * \param[in] size Column and row sizes of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_set_inverse(rbc_67_mat_fq o, const rbc_67_mat_fq m, uint32_t size) {
  uint32_t words = (size + 63) / 64;
  uint64_t mask_i, mask_j, tmp_i, tmp_j;
  rbc_67_mat_fq t, v;
  rbc_67_mat_fq_init(&t, size, size);
  rbc_67_mat_fq_init(&v, 1, size);
  rbc_67_mat_fq_set(t, m, size, size);
  rbc_67_mat_fq_set_identity(o, size, size);
  for(size_t i = 0 ; i < size; ++i) {
    mask_i = -(t[i][i / 64] & ((uint64_t)1 << (i % 64)));
    mask_i >>= 63;
    tmp_i = mask_i;
    for(size_t j = (i + 1); j < size ; ++j) {
      mask_j = -(t[j][i / 64] & ((uint64_t)1 << (i % 64)));
      mask_j >>= 63;
      tmp_j = mask_j;
      rbc_67_mat_fq_minmax(&t[j], &mask_j, &t[i], &mask_i, size);
      rbc_67_mat_fq_minmax(&o[j], &tmp_j, &o[i], &tmp_i, size);
    }
    mask_i = 0;
    for(size_t j = 0; j < i ; ++j) {
      for(size_t k = 0; k < words ; ++k) {
        v[0][k] = t[i][k] ^ t[j][k];
      }
      mask_j = -(t[j][i / 64] & ((uint64_t)1 << (i % 64)));
      mask_j >>= 63;
      tmp_i = mask_i;
      tmp_j = mask_j;
      rbc_67_mat_fq_minmax(&t[j], &tmp_j, &v[0], &tmp_i, size);
      for(size_t k = 0; k < words ; ++k) {
        v[0][k] = o[i][k] ^ o[j][k];
      }
      tmp_i = mask_i;
      tmp_j = mask_j;
      rbc_67_mat_fq_minmax(&o[j], &tmp_j, &v[0], &tmp_i, size);
    }
    for(size_t j = (i + 1); j < size ; ++j) {
      for(size_t k = 0; k < words ; ++k) {
        v[0][k] = t[i][k] ^ t[j][k];
      }
      mask_j = -(t[j][i / 64] & ((uint64_t)1 << (i % 64)));
      mask_j >>= 63;
      tmp_i = mask_i;
      tmp_j = mask_j;
      rbc_67_mat_fq_minmax(&t[j], &tmp_j, &v[0], &tmp_i, size);
      for(size_t k = 0; k < words ; ++k) {
        v[0][k] = o[i][k] ^ o[j][k];
      }
      tmp_i = mask_i;
      tmp_j = mask_j;
      rbc_67_mat_fq_minmax(&o[j], &tmp_j, &v[0], &tmp_i, size);
    }
  }
  mask_i = 0;
  mask_j = 0;
  tmp_i = 0;
  tmp_j = 0;
  rbc_67_mat_fq_clear(v);
  rbc_67_mat_fq_clear(t);
}




/**
 * \void rbc_67_mat_fq_print(rbc_67_mat_fq m, uint32_t rows, uint32_t columns)
 * \brief Display a rbc_67_mat_fq element.
 *
 * \param[in] m rbc_67_mat_fq
 * \param[in] rows Row size of the rbc_67_mat_fq
 * \param[in] columns Column size of the rbc_67_mat_fq
 */
void rbc_67_mat_fq_print(rbc_67_mat_fq m, uint32_t rows, uint32_t columns) {
  printf("[\n");
  for(size_t i = 0 ; i < rows ; ++i) {
    printf("[");
    for(size_t j = 0 ; j < columns ; ++j) {
      printf(" %X", (uint8_t)((m[i][j / 64] >> (j % 64)) & 1));
    }
    printf("]\n");  }
  printf("]\n");}

