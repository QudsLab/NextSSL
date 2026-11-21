/**
 * \file rbc_67_mat.c
 * \brief Implementation of rbc_67_mat.h
 */

#include "rbc_67_mat.h"




/**
 * \fn void rbc_67_mat_init(rbc_67_mat* m, uint32_t rows, uint32_t columns)
 * \brief This function allocates the memory for a rbc_67_mat.
 *
 * \param[out] m Pointer to the allocated rbc_67_mat
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_init(rbc_67_mat* m, uint32_t rows, uint32_t columns) {
    *m = calloc(rows, sizeof(rbc_67_vec *));
    (*m)[0] = calloc(rows * columns, sizeof(rbc_67_elt));
    for(size_t i = 0; i < rows; ++i) {
        (*m)[i] = (*m)[0] + (i * columns);
    }
    if (m == NULL) exit(EXIT_FAILURE);
}




/**
 * \fn void rbc_67_mat_clear(rbc_67_mat m)
 * \brief This function clears a rbc_67_mat element.
 *
 * \param[out] m rbc_67_mat
 */
void rbc_67_mat_clear(rbc_67_mat m) {
    free(m[0]);
    free(m);
}



/**
 * \fn void rbc_67_mat_set(rbc_67_mat o, const rbc_67_mat m, uint32_t rows, uint32_t columns)
 * \brief This function copies a matrix of finite field elements to another one.
 *
 * \param[out] o rbc_67_mat
 * \param[in] m rbc_67_mat
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_set(rbc_67_mat o, const rbc_67_mat m, uint32_t rows, uint32_t columns) {
    for(size_t i = 0 ; i < rows ; ++i) {
        rbc_67_vec_set(o[i], m[i], columns);
    }
}



/**
 * \fn void rbc_67_mat_set_zero(rbc_67_mat m, uint32_t rows, uint32_t columns)
 * \brief This function sets a matrix of finite elements to zero.
 *
 * \param[out] m rbc_67_mat
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_set_zero(rbc_67_mat m, uint32_t rows, uint32_t columns) {
    for(size_t i = 0 ; i < rows ; ++i) {
        rbc_67_vec_set_zero(m[i], columns);
    }
}



/**
 * \fn void rbc_67_mat_set_random(seedexpander_shake* ctx, rbc_67_mat m, uint32_t rows, uint32_t columns)
 * \brief This function sets a matrix of finite field elements with random values using NIST seed expander.
 *
 * \param[out] ctx Seed expander
 * \param[out] m rbc_67_mat
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_set_random(seedexpander_shake_t* ctx, rbc_67_mat m, uint32_t rows, uint32_t columns) {
    for(size_t i = 0 ; i < rows ; ++i) {
        rbc_67_vec_set_random(ctx, m[i], columns);
    }
}



/**
 * \fn void rbc_67_mat_add(rbc_67_mat o, const rbc_67_mat m1, const rbc_67_mat m2, uint32_t rows, uint32_t columns)
 * \brief This functions adds matrices of finite field elements.
 *
 * \param[out] o rbc_67_mat equal to \f$ m1 \oplus m2 \f$
 * \param[in] m1 rbc_67_mat
 * \param[in] m2 rbc_67_mat
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_add(rbc_67_mat o, const rbc_67_mat m1, const rbc_67_mat m2, uint32_t rows, uint32_t columns) {
    for(size_t i = 0 ; i < rows ; ++i) {
        for(size_t j = 0 ; j < columns ; ++j) {
            rbc_67_elt_add(o[i][j], m1[i][j], m2[i][j]);
        }
    }
}



/**
 * \fn void rbc_67_mat_mul(rbc_67_mat o, const rbc_67_mat m1, const rbc_67_mat m2, uint32_t rows1, uint32_t columns1_rows2, uint32_t columns2)
 * \brief This functions multiplies matrices of finite field elements.
 *
 * \param[out] o rbc_67_mat equal to \f$ m1 \times m2 \f$
 * \param[in] m1 rbc_67_mat
 * \param[in] m2 rbc_67_mat
 * \param[in] rows1 Row size of m1
 * \param[in] columns1_rows2 Column and row sizes of m1 and m2, respectively
 * \param[in] columns2 Column size of m2
 */
void rbc_67_mat_mul(rbc_67_mat o, const rbc_67_mat m1, const rbc_67_mat m2, uint32_t rows1, uint32_t columns1_rows2, uint32_t columns2) {
    rbc_67_elt tmp, acc;
    rbc_67_mat_set_zero(o, rows1, columns2);
    for(size_t i = 0 ; i < rows1 ; ++i) {
        for(size_t j = 0 ; j < columns2 ; ++j) {
            rbc_67_elt_set_zero(acc);
            for(size_t k = 0 ; k < columns1_rows2 ; ++k) {
                rbc_67_elt_mul(tmp, m1[i][k], m2[k][j]);
                rbc_67_elt_add(acc, acc, tmp);
            }
            rbc_67_elt_set(o[i][j], acc);
        }
    }
}



/**
 * \fn void rbc_67_mat_mul_by_vec_right(rbc_67_vec o, const rbc_67_mat m, const rbc_67_vec v, uint32_t rows, uint32_t columns)
 * \brief This functions multiplies a matrix of finite field elements by a vector.
 *
 * \param[out] o rbc_67_vec equal to \f$ m \times v \f$
 * \param[in] m rbc_67_mat
 * \param[in] v rbc_67_vec
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat, and Row size of the rbd_vec
 */
void rbc_67_mat_mul_by_vec_right(rbc_67_vec o, const rbc_67_mat m, const rbc_67_vec v, uint32_t rows, uint32_t columns) {
    rbc_67_elt tmp, acc;
    for(size_t i = 0 ; i < rows ; ++i) {
        rbc_67_elt_set_zero(acc);
        for(size_t j = 0 ; j < columns ; ++j) {
            rbc_67_elt_mul(tmp, m[i][j], v[j]);
            rbc_67_elt_add(acc, acc, tmp);
        }
        rbc_67_elt_set(o[i], acc);
    }
}



/**
 * \fn void rbc_67_mat_mul_by_vec_left(rbc_67_vec o, const rbc_67_mat m, const rbc_67_vec v, uint32_t rows, uint32_t columns)
 * \brief This functions multiplies a matrix of finite field elements by a vector.
 *
 * \param[out] o rbc_67_vec equal to \f$ v \times m \f$
 * \param[in] m rbc_67_mat
 * \param[in] v rbc_67_vec
 * \param[in] rows Row size of the rbc_67_mat, and Row size of the rbd_vec
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_mul_by_vec_left(rbc_67_vec o, const rbc_67_mat m, const rbc_67_vec v, uint32_t rows, uint32_t columns) {
    rbc_67_elt tmp, acc;
    for(size_t i = 0 ; i < columns ; ++i) {
        rbc_67_elt_set_zero(acc);
        for(size_t j = 0 ; j < rows ; ++j) {
            rbc_67_elt_mul(tmp, m[j][i], v[j]);
            rbc_67_elt_add(acc, acc, tmp);
        }
        rbc_67_elt_set(o[i], acc);
    }
}



/**
 * \fn void rbc_67_mat_mul_by_vec_left_transpose(rbc_67_vec o, const rbc_67_mat m, const rbc_67_vec v, uint32_t rows, uint32_t columns)
 * \brief This functions multiplies a matrix of finite field elements by a vector.
 *
 * \param[out] o rbc_67_vec equal to \f$ v \times m^\top \f$
 * \param[in] m rbc_67_mat
 * \param[in] v rbc_67_vec
 * \param[in] rows Row size of the rbc_67_mat, and Row size of the rbd_vec
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_mul_by_vec_left_transpose(rbc_67_vec o, const rbc_67_mat m, const rbc_67_vec v, uint32_t rows, uint32_t columns) {
    rbc_67_elt tmp, acc;
    for(size_t i = 0 ; i < rows ; ++i) {
        rbc_67_elt_set_zero(acc);
        for(size_t j = 0 ; j < columns ; ++j) {
            rbc_67_elt_mul(tmp, m[i][j], v[j]);
            rbc_67_elt_add(acc, acc, tmp);
        }
        rbc_67_elt_set(o[i], acc);
    }
}



/**
 * \fn void rbc_67_mat_to_string(uint8_t* str, const rbc_67_mat m, uint32_t rows, uint32_t columns)
 * \brief This function parses a matrix of finite field elements into a string.
 *
 * \param[out] str Output string
 * \param[in] m rbc_67_mat
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_to_string(uint8_t* str, const rbc_67_mat m, uint32_t rows, uint32_t columns) {
  rbc_67_vec t;
  rbc_67_vec_init(&t, rows * columns);
  for(size_t i = 0 ; i < rows ; i++) {
    for(size_t j = 0 ; j < columns ; j++) {
      rbc_67_elt_set(t[i * columns + j], m[i][j]);
    }
  }
  rbc_67_vec_to_string(str, t, rows * columns);
  rbc_67_vec_clear(t);
}



/**
 * \fn void rbc_67_mat_from_string(rbc_67_mat m, uint32_t rows, uint32_t columns, const uint8_t* str)
 * \brief This function parses a string into a matrix of finite field elements.
 *
 * \param[out] m rbc_67_mat
 * \param[in] size Size of the matrix
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_from_string(rbc_67_mat m, uint32_t rows, uint32_t columns, const uint8_t* str) {
  rbc_67_vec t;
  rbc_67_vec_init(&t, rows * columns);
  rbc_67_vec_from_string(t, rows * columns, str);
  for(size_t i = 0 ; i < rows ; i++) {
    for(size_t j = 0 ; j < columns ; j++) {
      rbc_67_elt_set(m[i][j], t[i * columns + j]);
    }
  }
  rbc_67_vec_clear(t);
}



/**
 * \fn void rbc_67_mat_print(rbc_67_mat m, uint32_t rows, uint32_t columns)
 * \brief Display an rbc_67_mat element.
 *
 * \param[out] m rbc_67_mat
 * \param[in] rows Row size of the rbc_67_mat
 * \param[in] columns Column size of the rbc_67_mat
 */
void rbc_67_mat_print(rbc_67_mat m, uint32_t rows, uint32_t columns) {
    printf("[\n");
    for(size_t i = 0 ; i < rows ; ++i) {
        printf("[\t");
        for(size_t j = 0 ; j < columns ; ++j) {
            rbc_67_elt_print(m[i][j]);
        }
        printf("\t]\n");
    }
    printf("]\n");
}
