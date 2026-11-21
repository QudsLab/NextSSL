#ifndef RBC_61_H
#define RBC_61_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>

#define RBC_61_FIELD_Q 2
#define RBC_61_FIELD_M 61

#define RBC_61_ELT_SIZE 1
#define RBC_61_ELT_DATA_SIZE 1

#define RBC_61_ELT_UR_SIZE 2
#define RBC_61_ELT_UR_DATA_SIZE 2

#define RBC_61_ELT_UINT8_SIZE 8
#define RBC_61_ELT_UR_UINT8_SIZE 16


#define RBC_61_ELT_MASK 31


#define RBC_61_INTEGER_LENGTH 64

typedef int64_t rbc_61_elt_int;
typedef uint64_t rbc_61_elt_uint;
typedef uint64_t rbc_61_elt[RBC_61_ELT_SIZE];
typedef uint64_t rbc_61_elt_ur[RBC_61_ELT_UR_SIZE];
typedef uint64_t* rbc_61_elt_ptr;

typedef rbc_61_elt* rbc_61_vec;
typedef rbc_61_elt* rbc_61_vspace;

typedef struct {
  rbc_61_vec v;
  int32_t max_degree;
  // Do not use degree, it is deprecated and will be removed later
  // Kept temporarily for compatibility with rbc_61_qpoly
  int32_t degree;
} rbc_61_poly_struct;

typedef struct {
	 uint32_t coeffs_nb;
	 uint32_t* coeffs;
} rbc_61_poly_sparse_struct;

typedef rbc_61_poly_struct* rbc_61_poly;
typedef rbc_61_poly_sparse_struct* rbc_61_poly_sparse;

typedef rbc_61_poly rbc_61_qre;

typedef rbc_61_vec* rbc_61_mat;
typedef uint64_t** rbc_61_mat_fq;
typedef uint64_t* rbc_61_perm;

typedef struct {
  rbc_61_mat_fq P;
  rbc_61_mat_fq Q;
  uint32_t n;
} rbc_61_isometry;

void rbc_61_field_init(void);
extern uint64_t RBC_61_SQR_LOOKUP_TABLE[256];
static const rbc_61_elt RBC_61_ELT_MODULUS = {0x2000000000000027};

#ifndef min
  #define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef max
  #define max(a,b) (((a)>(b))?(a):(b))
#endif

#endif
