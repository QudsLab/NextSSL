#ifndef RBC_53_H
#define RBC_53_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>

#define RBC_53_FIELD_Q 2
#define RBC_53_FIELD_M 53

#define RBC_53_ELT_SIZE 1
#define RBC_53_ELT_DATA_SIZE 1

#define RBC_53_ELT_UR_SIZE 2
#define RBC_53_ELT_UR_DATA_SIZE 2

#define RBC_53_ELT_UINT8_SIZE 7
#define RBC_53_ELT_UR_UINT8_SIZE 14


#define RBC_53_ELT_MASK 31


#define RBC_53_INTEGER_LENGTH 64

typedef int64_t rbc_53_elt_int;
typedef uint64_t rbc_53_elt_uint;
typedef uint64_t rbc_53_elt[RBC_53_ELT_SIZE];
typedef uint64_t rbc_53_elt_ur[RBC_53_ELT_UR_SIZE];
typedef uint64_t* rbc_53_elt_ptr;

typedef rbc_53_elt* rbc_53_vec;
typedef rbc_53_elt* rbc_53_vspace;

typedef struct {
  rbc_53_vec v;
  int32_t max_degree;
  // Do not use degree, it is deprecated and will be removed later
  // Kept temporarily for compatibility with rbc_53_qpoly
  int32_t degree;
} rbc_53_poly_struct;

typedef struct {
	 uint32_t coeffs_nb;
	 uint32_t* coeffs;
} rbc_53_poly_sparse_struct;

typedef rbc_53_poly_struct* rbc_53_poly;
typedef rbc_53_poly_sparse_struct* rbc_53_poly_sparse;

typedef rbc_53_poly rbc_53_qre;

typedef rbc_53_vec* rbc_53_mat;
typedef uint64_t** rbc_53_mat_fq;
typedef uint64_t* rbc_53_perm;

typedef struct {
  rbc_53_mat_fq P;
  rbc_53_mat_fq Q;
  uint32_t n;
} rbc_53_isometry;

void rbc_53_field_init(void);
extern uint64_t RBC_53_SQR_LOOKUP_TABLE[256];
static const rbc_53_elt RBC_53_ELT_MODULUS = {0x0020000000000047};

#ifndef min
  #define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef max
  #define max(a,b) (((a)>(b))?(a):(b))
#endif

#endif
