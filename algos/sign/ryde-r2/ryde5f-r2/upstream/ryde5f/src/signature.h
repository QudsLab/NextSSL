/** 
 * @file ryde_5f_sign.h
 * @brief Sign algorithm of the RYDE scheme
 */

#ifndef RYDE_5F_SIGN_H
#define RYDE_5F_SIGN_H

#include <stdint.h>

int ryde_5f_sign(uint8_t* signature, const uint8_t* message, size_t message_size, const uint8_t* sk);

#endif

