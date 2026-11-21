/** 
 * @file ryde_1s_sign.h
 * @brief Sign algorithm of the RYDE scheme
 */

#ifndef RYDE_1S_SIGN_H
#define RYDE_1S_SIGN_H

#include <stdint.h>

int ryde_1s_sign(uint8_t* signature, const uint8_t* message, size_t message_size, const uint8_t* sk);

#endif

