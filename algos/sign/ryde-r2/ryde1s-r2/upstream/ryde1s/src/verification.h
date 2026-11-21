/**
 * \file ryde_1s_verify.h
 * \brief NIST SIGNATURE VERIFICATION API used by the RYDE scheme
 */

#ifndef RYDE_1S_VERIFY_H
#define RYDE_1S_VERIFY_H

#include <stdint.h>

int ryde_1s_verify(const uint8_t* signature, size_t signature_size, const uint8_t* message, size_t message_size, const uint8_t* pk);

#endif

