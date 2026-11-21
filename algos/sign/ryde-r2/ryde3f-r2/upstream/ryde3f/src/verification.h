/**
 * \file ryde_3f_verify.h
 * \brief NIST SIGNATURE VERIFICATION API used by the RYDE scheme
 */

#ifndef RYDE_3F_VERIFY_H
#define RYDE_3F_VERIFY_H

#include <stdint.h>

int ryde_3f_verify(const uint8_t* signature, size_t signature_size, const uint8_t* message, size_t message_size, const uint8_t* pk);

#endif

