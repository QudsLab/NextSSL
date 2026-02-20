#ifndef POW_PARSER_H
#define POW_PARSER_H

#include "pow_types.h"

// Parse challenge from JSON/Base64 string
int pow_parser_decode_challenge(const char* base64_str, POWChallenge* out_challenge);

// Encode challenge to JSON/Base64 string
// Returns 0 on success, < 0 on error
// out_str must be large enough
int pow_parser_encode_challenge(const POWChallenge* challenge, char* out_str, size_t out_len);

// Parse solution from JSON/Base64 string
int pow_parser_decode_solution(const char* base64_str, POWSolution* out_solution);

// Encode solution to JSON/Base64 string
int pow_parser_encode_solution(const POWSolution* solution, char* out_str, size_t out_len);

#endif // POW_PARSER_H
