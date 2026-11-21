// NextSSL adapter (not upstream code). Owns Crypto++ objects behind an extern "C" surface; every C++
// exception is caught here, nothing unwinds into Rust. Crypto++ wipes its own key material on destruction
// (SecBlock with AllocatorWithCleanup).
#include <new>
#include <cstddef>
#include <string>
#include "3way.h"
#include "algparam.h"

using namespace CryptoPP;

// Link support, not crypto. (1) misc.h declares this specialization but integer.cpp (the big-integer
// code, not needed here) defines it: the body is copied from integer.cpp. (2) algparam.h declares these
// template instantiations extern; the code that instantiates them (dll.cpp) is not compiled.
namespace CryptoPP {
template <> CRYPTOPP_DLL
std::string IntToString<word64>(word64 value, unsigned int base)
{
	static const unsigned int HIGH_BIT = (1U << 31);
	const char CH = !!(base & HIGH_BIT) ? 'A' : 'a';
	base &= ~HIGH_BIT;
	if (value == 0)
		return "0";
	std::string result;
	while (value > 0)
	{
		word64 digit = value % base;
		result = char((digit < 10 ? '0' : (CH - 10)) + digit) + result;
		value /= base;
	}
	return result;
}
#ifndef CRYPTOPP_MANUALLY_INSTANTIATE_TEMPLATES
template class AlgorithmParametersTemplate<bool>;
template class AlgorithmParametersTemplate<int>;
template class AlgorithmParametersTemplate<ConstByteArrayParameter>;
#endif
}

namespace {
struct Ctx {
    ThreeWay::Encryption enc;
    ThreeWay::Decryption dec;
};
}

extern "C" void *nextssl__3way__shim_new(const unsigned char *key, int keylen) {
    if (key == NULL || keylen <= 0) return NULL;
    try {
        Ctx *c = new Ctx();
        c->enc.SetKey(key, (size_t)keylen);
        c->dec.SetKey(key, (size_t)keylen);
        return c;
    } catch (...) {
        return NULL;
    }
}

extern "C" int nextssl__3way__shim_enc(const void *c, const unsigned char *in, unsigned char *out) {
    try {
        ((const Ctx *)c)->enc.ProcessBlock(in, out);
        return 0;
    } catch (...) {
        return -1;
    }
}

extern "C" int nextssl__3way__shim_dec(const void *c, const unsigned char *in, unsigned char *out) {
    try {
        ((const Ctx *)c)->dec.ProcessBlock(in, out);
        return 0;
    } catch (...) {
        return -1;
    }
}

extern "C" void nextssl__3way__shim_free(void *c) {
    delete (Ctx *)c;
}
