#include "calc_interface.h"

// Blake3: Block size 64 bytes, Chunk size 1024 bytes
// Very fast.
#define COST_BLAKE3_CHUNK 100.0

double pow_calc_cost_blake(PoWAlgorithm algo, const PoWComplexityArgs *args) {
    if (!args) return 0.0;
    
    // Blake3
    size_t num_chunks = (args->input_len + 1023) / 1024;
    return (double)num_chunks * COST_BLAKE3_CHUNK;
}
