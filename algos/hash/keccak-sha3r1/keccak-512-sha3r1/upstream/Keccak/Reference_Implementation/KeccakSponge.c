/*
Algorithm Name: Keccak
Authors: Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
Date: October 27, 2008

This code, originally by Guido Bertoni, Joan Daemen, Michaël Peeters and
Gilles Van Assche as a part of the SHA-3 submission, is hereby put in the
public domain. It is given as is, without any guarantee.

For more information, feedback or questions, please refer to our website:
http://keccak.noekeon.org/
*/

#include <string.h>
#include "KeccakNISTInterface.h"
#include "KeccakPermutationInterface.h"

HashReturn Init(hashState *state, int hashbitlen)
{
    KeccakInitialize();
    switch(hashbitlen) {
        case 0: // Arbitrary length output
            state->capacity = 576;
            break;
        case 224:
            state->capacity = 576;
            break;
        case 256:
            state->capacity = 576;
            break;
        case 384:
            state->capacity = 1088;
            break;
        case 512:
            state->capacity = 1088;
            break;
        default:
            return BAD_HASHLEN;
    }
    state->rate = KeccakPermutationSize - state->capacity;
    state->diversifier = hashbitlen/8;
    state->hashbitlen = hashbitlen;
    memset(state->state, 0, KeccakPermutationSizeInBytes);
    memset(state->dataQueue, 0, KeccakMaximumRateInBytes);
    state->bitsInQueue = 0;
    state->squeezing = 0;
    state->bitsAvailableForSqueezing = 0;

    return SUCCESS;
}

void AbsorbQueue(hashState *state)
{
    // state->bitsInQueue is assumed to be equal a multiple of 8
    KeccakPermutationAfterXor(state->state, state->dataQueue, state->bitsInQueue/8);
    state->bitsInQueue = 0;
}

void AbsorbWholeBlock(hashState *state, const BitSequence *data)
{
    KeccakPermutationAfterXor(state->state, data, state->rate/8);
}

HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
    DataLength i;
    DataLength partialBlock, partialByte;
    BitSequence lastByte;

    if ((state->bitsInQueue % 8) != 0)
        return FAIL; // Only the last call may contain a partial byte
    if (state->squeezing)
        return FAIL; // Too late for additional input

    i = 0;
    while(i < databitlen) {
        if ((state->bitsInQueue == 0) && (databitlen >= state->rate) && (i <= (databitlen-state->rate))) {
            do {
                AbsorbWholeBlock(state, data+i/8);
                i += state->rate;
            } while(i <= (databitlen-state->rate));
        }
        else {
            partialBlock = databitlen - i;
            if (partialBlock+state->bitsInQueue > state->rate)
                partialBlock = state->rate-state->bitsInQueue;
            partialByte = partialBlock % 8;
            partialBlock -= partialByte;
            memcpy(state->dataQueue+state->bitsInQueue/8, data+i/8, partialBlock/8);
            state->bitsInQueue += partialBlock;
            i += partialBlock;
            if (state->bitsInQueue == state->rate)
                AbsorbQueue(state);
            if (partialByte > 0) {
                // Align the last partial byte to the least significant bits
                lastByte = data[i/8] >> (8-partialByte);
                state->dataQueue[state->bitsInQueue/8] = lastByte;
                state->bitsInQueue += partialByte;
                i += partialByte;
            }
        }
    }
    return SUCCESS;
}

void PadAndSwitchToSqueezingPhase(hashState *state)
{
    if ((state->bitsInQueue % 8) != 0) {
        // The bits are numbered from 0=LSB to 7=MSB
        unsigned char padByte = 1 << (state->bitsInQueue % 8);
        state->dataQueue[state->bitsInQueue/8] |= padByte;
        state->bitsInQueue += 8-(state->bitsInQueue % 8);
    }
    else {
        state->dataQueue[state->bitsInQueue/8] = 0x01;
        state->bitsInQueue += 8;
    }
    if (state->bitsInQueue == state->rate)
        AbsorbQueue(state);
    state->dataQueue[state->bitsInQueue/8] = state->diversifier;
    state->bitsInQueue += 8;
    if (state->bitsInQueue == state->rate)
        AbsorbQueue(state);
    state->dataQueue[state->bitsInQueue/8] = state->rate/8;
    state->bitsInQueue += 8;
    if (state->bitsInQueue == state->rate)
        AbsorbQueue(state);
    state->dataQueue[state->bitsInQueue/8] = 0x01;
    state->bitsInQueue += 8;
    if (state->bitsInQueue > 0)
        AbsorbQueue(state);
    state->squeezing = 1;
    state->bitsAvailableForSqueezing = state->rate;
}

HashReturn Final(hashState *state, BitSequence *hashval)
{
    if (state->squeezing)
        return FAIL; // Too late, we are already squeezing
    PadAndSwitchToSqueezingPhase(state);
    if (state->hashbitlen > 0)
        memcpy(hashval, state->state, state->hashbitlen/8);
    return SUCCESS;
}

HashReturn Squeeze(hashState *state, BitSequence *output, DataLength outputLength)
{
    DataLength i;
    DataLength partialBlock;

    if (!state->squeezing)
        return FAIL; // Too early, we are still absorbing
    if (state->hashbitlen != 0)
        return FAIL; // Arbitrary length output is not permitted in this case
    if ((outputLength % 8) != 0)
        return FAIL; // Only multiple of 8 bits are allowed, truncation can be done at user level

    i = 0;
    while(i < outputLength) {
        if (state->bitsAvailableForSqueezing == 0) {
            KeccakPermutation(state->state);
            state->bitsAvailableForSqueezing = state->rate;
        }
        partialBlock = outputLength - i;
        if (partialBlock > state->bitsAvailableForSqueezing)
            partialBlock = state->bitsAvailableForSqueezing;
        memcpy(output+i/8, state->state+(state->rate-state->bitsAvailableForSqueezing)/8, partialBlock/8);
        state->bitsAvailableForSqueezing -= partialBlock;
        i += partialBlock;
    }
    return SUCCESS;
}

HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
    hashState state;
    HashReturn result;

    if (hashbitlen == 0)
        return BAD_HASHLEN; // Arbitrary length output not available through this API
    result = Init(&state, hashbitlen);
    if (result != SUCCESS)
        return result;
    result = Update(&state, data, databitlen);
    if (result != SUCCESS)
        return result;
    result = Final(&state, hashval);
    return result;
}
