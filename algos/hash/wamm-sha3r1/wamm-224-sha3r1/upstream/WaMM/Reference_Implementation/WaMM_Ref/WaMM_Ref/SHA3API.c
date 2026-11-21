/*
 * SHA3API.h ($RCSfile: SHA3API.c,v $)
 *
 * Implements the required API elements dictated by the rules of the SHA3 contest.
 *
 * Copyright 2008 John Washburn.  All rights reserved until I win the SHA3 contest.
 
$Header: D:\\RCSArchive\\D\\Programming\\WaMM\\ReferenceImplementation\\WaMM\\WaMM\\SHA3API.c,v 1.7 2008-10-19 08:25:48-05 johnwashburn Exp johnwashburn $
$Revision: 1.7 $

$Log: SHA3API.c,v $
Revision 1.7  2008-10-19 08:25:48-05  johnwashburn
Daily Checkpointing

Revision 1.6  2008-10-13 18:13:55-05  johnwashburn
Daily Check Point

Revision 1.2  2008-10-08 02:25:57-05  johnwashburn
proved comment header block to better use RCS keywords

Revision 1.1  2008-10-08 02:08:03-05  johnwashburn
Added RCS Header Comment block using RCS Keywords.


*/
#include "WaMM.h"
#include "BitArray.h"

/* 
 * Hash in the Update() function in large blocks of data if possible.
 * This constant is platform dependent.  Choose a constant which is as large as possible
 * without causing degradation in the calls to alloc(), malloc(), realloc(), and free().
 */
const long gc_WaMM_SIZE_MessageMemoryBlock_Bytes = 0x100000;	/* process data in 1 megabyte chunks whenever possible */
      long gc_WaMM_SIZE_MessageMemoryBlock_Bits  = 0x800000;	/* (gc_WaMM_SIZE_MessageMemoryBlock_Bytes * WaMM_BitsPerBitSequence) */

HashReturn Init(hashState *pState, int hashbitlen)
{
	HashReturn retVal = FAIL;
	int i, j;

	retVal = InitWaMMEnvironment();
	if (SUCCESS == retVal)
	{
		if (IsHashLengthSupported(hashbitlen))
		{
			if (NULL != pState)
			{
				/* set the hash length variable of ths structure */
				pState->hashbitlen = hashbitlen;

				/* set the Vectors to Size to zero */
				retVal = SUCCESS;
				if (SUCCESS == retVal)
				{
					retVal = InitWaMMVector(pState->MessageLength);
				}
				if (SUCCESS == retVal)
				{
					retVal = InitWaMMVector(pState->InputVector);
				}
				
				if (SUCCESS == retVal)
				{
					/* Set the buffer and data length to a state of: 
					 *		there are no yet-to-be-hashed bits left over from previous calls to Update()
					 */
					pState->pUnprocessedBitArray = NewBitArray(0);
					if (NULL != pState->pUnprocessedBitArray)
					{
						/* use the bytes of the WaMM binary operator to initialize the state matrix. */
						for (i = 0; i < WaMM_MatrixDimension; ++i)
						{
							for (j = 0; j < WaMM_MatrixDimension; ++j)
							{
								 pState->stateMatrix[i][j] = gc_WaMMOperator[i][j];
							}
						}

						/* set the other variables of this structure */
						pState->BitsProcessed = 0;
						pState->iCurrRow = 0;

						retVal = SUCCESS;
					}
					else
					{
						retVal = _WaMM_ErrorCode;
					}
				}
			}
			else
			{
				retVal = ERORR_NULL_STATE_POINTER;
			}
		}
		else
		{
			retVal = BAD_HASHLENGTH;
		}
	}

	if (g_bDumpIntermediateStates &&
		(SUCCESS == retVal))
	{
		sprintf(_WaMM_ErrorMesssage, "\fInitialized Hash State");
		WaMM_DumpState(pState, _WaMM_ErrorMesssage);
	}

	return retVal;
}

HashReturn Update(hashState *pState, const BitSequence *pData, DataLength databitlen)
{
	HashReturn retVal = FAIL;
	const BitSequence *pNextBlock = pData;
	DataLength llBitsRemaining = databitlen;

	/* a negative bit length is an error */
	if (0 > databitlen)
	{
		retVal = ERORR_NEGATVELEN_BITARRAY;
	}
	else if (0 < databitlen)
	{
		if (NULL != pState)
		{
			if (IsHashLengthSupported(pState->hashbitlen))
			{
				if (NULL != pData)
				{
					retVal = SUCCESS;
					pState->BitsProcessed = 0;

					/* process the incoming data in large, but smaller chunks */
					while ((SUCCESS == retVal) && 
						   (gc_WaMM_SIZE_MessageMemoryBlock_Bytes <= llBitsRemaining))
					{
						retVal = UpdateOneMemoryBlock(pState, pNextBlock, gc_WaMM_SIZE_MessageMemoryBlock_Bits);
						pNextBlock += gc_WaMM_SIZE_MessageMemoryBlock_Bytes;
						llBitsRemaining -= (DataLength) gc_WaMM_SIZE_MessageMemoryBlock_Bits;
					}

					if (SUCCESS == retVal)
					{
						/* If there is still some incoming data, then process the last chunk */
						if (0 < llBitsRemaining)
						{
							assert(llBitsRemaining <= LONG_MAX);
							retVal = UpdateOneMemoryBlock(pState, pNextBlock, (long) llBitsRemaining);
						}
					}

					if (SUCCESS == retVal)
					{
						retVal = AddToMessageSize(pState, pState->BitsProcessed);
					}
				}
				else
				{
					retVal = ERORR_NULL_HASHDATA_POINTER;
				}
			}
			else
			{
				retVal = BAD_HASHLENGTH;
			}
		}
		else
		{
			retVal = ERORR_NULL_STATE_POINTER;
		}
	}
	else
	{
		/* 
		 * Process any data still awaiting to be hashed.
		 */
		retVal = SUCCESS;
	}

	return retVal;
}

HashReturn Final(hashState *pState, BitSequence *pHashval)
{
	HashReturn retVal = FAIL;
	int iNumHashBytes;
	int iIndex;
	int iPrimeOffset;
	int iPrimeMultiplier;
	int n, r;
	div_t stateIndex;

	if (NULL != pState)
	{
		if (NULL != pHashval)
		{
			if (IsHashLengthSupported(pState->hashbitlen))
			{
				if (g_bDumpIntermediateStates)
				{
					fprintf(g_fileDumpIntermediate, "\fBegin Finalization\n");
				}

				/* process any remaining unprocessed message bits */
				if (0 < pState->pUnprocessedBitArray->lNumBits)
				{
					if (g_bDumpIntermediateStates)
					{
						fprintf(g_fileDumpIntermediate, "Process Reminder of Message\n");
					}
					retVal = AddToMessageSize(pState, pState->pUnprocessedBitArray->lNumBits);
					if (SUCCESS == retVal)
					{
						retVal = PopPartialVectorFromBitArray( pState->pUnprocessedBitArray, pState->InputVector);
						if (SUCCESS == retVal)
						{
							retVal = WaMMRoundFunction(pState);
						}
					}
				}
				else
				{
					retVal = SUCCESS;
				}
				if (SUCCESS == retVal)
				{
					if (g_bDumpIntermediateStates)
					{
						fprintf(g_fileDumpIntermediate, "Process Message length\n");
					}
					/* Process Message length in bits as if it were another block of data */
					memmove(pState->InputVector, 
						    pState->MessageLength, 
							WaMM_VectorLength_BitSequences);
					retVal = WaMMRoundFunction(pState);
					if (SUCCESS == retVal)
					{
						/* If the round function from processing the message length did not invoke a squaring
						 * perform a squaring of the StateMatrix to insure the message length and the last bits
						 * of the incoming message are mixed into the state matrix.
						 */
						if (0 != pState->iCurrRow)
						{
							retVal = WaMMSquare(pState);
						}
						if (SUCCESS == retVal)
						{
							/*
							 * tap the bytes of the state matrix to form the N-byte hash value.
							 */
							iNumHashBytes = pState->hashbitlen / WaMM_BitsPerByte;
							iIndex = pState->hashbitlen / WaMM_HashLen_BitLengthModulus;
							iPrimeOffset = gc_TappingPrime[iIndex];
							iPrimeMultiplier = gc_TappingPrime[iIndex - 2];

							if (g_bDumpIntermediateStates)
							{
								fprintf(g_fileDumpIntermediate, "\fTapping Sequence:");
								fprintf(g_fileDumpIntermediate, "Number of bytes in hash value = %d\n", iNumHashBytes);
								fprintf(g_fileDumpIntermediate, "iIndex = floor(%d / %d) = %d\n", pState->hashbitlen, WaMM_HashLen_BitLengthModulus, iIndex);
								fprintf(g_fileDumpIntermediate, "r = ((%d * n) + %d ) mod %d\n", iPrimeMultiplier, iPrimeOffset, WaMM_NumBytesStateMatrix);
							}

							for(n = 0; n < iNumHashBytes; ++n)
							{
								r  = n*iPrimeMultiplier + iPrimeOffset;
								r %= WaMM_NumBytesStateMatrix;
								stateIndex = div(r, WaMM_MatrixDimension);
								pHashval[n] = pState->stateMatrix[stateIndex.quot][stateIndex.rem];

								if (g_bDumpIntermediateStates)
								{
									fprintf(g_fileDumpIntermediate, "[n,r] = [%3d, %3d].  HashByte[%3d] = StateMatrix[%2d][%2d] = 0x%2.2X\n", n,r, n, stateIndex.quot, stateIndex.rem, pHashval[n]);
								}
							}

							/* The hashing is done and so is the need for the allocated BitArray */
							if (NULL != pState->pUnprocessedBitArray);
							{
								/* Dispose of exising Bit Array if Present */
								FreeBitArray(pState->pUnprocessedBitArray);
							}
							pState->pUnprocessedBitArray = NULL;
						}
					}
				}
			}
			else
			{
				retVal = BAD_HASHLENGTH;
			}
		}
		else
		{
			retVal = ERORR_NULL_HASHVALUE_POINTER;
		}
	}
	else
	{
		retVal = ERORR_NULL_STATE_POINTER;
	}

	if (g_bDumpIntermediateStates &&
		(SUCCESS == retVal))
	{
		sprintf(_WaMM_ErrorMesssage, "\fFinal Hash State");
		WaMM_DumpState(pState, _WaMM_ErrorMesssage);
	}

	return retVal;
}

HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	HashReturn retVal = FAIL;
	hashState State;
	int i;

	if (IsHashLengthSupported(hashbitlen))
	{
		if (NULL != hashval)
		{
			if (NULL != data)
			{
				retVal = Init(&State, hashbitlen);
				if (SUCCESS == retVal)
				{
#if 2 <= WAMM_DEBUGGING_LEVEL
		WaMM_DumpState(&State, "\fInitialization");
#endif

					retVal = Update(&State, data, databitlen);
					if (SUCCESS == retVal)
					{
#if 2 <= WAMM_DEBUGGING_LEVEL
		WaMM_DumpState(&State, "\fUpdate");
#endif
						if (SUCCESS == retVal)
						{
							retVal = Final(&State, hashval);
#if 2 <= WAMM_DEBUGGING_LEVEL
		WaMM_DumpState(&State, "\fFinalized");
#endif
						}
					}
				}
			}
			else
			{
				retVal = ERORR_NULL_INPUT_POINTER;
			}
		}
		else
		{
			retVal = ERORR_NULL_HASHVALUE_POINTER;
		}
	}
	else
	{
		retVal = ERORR_NULL_STATE_POINTER;
	}

#if 2 <= WAMM_DEBUGGING_LEVEL
	if (SUCCESS == retVal)
	{
		printf("[");
		for(i = 0; i < hashbitlen / WaMM_BitsPerByte; ++i)
		{
			printf("%2.2X ", hashval[i]);
		}
		printf("] %d-Bit HashValue\n", hashbitlen);
	}
#endif
#if 1 <= WAMM_MEMORY_DEBUGGING
		printf("Hash()\tFinished\n\n");
#endif

	return retVal;
}

