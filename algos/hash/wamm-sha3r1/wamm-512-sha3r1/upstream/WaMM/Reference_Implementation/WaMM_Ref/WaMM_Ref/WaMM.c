/*
 * WaMM.c ($RCSfile: WaMM.c,v $)
 *
 * The bulk of the code fro the reference implementation of the WaMM Hashing algorithm is in this file.
 *
 * Copyright 2008 John Washburn.  All rights reserved until I win the SHA3 contest.
 
$Header: D:\\RCSArchive\\D\\Programming\\WaMM\\ReferenceImplementation\\WaMM\\WaMM\\WaMM.c,v 1.7 2008-10-19 08:25:50-05 johnwashburn Exp johnwashburn $
$Revision: 1.7 $

$Log: WaMM.c,v $
Revision 1.7  2008-10-19 08:25:50-05  johnwashburn
Daily Checkpointing

Revision 1.6  2008-10-13 18:13:54-05  johnwashburn
Daily Check Point

Revision 1.2  2008-10-08 02:26:17-05  johnwashburn
Improved comment header block to better use RCS keywords

Revision 1.1  2008-10-08 02:08:03-05  johnwashburn
Added RCS Header Comment block using RCS Keywords.


*/
#include "WaMM.h"
#include "WaMMOperator.h"
#include "WaMMTappingPrimes.h"
#include "WaMMErrorMessage.h"
#include "BitArray.h"
#include "ReverseBits.h"

/* 
 * Set the storage location of the global variable for dumping intermediate states here and
 * set the default value to FALSE: i.e. No, don't dump intermediate states to stdout.
 */
BOOL g_bDumpIntermediateStates = FALSE;
FILE *g_fileDumpIntermediate = NULL;

HashReturn InitWaMMEnvironment()
{
	HashReturn retVal = FAIL;

	retVal = EnableBitArrays();
	if (SUCCESS == retVal)
	{
		retVal = InitErrorMessageBuffer();
		if (SUCCESS == retVal)
		{
			; /* NULL Statement.  Add the next Layer of initialization here. */
		}
	}

	return retVal;
}


BOOL IsHashLengthSupported(int hashbitlen)
{
	BOOL bIsSupported = FALSE;

/* Decide if the hash length is at least in range */
	if ((WaMM_HashLen_MaxBitLength < hashbitlen) ||
		(WaMM_HashLen_MinBitLength > hashbitlen))
	{
		sprintf(_WaMM_ErrorMesssage, "Hash bitlength of %d must be between %d and %d; inclusive.\n", hashbitlen, WaMM_HashLen_MinBitLength, WaMM_HashLen_MaxBitLength);
	}
	else
	{
		int iRemainder = hashbitlen % WaMM_HashLen_BitLengthModulus;
		if (0 < iRemainder)
		{
			sprintf(_WaMM_ErrorMesssage, "Hash bitlength of %d must be a multiple of %d.\n", hashbitlen, WaMM_HashLen_BitLengthModulus);
		}
		else
		{
			bIsSupported = TRUE;
		}
	}


	return bIsSupported;
}

HashReturn WaMM_DumpState(hashState *pState, char *szMessagePrefix)
{
	HashReturn retVal = FAIL;
	int iIndex, iRow, iCol;

	if (NULL != pState)
	{
		retVal = SUCCESS;

		if (NULL == g_fileDumpIntermediate)
		{
			g_fileDumpIntermediate = stdout;
		}

		if (NULL != szMessagePrefix)
		{
			fprintf(g_fileDumpIntermediate, "%s\n", szMessagePrefix);
		}

		fprintf(g_fileDumpIntermediate, "HashLength = %d bits.\n", pState->hashbitlen);
		fprintf(g_fileDumpIntermediate, "BitsProcessed = %lX bits.\n", pState->BitsProcessed);
		fprintf(g_fileDumpIntermediate, "Current Row of State Matrix = %d.\n", pState->iCurrRow);

		fprintf(g_fileDumpIntermediate, "[");
		for(iIndex = 0; iIndex < WaMM_VectorLength_Bytes; ++iIndex)
		{
			if ((0 == (iIndex % 4)) &&
				(0 != iIndex))
			{
				fprintf(g_fileDumpIntermediate, "| ");
			}
			fprintf(g_fileDumpIntermediate, "%2.2X ", pState->InputVector[iIndex]);
		}
		fprintf(g_fileDumpIntermediate, "] Input Vector.\n");

		fprintf(g_fileDumpIntermediate, "[");
		for(iIndex = 0; iIndex < WaMM_VectorLength_Bytes; ++iIndex)
		{
			if ((0 == (iIndex % 4)) &&
				(0 != iIndex))
			{
				fprintf(g_fileDumpIntermediate, "| ");
			}
			fprintf(g_fileDumpIntermediate, "%2.2X ", pState->MessageLength[iIndex]);
		}
		fprintf(g_fileDumpIntermediate, "] Message Length.\n");

		BitArrayToSring(pState->pUnprocessedBitArray, _WaMM_ErrorMesssage);
		fprintf(g_fileDumpIntermediate, "%s pUnprocessedBitArray.\n", _WaMM_ErrorMesssage);

		fprintf(g_fileDumpIntermediate, "\n");

		fprintf(g_fileDumpIntermediate, "[");
		for(iRow = 0; iRow < WaMM_MatrixDimension; ++iRow)
		{
			if (0 < iRow)
			{
				fprintf(g_fileDumpIntermediate, " ");
			}
			for(iCol = 0; iCol < WaMM_MatrixDimension; ++iCol)
			{
				if ((0 == (iCol % 4)) &&
					(0 != iCol))
				{
					fprintf(g_fileDumpIntermediate, "| ");
				}
				fprintf(g_fileDumpIntermediate, "%2.2X ", pState->stateMatrix[iRow][iCol]);
			}
			if (WaMM_MatrixDimension - 1 == iRow)
			{
				fprintf(g_fileDumpIntermediate, "] StateMatrix ");
			}
			fprintf(g_fileDumpIntermediate, "\n");
		}
	}
	else
	{
		retVal = ERORR_NULL_STATE_POINTER;
	}

	return retVal;
}

HashReturn InitWaMMVector(WaMM_DataVector pVector)
{
	HashReturn retVal = FAIL;

	if (NULL != pVector)
	{
		memset(pVector, 0, WaMM_VectorLength_BitSequences);
		retVal = SUCCESS;
	}
	else
	{
		retVal = ERORR_INITALIZE_NULL_VECTOR;
	}
	return retVal;
}

HashReturn CopyWaMMVector(WaMM_DataVector pDestinationVector, WaMM_DataVector pSourceVector)
{
	HashReturn retVal = FAIL;
	int i;

	if (NULL != pDestinationVector)
	{
		if (NULL != pDestinationVector)
		{
			for (i = 0; i < WaMM_VectorLength_Bytes; ++i)
			{
				pDestinationVector[i] = pSourceVector[i];
			}

			retVal = SUCCESS;
		}
		else
		{
			retVal = ERORR_COPY_NULL_VECTOR;
		}
	}
	else
	{
		retVal = ERORR_COPY_NULL_VECTOR;
	}

	return retVal;
}

HashReturn UpdateOneMemoryBlock(hashState *pState, const BitSequence *pData, long lBitsInBlock)
{
	HashReturn retVal = FAIL;
	BitArray *pBitArrayIncomingData = NULL;

	/* a negative bit length is an error */
	if (0 > lBitsInBlock)
	{
		retVal = ERORR_NEGATVELEN_BITARRAY;
	}
	else if (0 < lBitsInBlock)
	{
		if (NULL != pState)
		{
			if (IsHashLengthSupported(pState->hashbitlen))
			{
				if (NULL != pData)
				{
					// retVal = InitWaMMVector(pState->InputVector);
					retVal = InitWaMMVector(pState->InputVector);
					if (SUCCESS == retVal)
					{
						/* convert incoming bit sequence into a BitArray struct */
						pBitArrayIncomingData = BitArrayFromBitSequence(lBitsInBlock, pData);
						if (NULL != pBitArrayIncomingData)
						{
							/* Add the BitArray of the incoming bits to pUnprocessedBitArray */
							retVal = ConcatenateBitArray(pState->pUnprocessedBitArray, pBitArrayIncomingData);
							if (SUCCESS == retVal)
							{
								/* while full vectors of data exist within the incoming data
								 * transfer the full vectors to the and hash them
								 */
								while ((WaMM_VectorLength_Bits <= pState->pUnprocessedBitArray->lNumBits) &&
										(SUCCESS == retVal))
								{
									retVal = PopWholeVectorFromBitArray( pState->pUnprocessedBitArray, pState->InputVector);
									if (SUCCESS == retVal)
									{
										retVal = WaMMRoundFunction(pState);
										pState->BitsProcessed += WaMM_VectorLength_Bits;
									}
								}
							}
							FreeBitArray(pBitArrayIncomingData);
						}
						else
						{
							retVal = ERORR_MALLOC_BITARRAY;
						}
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
		/* Processing Zero Incoming bits is a NULL operation.  the state matrix is unchanged. */
		retVal = SUCCESS;
	}

	return retVal;
}

HashReturn AddToMessageSize(hashState *pState, DataLength databitlen)
{
	HashReturn retVal = FAIL;
	DataLength PrevSum;
	DataLength CurrSum;
	DataLength Carry = databitlen;
	DataLength *pNumber;
	int iIndex;
	int iNumNumbersInDataVector;

	if (NULL != pState)
	{
		if (0 > databitlen)
		{
			retVal = ERORR_NEGATVELEN_BITARRAY;
		}
		else if (0 < databitlen)
		{
			iNumNumbersInDataVector = WaMM_VectorLength_Bits / (sizeof(DataLength) * CHAR_BIT);
			for(iIndex = iNumNumbersInDataVector -1 ; (0 < Carry) && (0 <= iIndex); --iIndex)
			{
				/* Cast the DataVector in Message Length to an array of type DataLength
				 * The get the address of the number in the array of DataLength.
				 * If Little endian addressing is used, then you need to reverse the bytes to convert properly from
				 * little endian number of type DataLength into big-endian bit-sequences.
				 */
				pNumber = &(((DataLength *) pState->MessageLength)[iIndex]);
				PrevSum = *pNumber; 
				if (WaMM_LITTLE_ENDIAN)
				{
					PrevSum = ReverseBytesULongLong(PrevSum);
				}
				CurrSum = PrevSum + Carry;

				/* check for overflow in unsigned addition.  If found the a Carry to the next DataLength in the has occured. */
				if (CurrSum < PrevSum)
				{
					Carry = 1;
				}
				else
				{
					Carry = 0;
				}

				if (WaMM_LITTLE_ENDIAN)
				{
					CurrSum = ReverseBytesULongLong(CurrSum);
				}
				*pNumber = CurrSum;
			}

			retVal = SUCCESS;
		}
		else
		{
			/* adding zero is an easy success */
			retVal = SUCCESS;
		}
	}
	else
	{
		retVal = ERORR_NULL_STATE_POINTER;
	}
	
	return retVal;
}

HashReturn WaMMSquare(hashState *pState)
{
	HashReturn retVal = FAIL;
	int iRow, iCol, iIndex;
	int i, j;
	int iRound = 0;
	BYTE btProduct;
	WaMM_StateMatrix smSquared[WaMM_NumberOfRounds+1];

	if (NULL != pState)
	{
		retVal = SUCCESS;

#if 3 <= WAMM_DEBUGGING_LEVEL
		sprintf(_WaMM_ErrorMesssage, "\fBefore Squaring of SM");
		WaMM_DumpState(pState, _WaMM_ErrorMesssage);
#endif
		/* Transfer the current stateMatrix to the the 0 element of the mSquared array*/
		for( iRow = 0; iRow < WaMM_MatrixDimension; ++iRow)
		{
			for( iCol = 0; iCol < WaMM_MatrixDimension; ++iCol)
			{
				smSquared[0][iRow][iCol] = pState->stateMatrix[iRow][iCol];
			}
		}

		if (g_bDumpIntermediateStates)
		{
			sprintf(_WaMM_ErrorMesssage, "Squaring of SM after round 0");
			WaMM_DumpState(pState, _WaMM_ErrorMesssage);
		}

		/* Calculate the square of the matrix, smSquared[n-1], and store the results in smSquared[n]*/
		for( iRound = 1; iRound <= WaMM_NumberOfRounds; ++iRound)
		{
			for( iRow = 0; iRow < WaMM_MatrixDimension; ++iRow)
			{
				for( iCol = 0; iCol < WaMM_MatrixDimension; ++iCol)
				{
					smSquared[iRound][iRow][iCol] = 0;
					for( iIndex = 0; iIndex < WaMM_MatrixDimension; ++iIndex)
					{
						i = smSquared[iRound-1][ iRow ][iIndex];
						j = smSquared[iRound-1][iIndex][ iCol ];
						btProduct = gc_WaMMOperator[i][j];
						smSquared[iRound][iRow][iCol] += btProduct;
					}
				}
			}

			if (g_bDumpIntermediateStates)
			{
				for( iRow = 0; iRow < WaMM_MatrixDimension; ++iRow)
				{
					for( iCol = 0; iCol < WaMM_MatrixDimension; ++iCol)
					{
						pState->stateMatrix[iRow][iCol] = smSquared[iRound][iRow][iCol];
					}
				}
				sprintf(_WaMM_ErrorMesssage, "Squaring of SM after round %d", iRound);
				WaMM_DumpState(pState, _WaMM_ErrorMesssage);
			}
		}

		/* Transfer the last element of the smSquared array back to the stateMatrix */
		iRound = WaMM_NumberOfRounds;
		for( iRow = 0; iRow < WaMM_MatrixDimension; ++iRow)
		{
			for( iCol = 0; iCol < WaMM_MatrixDimension; ++iCol)
			{
				pState->stateMatrix[iRow][iCol] = smSquared[iRound][iRow][iCol];
			}
		}

#if 3 <= WAMM_DEBUGGING_LEVEL
		sprintf(_WaMM_ErrorMesssage, "\fSquaring of SM after round %d", iRound);
		WaMM_DumpState(pState, _WaMM_ErrorMesssage);
#endif

	}
	else
	{
		retVal = ERORR_NULL_STATE_POINTER;
	}

	return retVal;
}



HashReturn WaMMRoundFunction(hashState *pState)
{
	HashReturn retVal = FAIL;
	int iIndex;

	if (NULL != pState)
	{

		retVal = SUCCESS;

		if (g_bDumpIntermediateStates)
		{
			sprintf(_WaMM_ErrorMesssage, "\fInitial State of WaMMRoundFunction");
			WaMM_DumpState(pState, _WaMM_ErrorMesssage);
		}

		for(iIndex = 0; iIndex < WaMM_VectorLength_Bytes; ++iIndex)
		{
			pState->stateMatrix[pState->iCurrRow][iIndex] ^= pState->InputVector[iIndex];
		}

		++pState->iCurrRow;
		pState->iCurrRow %= WaMM_MatrixDimension;

		if (0 == pState->iCurrRow)
		{
			retVal = WaMMSquare(pState);
		}

		if (g_bDumpIntermediateStates &&
			(SUCCESS == retVal))
		{
			sprintf(_WaMM_ErrorMesssage, "\fInternal state after round Function");
			WaMM_DumpState(pState, _WaMM_ErrorMesssage);
		}
	}
	else
	{
		retVal = ERORR_NULL_STATE_POINTER;
	}

	return retVal;
}
