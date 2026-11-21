/*
 * ***************************************************************************************************
 * WaMMErrorMessage.c ($RCSfile: $)
 *
 * Allocate the reference to the external variable _WaMM_ErrorMesssage
 *
 * Copyright 2008 John Washburn.  All rights reserved until I win the SHA3 contest.
 *
 *
 * ***************************************************************************************************

$Header: $

$Revision: $

$Log: $

 *
 */

#include <stdlib.h>
#include <memory.h>
#include "WaMMErrorMessage.h"

HashReturn _WaMM_ErrorCode = NOT_IMPLEMENTED;
char *_WaMM_ErrorMesssage = NULL;

HashReturn InitErrorMessageBuffer(void)
{
	HashReturn retVal = ERORR_MALLOC_ERROR_MSG_BUFFER;

	_WaMM_ErrorMesssage = (char*) malloc(WaMM_ErrorMessageBufferSize);
	if (NULL != _WaMM_ErrorMesssage)
	{
		memset(_WaMM_ErrorMesssage, 0, WaMM_ErrorMessageBufferSize);
		retVal = SUCCESS;
	}

	return retVal;
}


