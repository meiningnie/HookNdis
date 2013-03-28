/*++

Module Name:

	RabbitHole.c


Abstract:

	Filters network packets received.


Author:

	xiaonie

	2012/07/12


--*/
#include <ntddk.h>
#include <ndis.h>

#include "RabbitHole.h"


BOOLEAN
RabbitHole(
	IN CONST UCHAR * CONST pBuffer,
	IN CONST ULONG ulBufSize
	)
/*++

Routine Description:

	Filters network packets received.


Arguments:

	pBuffer - Pointer to a buffer containing the network packet.

	ulBufSize - Size of the packet.


Return Value:

	Returns TRUE if you want to block this packet.

	Returns FALSE to let this packet pass through.


Author:

	xiaonie

	2012/07/12


--*/
{
	ULONG i, j;
	PCHAR strTmp = NULL;
	BOOLEAN bRet = FALSE;
	//
	//	Demonstration: block every packet containing "rabbit"
	//
	for (i = 0; i < ulBufSize - 5; ++i)
	{
		if ((pBuffer[i + 0] == 'r' || pBuffer[i + 0] == 'R') &&
			(pBuffer[i + 1] == 'a' || pBuffer[i + 1] == 'A') &&
			(pBuffer[i + 2] == 'b' || pBuffer[i + 2] == 'B') &&
			(pBuffer[i + 3] == 'b' || pBuffer[i + 3] == 'B') &&
			(pBuffer[i + 4] == 'i' || pBuffer[i + 4] == 'I') &&
			(pBuffer[i + 5] == 't' || pBuffer[i + 5] == 'T') )
		{
			// print some message
			DbgPrint("\r\nSomething fall in rabbit hole(%d/%d)!\r\n", i, ulBufSize);
			for (j = 0; j < ulBufSize; ++j) {
				DbgPrint("0x%02x(%c) ", pBuffer[j], pBuffer[j]);
			}
			DbgPrint("\r\n");

			// block this packet
			bRet = TRUE;
		}
	}

	strTmp = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, ulBufSize + 1, '!nmN');
	if (strTmp == NULL) {
		DbgPrint("Look(%d): tragedy!\r\n", ulBufSize);
	} else {
		for (i = 0; i < ulBufSize; ++i) {
			if (pBuffer[i] < 32 || pBuffer[i] > 126) {
				strTmp[i] = '?';
			} else {
				strTmp[i] = pBuffer[i];
			}
		}
		strTmp[ulBufSize] = 0;

		DbgPrint("Look(%d): %s\r\n", ulBufSize, strTmp);

		ExFreePoolWithTag(strTmp, '!nmN');
	}

	return bRet;
}
