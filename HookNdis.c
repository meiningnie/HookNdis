/*++

Module Name:

	HookNdis.c


Abstract:

	Hooks NDIS routines and filters network packets.


Author:

	xiaonie

	2012/07/12


--*/
#include <ntddk.h>
#include <ndis.h>

#include "HookNdis.h"
#include "RabbitHole.h"

LIST_ENTRY g_linkListHead;
KSPIN_LOCK g_lock;

NDIS_HANDLE g_PacketPool = NULL;
NDIS_HANDLE g_BufferPool = NULL;

NTSTATUS
DriverEntry (
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryString
	)
/*++

Routine Description:

	Diver entry point. Initializes global variables and complete hook operation.


Arguments:

	DriverObject - A pointer to this driver, provided by system.

	RegistryString - A pointer to register path used by this driver, provided by system.


Return Value:

	Returns corresponding NTSTATUS to indicate success or failure.


Author:

	xiaonie

	2012/07/12


--*/
{
	NTSTATUS status;
	DbgPrint("NDIS Hook ------ start!\r\n");

	// check os version
	if (OS_VERSION_XP != GetOsVersion()) {
		DbgPrint("Only XP supported!\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	// setup unload routine for this driver
	DriverObject->DriverUnload = OnUnload;

	// init global viaribles.
	KeInitializeSpinLock(&g_lock);
	InitializeListHead(&g_linkListHead);

	NdisAllocatePacketPool(&status,&g_PacketPool, 0x1000, PROTOCOL_RESERVED_SIZE_IN_PACKET);
	if (status != NDIS_STATUS_SUCCESS/* || g_PacketPool == NULL*/) {
		DbgPrint("alloc packet pool failed!\r\n");
		return status;
	}

	NdisAllocateBufferPool(&status, &g_BufferPool, 0x10);
	if(status != NDIS_STATUS_SUCCESS/* || g_BufferPool == NULL*/) {
		DbgPrint("alloc buffer pool failed!\r\n");
		NdisFreePacketPool(g_PacketPool);
		return status;
	}

	// hook nids routines
	status = HookNdis();

	if (!NT_SUCCESS(status)) {
		DbgPrint("HookNdis failed!\r\n");
		NdisFreeBufferPool(g_BufferPool);
		NdisFreePacketPool(g_PacketPool);
	}
	return status;
}

VOID
OnUnload (
	IN PDRIVER_OBJECT DriverObject
	)
/*++

Routine Description:

	Diver exit point. Releases resources and unhooks NDIS routines.


Arguments:

	DriverObject - A pointer to this driver, provided by system.


Return Value:

	None.


Author:

	xiaonie

	2012/07/12


--*/
{
	PLIST_ENTRY pEntry;
	PNDIS_HOOK_LIST_NODE pNdisHookListNode;
	PNDIS_OPEN_BLOCK pOpenBlock;
	LARGE_INTEGER interval;

	// unhook NDIS routines
	while (TRUE) {
		pEntry = ExInterlockedRemoveHeadList(&g_linkListHead, &g_lock);
		if (pEntry == NULL)
			break;
		pNdisHookListNode = CONTAINING_RECORD(pEntry, NDIS_HOOK_LIST_NODE, ListEntry);

		pOpenBlock = pNdisHookListNode->pOpenBlock;

		InterlockedExchange((PLONG)&pOpenBlock->ReceiveHandler, (LONG)pNdisHookListNode->ulRealReceiveHandler);
		// InterlockedExchange((PLONG)&pOpenBlock->WanReceiveHandler, (LONG)pNdisHookListNode->ulRealWanReceivePacketHandler);
		InterlockedExchange((PLONG)&pOpenBlock->ReceivePacketHandler, (LONG)pNdisHookListNode->ulRealProtocolReceiveHandler);
		InterlockedExchange((PLONG)&pOpenBlock->TransferDataCompleteHandler, (LONG)pNdisHookListNode->ulRealTransferDataCompleteHandler);

		// release memory
		ExFreePoolWithTag(pNdisHookListNode, '!nmN');
	}

	// wait 5 sec, reduce the possibility of BSOD.
	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);
	interval.QuadPart = - 5L * 10L * 1000L * 1000L;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);

	NdisFreeBufferPool(g_BufferPool);
	NdisFreePacketPool(g_PacketPool);

	DbgPrint("NDIS Hook ------ end!\r\n");
}


ULONG GetOsVersion()
/*++

Routine Description:

	Gets OS Version


Arguments:

	None.


Return Value:

	returns OS Version.


Author:

	xiaonie

	2012/07/12


--*/
{
	ULONG ulOsVersion;
	RTL_OSVERSIONINFOW OsVersionInfo;

	OsVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	if (!NT_SUCCESS(RtlGetVersion(&OsVersionInfo)))
		return OS_VERSION_ERROR;

	switch (OsVersionInfo.dwBuildNumber) {
	case 2195:
		ulOsVersion = OS_VERSION_2000;
		break;

	case 2600:
		ulOsVersion = OS_VERSION_XP;
		break;

	case 3790:
		ulOsVersion = OS_VERSION_SERVER_2003;
		break;

	case 6000:
		ulOsVersion = OS_VERSION_VISTA;
		break;

	case 6001:
		ulOsVersion = OS_VERSION_VISTA_SP1;
		break;

	case 6002:
		ulOsVersion = OS_VERSION_VISTA_SP2;
		break;

	case 7600:
		ulOsVersion = OS_VERSION_WIN7;
		break;

	case 7601:
		ulOsVersion = OS_VERSION_WIN7_SP1;
		break;

	default:
		ulOsVersion = OS_VERSION_ERROR;
	}
	return ulOsVersion;
}



NTSTATUS HookNdis ()
/*++

Routine Description:

	Hooks NDIS routines.


Arguments:

	None.


Return Value:

	returns corresponding NTSTATUS to indicate success or failure.


Author:

	xiaonie

	2012/07/12


--*/
{
	ULONG ulProtocolPtr;
	NDIS_HANDLE hFakeProtocol = NULL;
	PNDIS_OPEN_BLOCK pNdisOpenBlock = NULL;
	PNDIS_HOOK_LIST_NODE pNode;
	ULONG ulMagic = 0x10;  // Hardcoded offset. Only valid with NDIS 5.0, Windows XP.
	NTSTATUS status;

	// register a fake NDIS protocol in older to obtain a pointer to the NdisOpenBlock structure.
	hFakeProtocol = RegisterFakeNDISProtocol();

	if (hFakeProtocol == NULL)
		return STATUS_UNSUCCESSFUL;

	ulProtocolPtr = *(PULONG)((ULONG)hFakeProtocol + ulMagic);

	// traverse NDIS protocols to hook all the protocol routines.
	while (ulProtocolPtr != 0) {

		pNdisOpenBlock = *(PNDIS_OPEN_BLOCK *)ulProtocolPtr;

		if (pNdisOpenBlock != NULL) {

			pNode = (PNDIS_HOOK_LIST_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(NDIS_HOOK_LIST_NODE), '!nmN');

			if (pNode != NULL) {
				// save real routines for filtering and unhooking.
				//pNode->MacHandle = *(PVOID *)pNdisOpenBlock;
				//pNode->ProtocolBindingContext = *(NDIS_HANDLE *)((ULONG)pNdisOpenBlock + 16);
				//pNode->MacBindingHandle = *(NDIS_HANDLE *)((ULONG)pNdisOpenBlock + 4);
				//pNode->pOpenBlock = pNdisOpenBlock;

				// pNode->MacHandle = pNdisOpenBlock->MacHandle;
				pNode->ProtocolBindingContext = pNdisOpenBlock->Reserved8;
				pNode->MacBindingHandle = pNdisOpenBlock->BindingHandle;
				pNode->pOpenBlock = pNdisOpenBlock;

				// Hook NDIS protocols
				pNode->ulRealReceiveHandler = (ULONG)InterlockedExchange((PLONG)&pNdisOpenBlock->ReceiveHandler, (LONG)FakeNDISReceiveHandler);
				// pNode->ulRealWanReceivePacketHandler = (ULONG)InterlockedExchange((PLONG)&pNdisOpenBlock->WanReceiveHandler, (LONG)FakeNDISWanReceivePacketHandler);
				pNode->ulRealProtocolReceiveHandler = (ULONG)InterlockedExchange((PLONG)&pNdisOpenBlock->ReceivePacketHandler, (LONG)FakeNDISProtocolReceiveHandler);
				pNode->ulRealTransferDataCompleteHandler = (ULONG)InterlockedExchange((PLONG)&pNdisOpenBlock->TransferDataCompleteHandler, (LONG)FakeNDISTransferDataCompleteHandler);

				ExInterlockedInsertTailList(&g_linkListHead, &pNode->ListEntry, &g_lock);
			}
		}
		ulProtocolPtr = ulProtocolPtr + ulMagic;
		ulProtocolPtr = *(PULONG)ulProtocolPtr;
	}

	// unregister the fake NDIS protocol.
	NdisDeregisterProtocol(&status, hFakeProtocol);

	return STATUS_SUCCESS;
}





NDIS_HANDLE RegisterFakeNDISProtocol ()
/*++

Routine Description:

	Registers a fake NDIS routines.


Arguments:

	None.


Return Value:

	Handle to the fake NDIS protocol if successful, otherwise returns NULL.


Author:

	xiaonie

	2012/07/12


--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	NDIS_HANDLE hFakeProtocol = NULL;
	NDIS_PROTOCOL_CHARACTERISTICS FakeProtocol;
	NDIS_STRING ProtocolName;

	NdisZeroMemory(&FakeProtocol, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));
	FakeProtocol.MajorNdisVersion = 0x05;
	FakeProtocol.MinorNdisVersion = 0x00;

	NdisInitUnicodeString(&ProtocolName, L"FakeProtocol");
	FakeProtocol.Name = ProtocolName;
	FakeProtocol.ReceiveHandler = FakeNdisProtocolReceive;
	FakeProtocol.BindAdapterHandler = FakeBind;
	FakeProtocol.UnbindAdapterHandler = FakeUnBind;

	NdisRegisterProtocol(&status, &hFakeProtocol, &FakeProtocol,
		sizeof(NDIS50_PROTOCOL_CHARACTERISTICS));

	if (status == STATUS_SUCCESS) {
		return hFakeProtocol;
	} else {
		DbgPrint("RegisterFakeNDISProtocol failed: 0x%08x!\r\n", status);
		return NULL;
	}
}





NDIS_STATUS
FakeNDISReceiveHandler (
	NDIS_HANDLE ProtocolBindingContext,
	NDIS_HANDLE MacReceiveContext,
	PUCHAR pHeaderBuffer,
	UINT HeaderBufferSize,
	PUCHAR pLookaheadBuffer,
	UINT LookaheadBufferSize,
	UINT PacketSize
	)
/*++

Routine Description:

	Filters network packets received.


Arguments:

	ProtocolBindingContext - ...

	MacReceiveContext - ...

	pHeaderBuffer - packet header

	HeaderBufferSize - packet header length

	pLookaheadBuffer - look ahead buffer after packet header

	LookaheadBufferSize - length of look ahead buffer

	PacketSize - length of packet, exclude packet header


Return Value:

	...


Author:

	xiaonie

	2012/07/12


--*/
{
	PLIST_ENTRY pEntry;
	PNDIS_HOOK_LIST_NODE pNode;
	KIRQL irql;
	ULONG ulFunAddr = 0;
	// PVOID MacHandle = NULL;
	NDIS_STATUS status = NDIS_STATUS_SUCCESS;
	PNDIS_PACKET pNdisPacket = NULL;
	PNDIS_BUFFER pNdisBuffer = NULL;
	PUCHAR pBuffer = NULL;
	ULONG ulLen;
	KEVENT evt;

	KeAcquireSpinLock(&g_lock, &irql);
	for (pEntry = g_linkListHead.Flink; pEntry != &g_linkListHead; pEntry = pEntry->Flink) {
		pNode = CONTAINING_RECORD(pEntry, NDIS_HOOK_LIST_NODE, ListEntry);
		if (pNode->ProtocolBindingContext == ProtocolBindingContext) {
			ulFunAddr = pNode->ulRealReceiveHandler;
			// MacHandle = pNode->MacHandle;
			break;
		}
	}
	KeReleaseSpinLock(&g_lock, irql);

	if (ulFunAddr == 0) {
		DbgPrint("\r\n Attention: FunAddr == 0(0: FakeNDISReceiveHandler)\r\n");
		// return NDIS_STATUS_SUCCESS;
		return NDIS_STATUS_NOT_ACCEPTED;
	}


	////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	if (PacketSize + HeaderBufferSize < PacketSize || PacketSize < LookaheadBufferSize) {	// PacketSize not valid
		DbgPrint("\r\n Attention: PacketSize not valid!(0: FakeNDISReceiveHandler)\r\n");
		return NDIS_STATUS_NOT_ACCEPTED;
	}

	// allocate buffer to hold network packet
	status = NdisAllocateMemoryWithTag(&pBuffer, HeaderBufferSize + PacketSize, '!nmN');
	if (status != NDIS_STATUS_SUCCESS/* || pBuffer == NULL*/)
		return NDIS_STATUS_NOT_ACCEPTED;

	// copy packet header to buffer
	NdisMoveMemory(pBuffer, pHeaderBuffer, HeaderBufferSize);

	if (PacketSize == LookaheadBufferSize)		// Lookahead buffer contains a complete packet
	{
		//
		//	path 1 of 3, tested ok!
		//
		NdisMoveMemory(pBuffer + HeaderBufferSize, pLookaheadBuffer, PacketSize);

		// do the filtering work
		if (TRUE == RabbitHole(pBuffer, HeaderBufferSize + PacketSize)) {
			NdisFreeMemory(pBuffer, 0, 0);
			return NDIS_STATUS_NOT_ACCEPTED;
		}

		NdisFreeMemory(pBuffer, 0, 0);

	}
	else										// Lookahead buffer contains an incomplete packet
	{
		//
		// get the full packet
		//
		// DbgPrint("Get Full Packet!\r\n");

		//if (MacHandle == NULL) {
		//	DbgPrint("MacHandle == NULL!(0: FakeNDISReceiveHandler)\r\n");
		//	NdisFreeMemory(pBuffer, 0, 0);
		//	return NDIS_STATUS_NOT_ACCEPTED;
		//}

		// make pBuffer a NDIS buffer to hold data
		NdisAllocateBuffer(&status, &pNdisBuffer, g_BufferPool, pBuffer + HeaderBufferSize, PacketSize);
		if (status != NDIS_STATUS_SUCCESS/* || pNdisBuffer == NULL*/) {
			DbgPrint("allocate pNdisBuffer(size = %d) failed in FakeNDISReceiveHandler!\r\n", PacketSize);
			NdisFreeMemory(pBuffer, 0, 0);
			return NDIS_STATUS_NOT_ACCEPTED;
		}

		// allocate a NIDS packet to chain buffer in.
		NdisAllocatePacket(&status, &pNdisPacket, g_PacketPool);
		if (status != NDIS_STATUS_SUCCESS/* || pNdisPacket == NULL*/) {
			DbgPrint("allocate pNdisPacket failed in FakeNDISReceiveHandler!\r\n");
			NdisFreeBuffer(pNdisBuffer);
			NdisFreeMemory(pBuffer, 0, 0);
			return NDIS_STATUS_NOT_ACCEPTED;
		}

		NDIS_SET_PACKET_STATUS(pNdisPacket, STATUS_SUCCESS);

		// Bring explosives.
		KeInitializeEvent(&evt, NotificationEvent, FALSE);
		*(PKEVENT *)(pNdisPacket->ProtocolReserved) = &evt;

		NdisChainBufferAtFront(pNdisPacket, pNdisBuffer);

		// try to get complete packet
		NdisTransferData(&status, pNode->pOpenBlock, MacReceiveContext, 0, PacketSize, pNdisPacket, &ulLen);

		if (status == NDIS_STATUS_PENDING) {			// wait for the right time
			//
			// Path 2 of 3, not tested yet! Warning: An Error may occur!
			//
			DbgPrint("NdisTransferData is pending in FakeNDISReceiveHandler!\r\n", status);
			KeWaitForSingleObject(&evt, Executive, KernelMode, FALSE, NULL);
		} else if (status != NDIS_STATUS_SUCCESS) {
			DbgPrint("NdisTransferData failed(status == 0x%08x) in FakeNDISReceiveHandler!\r\n", status);
			NdisFreePacket(pNdisPacket);
			NdisFreeBuffer(pNdisBuffer);
			NdisFreeMemory(pBuffer, 0, 0);
			return NDIS_STATUS_NOT_ACCEPTED;
		}

		//
		// Path 3 of 3, Filtering doesn't seem to work properly.
		//
		// do the filtering work
		if (TRUE == FilterPacket_ReceiveHandler(pBuffer, HeaderBufferSize, pNdisPacket)) {
			NdisFreePacket(pNdisPacket);
			NdisFreeBuffer(pNdisBuffer);
			NdisFreeMemory(pBuffer, 0, 0);
			return NDIS_STATUS_NOT_ACCEPTED;
		}

		NdisFreePacket(pNdisPacket);
		NdisFreeBuffer(pNdisBuffer);
		NdisFreeMemory(pBuffer, 0, 0);
	}

	// call the original NDIS routine.
	__asm {
		pushad;
		push	PacketSize;
		push	LookaheadBufferSize;
		push	pLookaheadBuffer;
		push	HeaderBufferSize;
		push	pHeaderBuffer;
		push	MacReceiveContext;
		push	ProtocolBindingContext;
		mov		eax, ulFunAddr;
		call	eax;
		mov		status, eax;
		popad;
	}

	return status;
}

//NDIS_STATUS
//FakeNDISWanReceivePacketHandler (
//	IN  NDIS_HANDLE             NdisLinkHandle,
//	IN  PUCHAR                  Packet,
//	IN  ULONG                   PacketSize
//	)
//{
//	DbgPrint("\r\n1: FakeNDISWanReceivePacket\r\n");
//	return NDIS_STATUS_SUCCESS;
//}

INT
FakeNDISProtocolReceiveHandler (
	IN NDIS_HANDLE ProtocolBindingContext,
	IN PNDIS_PACKET Packet
	)
{
	PLIST_ENTRY pEntry;
	PNDIS_HOOK_LIST_NODE pNode;
	KIRQL irql;
	ULONG ulFunAddr = 0;
	// NDIS_STATUS status;
	INT nRet;

	KeAcquireSpinLock(&g_lock, &irql);
	for (pEntry = g_linkListHead.Flink; pEntry != &g_linkListHead; pEntry = pEntry->Flink) {
		pNode = CONTAINING_RECORD(pEntry, NDIS_HOOK_LIST_NODE, ListEntry);
		if (pNode->ProtocolBindingContext == ProtocolBindingContext) {
			ulFunAddr = pNode->ulRealProtocolReceiveHandler;
			break;
		}
	}
	KeReleaseSpinLock(&g_lock, irql);

	if (ulFunAddr == 0)
	{
		DbgPrint("\r\n Attention: FunAddr == 0(2: FakeNDISProtocolReceiveHandler)\r\n");
		return 0;
	}

	// do the filtering work
	if (TRUE == FilterPacket_ProtocolReceiveHandler(Packet))
		return 0;

	// call the real NDIS routines
	__asm {
		pushad;
		push	Packet;
		push	ProtocolBindingContext;
		mov		eax, ulFunAddr;
		call	eax;
		mov		nRet, eax;
		popad;
	}
	return nRet;
}


VOID
FakeNDISTransferDataCompleteHandler(
	IN NDIS_HANDLE                  ProtocolBindingContext,
	IN PNDIS_PACKET                 pNdisPacket,
	IN NDIS_STATUS                  TransferStatus,
	IN UINT                         BytesTransferred
	)
/*++

Routine Description:

	Called to signal completion of a pended NdisTransferData.


Arguments:

	ProtocolBindingContext - pointer to open context

	pNdisPacket - our receive packet into which data is transferred

	TransferStatus - status of the transfer

	BytesTransferred - bytes copied into the packet.


Return Value:

	None


Author:

	xiaonie

	2012/07/12
--*/
{
	PLIST_ENTRY pEntry;
	PNDIS_HOOK_LIST_NODE pNode;
	KIRQL irql;
	ULONG ulFunAddr = 0;

	KeAcquireSpinLock(&g_lock, &irql);
	for (pEntry = g_linkListHead.Flink; pEntry != &g_linkListHead; pEntry = pEntry->Flink) {
		pNode = CONTAINING_RECORD(pEntry, NDIS_HOOK_LIST_NODE, ListEntry);
		if (pNode->ProtocolBindingContext == ProtocolBindingContext) {
			ulFunAddr = pNode->ulRealProtocolReceiveHandler;
			break;
		}
	}
	KeReleaseSpinLock(&g_lock, irql);

	if (ulFunAddr == 0)
	{
		DbgPrint("\r\n Attention: FunAddr == 0(4: FakeNDISTransferDataCompleteHandler)\r\n");
		return;
	}

	if (NdisGetPoolFromPacket(pNdisPacket) == g_PacketPool) {
		PKEVENT pEvt = *(PKEVENT *)(pNdisPacket->ProtocolReserved);

		// trigger the right time.
		KeSetEvent(pEvt, IO_NO_INCREMENT, FALSE);

		return;
	}

	// None of our business. call the real NDIS routines
	__asm {
		pushad;
		push	BytesTransferred;
		push	TransferStatus;
		push	pNdisPacket;
		push	ProtocolBindingContext;
		mov		eax, ulFunAddr;
		call	eax;
		popad;
	}
}


////////////////////////////////////////////////////////////////////////
//
// Fake functions used only in hooking
//
VOID
	FakeBind (
	PNDIS_STATUS Status,
	NDIS_HANDLE BindContext,
	PNDIS_STRING DeviceName,
	PVOID SystemSpecific1,
	PVOID SystemSpecific2
	)
{
	return;
}

VOID
	FakeUnBind (
	PNDIS_STATUS Status,
	NDIS_HANDLE ProtocolBindingContext,
	NDIS_HANDLE UnbindContext
	)
{
	return;
}

NDIS_STATUS
	FakeNdisProtocolReceive (
	NDIS_HANDLE ProtocolBindingContext,
	NDIS_HANDLE MacReceiveContext,
	PVOID HeaderBuffer,
	UINT HeaderBufferSize,
	PVOID LookAheadBuffer,
	UINT LookAheadBufferSize,
	UINT PacketSize
	)
{
	return NDIS_STATUS_NOT_ACCEPTED;
}
////////////////////////////////////////////////////////////////////////


BOOLEAN
FilterPacket_ProtocolReceiveHandler (
	PNDIS_PACKET pPacket
	)
/*++

Routine Description:

	Filters network packets for NDISProtocolReceiveHandler.


Arguments:

	pPacket - Pointer to the packet buffer descriptor.


Return Value:

	TRUE: This packet should be blocked.

	FALSE: This packet should pass through.


Author:

	xiaonie

	2012/07/12


--*/
{
	ULONG ulTotalPacketLength;
	PUCHAR pBuffer = NULL;
	BOOLEAN bRet = FALSE;
	NDIS_STATUS status;

	NdisQueryPacket(pPacket, NULL, NULL, NULL, &ulTotalPacketLength);
	if (ulTotalPacketLength == 0)
		return FALSE;

	status = NdisAllocateMemoryWithTag(&pBuffer, ulTotalPacketLength, '!nmN');
	if (status != NDIS_STATUS_SUCCESS/* || pBuffer == NULL*/)
		return FALSE;

	ReadPacket(pPacket, pBuffer, ulTotalPacketLength);

	// filter it!
	bRet = RabbitHole(pBuffer, ulTotalPacketLength);

	NdisFreeMemory(pBuffer, ulTotalPacketLength, 0);

	return bRet;
}


BOOLEAN
FilterPacket_ReceiveHandler (
	PVOID pHeadBuffer,
	ULONG ulHeadSize,
	PNDIS_PACKET pPacket
	)
/*++

Routine Description:

	Filters network packets for NDISReceiveHandler.


Arguments:

	...


Return Value:

	TRUE: This packet should be blocked.

	FALSE: This packet should pass through.


Author:

	xiaonie

	2012/07/12


--*/
{
	ULONG ulPacketSize;
	PUCHAR pBuffer = NULL;
	NDIS_STATUS status;
	PNDIS_BUFFER pFirstBuffer, pNextBuffer;
	BOOLEAN bRet = FALSE;

	NdisQueryPacket(pPacket, NULL, NULL, NULL, &ulPacketSize);
	if (ulPacketSize == 0)
		return FALSE;

	DbgPrint("ulHeadSize == %d, ulPacketSize == %d in FilterPacket_ReceiveHandler!\r\n", ulHeadSize, ulPacketSize);

	status = NdisAllocateMemoryWithTag(&pBuffer, ulPacketSize + ulHeadSize, '!nmN');
	if (status != NDIS_STATUS_SUCCESS/* || pBuffer == NULL */)
		return FALSE;

	//obtain content from the packet
	NdisMoveMemory(pBuffer, pHeadBuffer, ulHeadSize);
	ReadPacket(pPacket, pBuffer + ulHeadSize, ulPacketSize);

	bRet = RabbitHole(pBuffer, ulPacketSize + ulHeadSize);

	NdisFreeMemory(pBuffer, ulPacketSize + ulHeadSize, 0);

	return bRet;
}


VOID
ReadPacket (
	PNDIS_PACKET pPacket,
	PUCHAR pBuffer,
	ULONG ulBufSize
	)
/*++

Routine Description:

	Retrieves the buffer from a buffer descriptor.


Arguments:

	Packet - Pointer to the buffer descriptor.

	pBuffer - Pointer to the buffer.

	ulBufSize - Size of the buffer.

Return Value:

	None.


Author:

	xiaonie

	2012/07/12


--*/
{
	PVOID			pVA;
	PNDIS_BUFFER	pFirstBuffer, pNextBuffer;
	ULONG			ulTotalLength;
	ULONG			ulLen;
	PVOID			pBuf = NULL;
	ULONG			ulCount = 0;

	NdisQueryPacket(pPacket, NULL, NULL, &pFirstBuffer, NULL);
	while (pFirstBuffer != NULL)
	{
		NdisQueryBufferSafe(pFirstBuffer, &pVA, &ulLen, NormalPagePriority);

		if(!pVA)
		{
			// memory not enough
			DbgPrint("pVA == NULL, insufficient memory!\r\n");
			break;
		}
		if (ulCount + ulLen > ulBufSize) {
			DbgPrint("ulCount + ulLen(%d) > ulBufSize(%d)\r\n", ulCount + ulLen, ulBufSize);
			break;
		}

		NdisMoveMemory(pBuffer + ulCount, pVA, ulLen);
		ulCount += ulLen;
		NdisGetNextBuffer(pFirstBuffer,  &pNextBuffer);
		pFirstBuffer = pNextBuffer;
	}

	DbgPrint("ReadPacket: ulBufSize == %d, ulCount == %d\n", ulBufSize, ulCount);

	return;
}




//BOOLEAN
//AllocateReceivePacket (
//	ULONG ulDataSize,
//	PUCHAR * ppBuffer,
//	PNDIS_PACKET * ppPacket
//	)
///*++
//
//Routine Description:
//
//    Allocate buffer and packet, and chain buffer to the packet front.
//
//
//Arguments:
//
//    ulDataSize - total length in bytes of the packet.
//
//    ppBuffer - place to return pointer to allocated buffer
//
//    ppPacket - place to return pointer to allocated packet
//
//
//Return Value:
//
//    TRUE or FALSE, indicating success or failure.
//
//
//Comments:
//
//    buffer and packet are allocated from g_BufferPool and g_PacketPool.
//
//
//--*/
//{
//    PNDIS_PACKET            pNdisPacket = NULL;
//    PNDIS_BUFFER            pNdisBuffer = NULL;
//    PUCHAR                  pDataBuffer = NULL;
//    NDIS_STATUS             status;
//
//	// allocate buffer
//	status = NdisAllocateMemoryWithTag(&pDataBuffer, ulDataSize, '!nmN');
//	if (status != NDIS_STATUS_SUCCESS/* || pDataBuffer == NULL*/) {
//		DbgPrint("allocate pDataBuffer(size = %d) failed in AllocateReceivePacket!\r\n", ulDataSize);
//		return FALSE;
//	}
//
//	// make this an NDIS buffer
//	NdisAllocateBuffer(&status, &pNdisBuffer, g_BufferPool, pDataBuffer, ulDataSize);
//	if (status != NDIS_STATUS_SUCCESS/* || pNdisBuffer == NULL*/) {
//		DbgPrint("allocate pNdisBuffer(size = %d) failed in AllocateReceivePacket!\r\n", ulDataSize);
//		NdisFreeMemory(pDataBuffer, 0, 0);
//		return FALSE;
//	}
//
//	// allocate packet
//	NdisAllocatePacket(&status, &pNdisPacket, g_PacketPool);
//	if (status != NDIS_STATUS_SUCCESS/* || pNdisPacket == NULL*/) {
//		DbgPrint("allocate pNdisPacket failed in AllocateReceivePacket!\r\n");
//		NdisFreeBuffer(pNdisBuffer);
//		NdisFreeMemory(pDataBuffer, 0, 0);
//		return FALSE;
//	}
//
//	NDIS_SET_PACKET_STATUS(pNdisPacket, STATUS_SUCCESS);
//
//	NdisChainBufferAtFront(pNdisPacket, pNdisBuffer);
//
//	*ppBuffer = pDataBuffer;
//	*ppPacket = pNdisPacket;
//
//	return TRUE;
//}
