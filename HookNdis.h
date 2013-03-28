#ifndef _HOOK_NDIS_H_
#define _HOOK_NDIS_H_


#define MAX_RECV_PACKET_POOL_SIZE    20;

#define OS_VERSION_ERROR		0
#define OS_VERSION_2000			1
#define OS_VERSION_XP			2
#define OS_VERSION_SERVER_2003	3
#define OS_VERSION_VISTA		4
#define OS_VERSION_VISTA_SP1	5
#define OS_VERSION_VISTA_SP2	6
#define OS_VERSION_WIN7			7
#define OS_VERSION_WIN7_SP1		8


typedef struct _NDIS_HOOK_LIST_NODE_ {
	PNDIS_OPEN_BLOCK		pOpenBlock;
	// PVOID					MacHandle;
	NDIS_HANDLE				ProtocolBindingContext;
	NDIS_HANDLE				MacBindingHandle;
	ULONG					ulRealReceiveHandler;
	// ULONG					ulRealWanReceivePacketHandler;
	ULONG					ulRealProtocolReceiveHandler;
	ULONG					ulRealTransferDataCompleteHandler;
	LIST_ENTRY ListEntry;
} NDIS_HOOK_LIST_NODE, *PNDIS_HOOK_LIST_NODE, **PPNDIS_HOOK_LIST_NODE;

extern LIST_ENTRY g_linkListHead;
extern KSPIN_LOCK g_lock;
extern NDIS_HANDLE g_PacketPool;
extern NDIS_HANDLE g_BufferPool;


VOID
FakeBind (
	PNDIS_STATUS Status,
	NDIS_HANDLE BindContext,
	PNDIS_STRING DeviceName,
	PVOID SystemSpecific1,
	PVOID SystemSpecific2
	);

VOID
FakeUnBind (
	PNDIS_STATUS Status,
	NDIS_HANDLE ProtocolBindingContext,
	NDIS_HANDLE UnbindContext
	);

NDIS_STATUS
FakeNdisProtocolReceive (
	NDIS_HANDLE ProtocolBindingContext,
	NDIS_HANDLE MacReceiveContext,
	PVOID HeaderBuffer,
	UINT HeaderBufferSize,
	PVOID LookAheadBuffer,
	UINT LookAheadBufferSize,
	UINT PacketSize
	);

NDIS_HANDLE RegisterFakeNDISProtocol();

NDIS_STATUS
FakeNDISReceiveHandler (
	NDIS_HANDLE ProtocolBindingContext,
	NDIS_HANDLE MacReceiveContext,
	PUCHAR pHeaderBuffer,
	UINT HeaderBufferSize,
	PUCHAR pLookaheadBuffer,
	UINT LookaheadBufferSize,
	UINT PacketSize
	);

//NDIS_STATUS
//FakeNDISWanReceivePacketHandler (
//	IN  NDIS_HANDLE             NdisLinkHandle,
//	IN  PUCHAR                  Packet,
//	IN  ULONG                   PacketSize
//	);

INT
FakeNDISProtocolReceiveHandler (
	IN NDIS_HANDLE ProtocolBindingContext,
	IN PNDIS_PACKET Packet
	);

VOID
FakeNDISTransferDataCompleteHandler(
	IN NDIS_HANDLE                  ProtocolBindingContext,
	IN PNDIS_PACKET                 pNdisPacket,
	IN NDIS_STATUS                  TransferStatus,
	IN UINT                         BytesTransferred
	);

NTSTATUS HookNdis ();


VOID
OnUnload (
	IN PDRIVER_OBJECT DriverObject
	);


NTSTATUS
DriverEntry (
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryString
	);

ULONG GetOsVersion();

BOOLEAN
FilterPacket_ProtocolReceiveHandler (
	PNDIS_PACKET pPacket
	);


BOOLEAN
FilterPacket_ReceiveHandler (
	PVOID pHeadBuffer,
	ULONG ulHeadSize,
	PNDIS_PACKET pPacket
	);


VOID
ReadPacket (
	PNDIS_PACKET pPacket,
	PUCHAR pBuffer,
	ULONG ulBufSize
	);

//BOOLEAN
//AllocateReceivePacket (
//	ULONG ulDataSize,
//	PUCHAR * ppBuffer,
//	PNDIS_PACKET * ppPacket
//	);

#endif
