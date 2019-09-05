/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ntddk.h>
#include <storport.h>
#include <stdlib.h>
#include <ntstrsafe.h>

#include <xencdb.h>
#include <cache_interface.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <debug_interface.h>

#include "ring.h"
#include "frontend.h"
#include "target.h"
#include "adapter.h"
#include "srbext.h"
#include "driver.h"
#include "granter.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

#define XENVBD_MAX_RING_PAGE_ORDER  (4)
#define XENVBD_MAX_RING_PAGES       (1 << XENVBD_MAX_RING_PAGE_ORDER)

#define xen_mb  KeMemoryBarrier
#define xen_wmb KeMemoryBarrier

typedef struct _XENVBD_SRB_STATE {
    LIST_ENTRY                      List;
    ULONG                           Count;
} XENVBD_SRB_STATE, *PXENVBD_SRB_STATE;

typedef struct _XENVBD_BLKIF_RING {
    PXENVBD_RING                    Ring;
    ULONG                           Index;
    PCHAR                           Path;
    PXENBUS_CACHE                   RequestCache;
    PXENBUS_CACHE                   SegmentCache;
    PXENBUS_CACHE                   IndirectCache;
    PMDL                            Mdl;
    blkif_sring_t                   *Shared;
    blkif_front_ring_t              Front;
    PXENBUS_GNTTAB_ENTRY            Grants[XENVBD_MAX_RING_PAGES];
    PXENBUS_EVTCHN_CHANNEL          Channel;
    KDPC                            Dpc;
    ULONG                           Dpcs;
    ULONG                           Events;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;
    BOOLEAN                         Stopped;
    PVOID                           Lock;
    PKTHREAD                        LockThread;
    XENVBD_SRB_STATE                State;
    LIST_ENTRY                      SrbQueue;
    LIST_ENTRY                      SubmittedList;
    LIST_ENTRY                      ShutdownQueue;
    ULONG                           SrbsQueued;
    ULONG                           SrbsCompleted;
    ULONG                           SrbsFailed;
    ULONG                           RequestsPosted;
    ULONG                           RequestsPushed;
    ULONG                           ResponsesProcessed;
    PXENBUS_DEBUG_CALLBACK          DebugCallback;
    LARGE_INTEGER                   TimeOfLastErrorLog;
} XENVBD_BLKIF_RING, *PXENVBD_BLKIF_RING;

typedef enum _XENVBD_STAT {
    XENVBD_STAT_BLKIF_OP_READ_DIRECT = 0,
    XENVBD_STAT_BLKIF_OP_READ_INDIRECT,
    XENVBD_STAT_BLKIF_OP_WRITE_DIRECT,
    XENVBD_STAT_BLKIF_OP_WRITE_INDIRECT,
    XENVBD_STAT_BLKIF_OP_WRITE_BARRIER,
    XENVBD_STAT_BLKIF_OP_FLUSH_DISKCACHE,
    XENVBD_STAT_BLKIF_OP_DISCARD,
    XENVBD_STAT_BLKIF_OP_UNKNOWN,
    XENVBD_STAT_SEGMENTS_GRANTED,
    XENVBD_STAT_SEGMENTS_BOUNCED,

    XENVBD_STAT__MAX
} XENVBD_STAT, *PXENVBD_STAT;

struct _XENVBD_RING {
    PXENVBD_FRONTEND                Frontend;
    XENBUS_DEBUG_INTERFACE          DebugInterface;
    XENBUS_CACHE_INTERFACE          CacheInterface;
    XENBUS_STORE_INTERFACE          StoreInterface;
    XENBUS_EVTCHN_INTERFACE         EvtchnInterface;
    PXENBUS_DEBUG_CALLBACK          DebugCallback;
    ULONG                           Order;
    PXENVBD_BLKIF_RING              *Ring;
    LONG                            Stats[XENVBD_STAT__MAX];
};

#define MAX_NAME_LEN                64
#define RING_POOL_TAG               'gnRX'
#define XEN_IO_PROTO_ABI            "x86_64-abi"

static FORCEINLINE PVOID
__RingAllocate(
    IN  ULONG                       Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool,
                                 Length,
                                 RING_POOL_TAG);
}

static FORCEINLINE VOID
__RingFree(
    IN  PVOID                       Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer,
                          RING_POOL_TAG);
}

static FORCEINLINE PCHAR
__BlkifOperationName(
    IN  UCHAR   Operation
    )
{
    switch (Operation) {
    case BLKIF_OP_READ:             return "READ";
    case BLKIF_OP_WRITE:            return "WRITE";
    case BLKIF_OP_WRITE_BARRIER:    return "WRITE_BARRIER";
    case BLKIF_OP_FLUSH_DISKCACHE:  return "FLUSH_DISKCACHE";
    case BLKIF_OP_RESERVED_1:       return "RESERVED_1";
    case BLKIF_OP_DISCARD:          return "DISCARD";
    case BLKIF_OP_INDIRECT:         return "INDIRECT";
    default:                        return "<unknown>";
    }
}

static FORCEINLINE PCHAR
__StatName(
    IN  XENVBD_STAT Operation
    )
{
    switch (Operation) {
    case XENVBD_STAT_BLKIF_OP_READ_DIRECT:      return "BLKIF_OP_READ (direct)";
    case XENVBD_STAT_BLKIF_OP_READ_INDIRECT:    return "BLKIF_OP_READ (indirect)";
    case XENVBD_STAT_BLKIF_OP_WRITE_DIRECT:     return "BLKIF_OP_WRITE (direct)";
    case XENVBD_STAT_BLKIF_OP_WRITE_INDIRECT:   return "BLKIF_OP_WRITE (indirect)";
    case XENVBD_STAT_BLKIF_OP_WRITE_BARRIER:    return "BLKIF_OP_WRITE_BARRIER";
    case XENVBD_STAT_BLKIF_OP_FLUSH_DISKCACHE:  return "BLKIF_OP_FLUSH_DISKCACHE";
    case XENVBD_STAT_BLKIF_OP_DISCARD:          return "BLKIF_OP_DISCARD";
    case XENVBD_STAT_SEGMENTS_GRANTED:          return "SegmentsGranted";
    case XENVBD_STAT_SEGMENTS_BOUNCED:          return "SegmentsBounced";
    default:                                    return "UNKNOWN";
    }
}

static FORCEINLINE ULONG
__SectorsPerPage(
    IN  ULONG   SectorSize
    )
{
    ASSERT3U(SectorSize, != , 0);
    return PAGE_SIZE / SectorSize;
}

static FORCEINLINE VOID
__Operation(
    IN  UCHAR       CdbOp,
    OUT PUCHAR      RingOp,
    OUT PBOOLEAN    ReadOnly
    )
{
    switch (CdbOp) {
    case SCSIOP_READ:
        *RingOp = BLKIF_OP_READ;
        *ReadOnly = FALSE;
        break;
    case SCSIOP_WRITE:
        *RingOp = BLKIF_OP_WRITE;
        *ReadOnly = TRUE;
        break;
    default:
        ASSERT(FALSE);
    }
}

static FORCEINLINE ULONG
__UseIndirect(
    IN  ULONG           SectorsPerPage,
    IN  ULONG           MaxIndirectSegs,
    IN  ULONG           SectorsLeft
    )
{
    if (MaxIndirectSegs <= BLKIF_MAX_SEGMENTS_PER_REQUEST)
        return BLKIF_MAX_SEGMENTS_PER_REQUEST; // not supported

    if (SectorsLeft < BLKIF_MAX_SEGMENTS_PER_REQUEST * SectorsPerPage)
        return BLKIF_MAX_SEGMENTS_PER_REQUEST; // first into a single BLKIF_OP_{READ/WRITE}

    return MaxIndirectSegs;
}

static FORCEINLINE MM_PAGE_PRIORITY
__Priority(
    IN  PXENVBD_CAPS    Caps
    )
{
    return (Caps->Paging ||
            Caps->Hibernation ||
            Caps->DumpFile) ? HighPagePriority :
                              NormalPagePriority;
}

static PXENVBD_INDIRECT
BlkifRingGetIndirect(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Frontend);
    PXENVBD_INDIRECT        Indirect;
    NTSTATUS                status;

    Indirect = XENBUS_CACHE(Get,
                            &Ring->CacheInterface,
                            BlkifRing->IndirectCache,
                            TRUE);
    if (Indirect == NULL)
        goto fail1;

    ASSERT3P(Indirect->Mdl, != , NULL);
    ASSERT3P(Indirect->Page, != , NULL);
    status = GranterGet(Granter,
                        MmGetMdlPfnArray(Indirect->Mdl)[0],
                        TRUE,
                        &Indirect->Grant);
    if (!NT_SUCCESS(status))
        goto fail2;

    return Indirect;

fail2:
    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 BlkifRing->IndirectCache,
                 Indirect,
                 TRUE);
fail1:
    return NULL;
}

static VOID
BlkifRingPutIndirect(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_INDIRECT    Indirect
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Frontend);

    if (Indirect->Grant)
        GranterPut(Granter, Indirect->Grant);
    Indirect->Grant = NULL;

    RtlZeroMemory(&Indirect->ListEntry, sizeof(LIST_ENTRY));

    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 BlkifRing->IndirectCache,
                 Indirect,
                 TRUE);
}

static PXENVBD_SEGMENT
BlkifRingGetSegment(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;

    return XENBUS_CACHE(Get,
                        &Ring->CacheInterface,
                        BlkifRing->SegmentCache,
                        TRUE);
}

static VOID
BlkifRingPutSegment(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SEGMENT     Segment
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Frontend);
    PXENVBD_BOUNCE          Bounce = Segment->Bounce;

    if (Segment->Grant)
        GranterPut(Granter, Segment->Grant);
    Segment->Grant = NULL;

    if (Bounce) {
        if (Bounce->SourcePtr) {
            MmUnmapLockedPages(Bounce->SourcePtr,
                               &Bounce->SourceMdl);
        }
        RtlZeroMemory(&Bounce->SourceMdl, sizeof(MDL));
        Bounce->SourcePtr = NULL;
        Bounce->SourcePfn[0] = 0;
        Bounce->SourcePfn[1] = 0;

        AdapterPutBounce(TargetGetAdapter(FrontendGetTarget(Frontend)),
                         Bounce);
    }
    Segment->Bounce = NULL;

    Segment->FirstSector = 0;
    Segment->LastSector = 0;
    RtlZeroMemory(&Segment->ListEntry, sizeof(LIST_ENTRY));

    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 BlkifRing->SegmentCache,
                 Segment,
                 TRUE);
}

static PXENVBD_REQUEST
BlkifRingGetRequest(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;

    return XENBUS_CACHE(Get,
                        &Ring->CacheInterface,
                        BlkifRing->RequestCache,
                        TRUE);
}

static VOID
BlkifRingPutRequest(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_REQUEST     Request
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PLIST_ENTRY             ListEntry;

    for (;;) {
        PXENVBD_SEGMENT Segment;

        ListEntry = RemoveHeadList(&Request->Segments);
        if (ListEntry == &Request->Segments)
            break;
        Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);
        BlkifRingPutSegment(BlkifRing, Segment);
    }

    for (;;) {
        PXENVBD_INDIRECT    Indirect;

        ListEntry = RemoveHeadList(&Request->Indirects);
        if (ListEntry == &Request->Indirects)
            break;
        Indirect = CONTAINING_RECORD(ListEntry, XENVBD_INDIRECT, ListEntry);
        BlkifRingPutIndirect(BlkifRing, Indirect);
    }

    Request->SrbExt = NULL;
    Request->Operation = 0;
    Request->Flags = 0;
    Request->NrSegments = 0;
    Request->FirstSector = 0;
    Request->NrSectors = 0;
    RtlZeroMemory(&Request->ListEntry, sizeof(LIST_ENTRY));

    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 BlkifRing->RequestCache,
                 Request,
                 TRUE);
}

static DECLSPEC_NOINLINE NTSTATUS
BlkifRingRequestCtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    PXENVBD_REQUEST Request = Object;

    UNREFERENCED_PARAMETER(Argument);

    InitializeListHead(&Request->Segments);
    InitializeListHead(&Request->Indirects);
    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
BlkifRingRequestDtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static DECLSPEC_NOINLINE NTSTATUS
BlkifRingSegmentCtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
BlkifRingSegmentDtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static DECLSPEC_NOINLINE NTSTATUS
BlkifRingIndirectCtor(
    IN  PVOID           Argument,
    IN  PVOID           Object
    )
{
    PXENVBD_INDIRECT    Indirect = Object;
    NTSTATUS            status;

    UNREFERENCED_PARAMETER(Argument);

    status = STATUS_NO_MEMORY;
    Indirect->Mdl = __AllocatePage();
    if (Indirect->Mdl == NULL)
        goto fail1;

    Indirect->Page = MmGetSystemAddressForMdlSafe(Indirect->Mdl,
                                                  NormalPagePriority);
    ASSERT(Indirect->Page);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static DECLSPEC_NOINLINE VOID
BlkifRingIndirectDtor(
    IN  PVOID           Argument,
    IN  PVOID           Object
    )
{
    PXENVBD_INDIRECT    Indirect = Object;

    UNREFERENCED_PARAMETER(Argument);

    __FreePages(Indirect->Mdl);
    Indirect->Page = NULL;
    Indirect->Mdl = NULL;
}

static VOID
BlkifRingDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVBD_BLKIF_RING  BlkifRing = Argument;
    PXENVBD_RING        Ring = BlkifRing->Ring;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "0x%p [%s]\n",
                 BlkifRing,
                 (BlkifRing->Enabled) ? "ENABLED" : "DISABLED");

    // Dump front ring
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
                 BlkifRing->Front.req_prod_pvt,
                 BlkifRing->Front.rsp_cons,
                 BlkifRing->Front.nr_ents,
                 BlkifRing->Front.sring);

    // Dump shared ring
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
                 BlkifRing->Shared->req_prod,
                 BlkifRing->Shared->req_event,
                 BlkifRing->Shared->rsp_prod,
                 BlkifRing->Shared->rsp_event);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
                 BlkifRing->RequestsPosted,
                 BlkifRing->RequestsPushed,
                 BlkifRing->ResponsesProcessed);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "SrbsQueued = %u, SrbsCompleted = %u, SrbsFailed = %u\n",
                 BlkifRing->SrbsQueued,
                 BlkifRing->SrbsCompleted,
                 BlkifRing->SrbsFailed);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Dpcs = %u, Events = %u\n",
                 BlkifRing->Dpcs,
                 BlkifRing->Events);
}

static DECLSPEC_NOINLINE VOID
__BlkifRingCompleteSrb(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PXENVBD_TARGET          Target = FrontendGetTarget(Frontend);
    PXENVBD_ADAPTER         Adapter = TargetGetAdapter(Target);
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;

    if (Srb->SrbStatus == SRB_STATUS_PENDING) {
        // SRB has not hit a failure condition (BLKIF_RSP_ERROR | BLKIF_RSP_EOPNOTSUPP)
        // from any of its responses. SRB must have succeeded
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        Srb->ScsiStatus = 0x00; // SCSI_GOOD
        ++BlkifRing->SrbsCompleted;
    } else {
        // Srb->SrbStatus has already been set by 1 or more requests with Status != BLKIF_RSP_OKAY
        Srb->ScsiStatus = 0x40; // SCSI_ABORTED
        ++BlkifRing->SrbsFailed;
    }

    AdapterCompleteSrb(Adapter, SrbExt);
}

static FORCEINLINE VOID
BlkifRingUnprepareRequest(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PLIST_ENTRY         List
    )
{
    for (;;) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_REQUEST     Request;

        ListEntry = RemoveHeadList(List);
        if (ListEntry == List)
            break;

        Request = CONTAINING_RECORD(ListEntry,
                                    XENVBD_REQUEST,
                                    ListEntry);

        BlkifRingPutRequest(BlkifRing, Request);
    }
}

static FORCEINLINE VOID
BlkifRingQueueRequests(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PLIST_ENTRY         List
    )
{
    PXENVBD_SRB_STATE       State = &BlkifRing->State;

    for (;;) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_REQUEST     Request;

        ListEntry = RemoveHeadList(List);
        if (ListEntry == List)
            break;

        Request = CONTAINING_RECORD(ListEntry,
                                    XENVBD_REQUEST,
                                    ListEntry);

        InsertTailList(&State->List, ListEntry);
        State->Count++;
    }
}

static BOOLEAN
BlkifRingPrepareSegment(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SEGMENT     Segment,
    IN  PXENVBD_SRBEXT      SrbExt,
    IN  BOOLEAN             ReadOnly,
    IN  ULONG               SectorsLeft,
    OUT PULONG              SectorsNow
    )
{
    PFN_NUMBER              Pfn;
    ULONG                   Offset;
    ULONG                   Length;
    NTSTATUS                Status;
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Ring->Frontend);
    PXENVBD_TARGET          Target = FrontendGetTarget(Ring->Frontend);
    PXENVBD_ADAPTER         Adapter = TargetGetAdapter(Target);

    const ULONG             SectorSize = FrontendGetDiskInfo(Ring->Frontend)->SectorSize;
    const ULONG             SectorsPerPage = __SectorsPerPage(SectorSize);

    Pfn = AdapterGetNextSGEntry(Adapter,
                                SrbExt,
                                0,
                                &Offset,
                                &Length);
    if ((Offset & (SectorSize - 1)) == 0 &&
        (Length & (SectorSize - 1)) == 0) {
        InterlockedIncrement(&Ring->Stats[XENVBD_STAT_SEGMENTS_GRANTED]);

        // get first sector, last sector and count
        Segment->FirstSector = (UCHAR)((Offset + SectorSize - 1) / SectorSize);
        *SectorsNow = __min(SectorsLeft, SectorsPerPage - Segment->FirstSector);
        Segment->LastSector = (UCHAR)(Segment->FirstSector + *SectorsNow - 1);

        ASSERT3U((Length / SectorSize), == , *SectorsNow);
    } else {
        PXENVBD_BOUNCE      Bounce;
        PMDL                Mdl;
        PXENVBD_CAPS        Caps = FrontendGetCaps(Ring->Frontend);

        InterlockedIncrement(&Ring->Stats[XENVBD_STAT_SEGMENTS_BOUNCED]);

        // get first sector, last sector and count
        Segment->FirstSector = 0;
        *SectorsNow = __min(SectorsLeft, SectorsPerPage);
        Segment->LastSector = (UCHAR)(*SectorsNow - 1);

        Bounce = AdapterGetBounce(Adapter);
        if (Bounce == NULL)
            goto fail1;
        Segment->Bounce = Bounce;

#pragma warning(push)
#pragma warning(disable:28145)
        Mdl = &Bounce->SourceMdl;
        Mdl->Next = NULL;
        Mdl->Size = (SHORT)(sizeof(MDL) + sizeof(PFN_NUMBER));
        Mdl->MdlFlags = MDL_PAGES_LOCKED;
        Mdl->Process = NULL;
        Mdl->MappedSystemVa = NULL;
        Mdl->StartVa = NULL;
        Mdl->ByteCount = Length;
        Mdl->ByteOffset = Offset;
        Bounce->SourcePfn[0] = Pfn;

        if (Length < *SectorsNow * SectorSize) {
            Pfn = AdapterGetNextSGEntry(Adapter,
                                        SrbExt,
                                        Length,
                                        &Offset,
                                        &Length);
            Mdl->Size += sizeof(PFN_NUMBER);
            Mdl->ByteCount += Length;
            Bounce->SourcePfn[1] = Pfn;
        }
#pragma warning(pop)

        ASSERT((Mdl->ByteCount & (SectorSize - 1)) == 0);
        ASSERT3U(Mdl->ByteCount, <= , PAGE_SIZE);
        ASSERT3U(*SectorsNow, == , (Mdl->ByteCount / SectorSize));

        Bounce->SourcePtr = MmMapLockedPagesSpecifyCache(Mdl,
                                                         KernelMode,
                                                         MmCached,
                                                         NULL,
                                                         FALSE,
                                                         __Priority(Caps));
        if (Bounce->SourcePtr == NULL)
            goto fail2;

        ASSERT3P(MmGetMdlPfnArray(Mdl)[0], == , Bounce->SourcePfn[0]);
        ASSERT3P(MmGetMdlPfnArray(Mdl)[1], == , Bounce->SourcePfn[1]);

        // copy contents in
        if (ReadOnly) { // Operation == BLKIF_OP_WRITE
            RtlCopyMemory(Bounce->BouncePtr,
                          Bounce->SourcePtr,
                          MmGetMdlByteCount(&Bounce->SourceMdl));
        }

        Pfn = MmGetMdlPfnArray(Bounce->BounceMdl)[0];
    }

    // Grant segment's page
    Status = GranterGet(Granter, Pfn, ReadOnly, &Segment->Grant);
    if (!NT_SUCCESS(Status))
        goto fail3;

    return TRUE;

fail3:
fail2:
fail1:
    return FALSE;
}

static NTSTATUS
BlkifRingPrepareReadWrite(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    ULONG64                 SectorStart = Cdb_LogicalBlock(Srb);
    ULONG                   SectorsLeft = Cdb_TransferBlock(Srb);
    UCHAR                   Operation;
    BOOLEAN                 ReadOnly;
    LIST_ENTRY              List;

    const ULONG             SectorSize = FrontendGetDiskInfo(Frontend)->SectorSize;
    const ULONG             SectorsPerPage = __SectorsPerPage(SectorSize);
    const ULONG             MaxIndirect = FrontendGetFeatures(Frontend)->Indirect;

    InitializeListHead(&List);

    __Operation(Cdb_OperationEx(Srb), &Operation, &ReadOnly);

    Srb->SrbStatus = SRB_STATUS_PENDING;

    SrbExt->RequestCount = 0;

    while (SectorsLeft > 0) {
        ULONG           Index;
        ULONG           MaxSegments;
        PXENVBD_REQUEST Request;

        Request = BlkifRingGetRequest(BlkifRing);
        if (Request == NULL)
            goto fail1;
        InsertTailList(&List, &Request->ListEntry);
        SrbExt->RequestCount++;

        Request->SrbExt = SrbExt;

        MaxSegments = __UseIndirect(SectorsPerPage,
                                    MaxIndirect,
                                    SectorsLeft);

        Request->Operation = Operation;
        Request->NrSegments = 0;
        Request->FirstSector = SectorStart;

        for (Index = 0;
             Index < MaxSegments &&
             SectorsLeft > 0;
             ++Index) {
            PXENVBD_SEGMENT Segment;
            ULONG           SectorsNow;

            Segment = BlkifRingGetSegment(BlkifRing);
            if (Segment == NULL)
                goto fail2;

            InsertTailList(&Request->Segments, &Segment->ListEntry);
            ++Request->NrSegments;

            if (!BlkifRingPrepareSegment(BlkifRing,
                                         Segment,
                                         SrbExt,
                                         ReadOnly,
                                         SectorsLeft,
                                         &SectorsNow))
                goto fail3;

            SectorsLeft -= SectorsNow;
            SectorStart += SectorsNow;
        }
        ASSERT3U(Request->NrSegments, >, 0);
        ASSERT3U(Request->NrSegments, <= , MaxSegments);

        if (MaxSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            ULONG               NrSegments = 0;

            for (Index = 0;
                 Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST &&
                 NrSegments < Request->NrSegments;
                 ++Index) {
                PXENVBD_INDIRECT    Indirect;

                Indirect = BlkifRingGetIndirect(BlkifRing);
                if (Indirect == NULL)
                    goto fail3;
                InsertTailList(&Request->Indirects, &Indirect->ListEntry);

                NrSegments += XENVBD_MAX_SEGMENTS_PER_PAGE;
            }
        }
    }

    BlkifRingQueueRequests(BlkifRing, &List);
    return STATUS_SUCCESS;

fail3:
fail2:
fail1:
    BlkifRingUnprepareRequest(BlkifRing, &List);
    SrbExt->RequestCount = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
BlkifRingPrepareUnmap(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    PUNMAP_LIST_HEADER      Unmap = Srb->DataBuffer;
    ULONG                   Count;
    ULONG                   Index;
    LIST_ENTRY              List;

    InitializeListHead(&List);

    Count = _byteswap_ushort(*(PUSHORT)Unmap->BlockDescrDataLength) / sizeof(UNMAP_BLOCK_DESCRIPTOR);
    Srb->SrbStatus = SRB_STATUS_PENDING;

    SrbExt->RequestCount = 0;

    for (Index = 0; Index < Count; ++Index) {
        PUNMAP_BLOCK_DESCRIPTOR Descr = &Unmap->Descriptors[Index];
        PXENVBD_REQUEST         Request;

        Request = BlkifRingGetRequest(BlkifRing);
        if (Request == NULL)
            goto fail1;
        InsertTailList(&List, &Request->ListEntry);
        SrbExt->RequestCount++;

        Request->SrbExt = SrbExt;
        Request->Operation = BLKIF_OP_DISCARD;
        Request->FirstSector = _byteswap_uint64(*(PULONG64)Descr->StartingLba);
        Request->NrSectors = _byteswap_ulong(*(PULONG)Descr->LbaCount);
        Request->Flags = 0;
    }

    BlkifRingQueueRequests(BlkifRing, &List);
    return STATUS_SUCCESS;

fail1:
    BlkifRingUnprepareRequest(BlkifRing, &List);
    SrbExt->RequestCount = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
BlkifRingPrepareSyncCache(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    PXENVBD_REQUEST         Request;
    UCHAR                   Operation;
    LIST_ENTRY              List;

    InitializeListHead(&List);
    Srb->SrbStatus = SRB_STATUS_PENDING;

    if (FrontendGetDiskInfo(Frontend)->FlushCache)
        Operation = BLKIF_OP_FLUSH_DISKCACHE;
    else
        Operation = BLKIF_OP_WRITE_BARRIER;

    SrbExt->RequestCount = 0;

    Request = BlkifRingGetRequest(BlkifRing);
    if (Request == NULL)
        goto fail1;
    InsertTailList(&List, &Request->ListEntry);
    SrbExt->RequestCount++;

    Request->SrbExt = SrbExt;
    Request->Operation = Operation;
    Request->FirstSector = Cdb_LogicalBlock(Srb);

    BlkifRingQueueRequests(BlkifRing, &List);
    return STATUS_SUCCESS;

fail1:
    BlkifRingUnprepareRequest(BlkifRing, &List);
    SrbExt->RequestCount = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return STATUS_UNSUCCESSFUL;
}

static DECLSPEC_NOINLINE NTSTATUS
__BlkifRingPrepareSrb(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    switch (Cdb_OperationEx(SrbExt->Srb)) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        return BlkifRingPrepareReadWrite(BlkifRing,
                                         SrbExt);

    case SCSIOP_SYNCHRONIZE_CACHE:
        return BlkifRingPrepareSyncCache(BlkifRing,
                                         SrbExt);

    case SCSIOP_UNMAP:
        return BlkifRingPrepareUnmap(BlkifRing,
                                     SrbExt);

    default:
        ASSERT(FALSE);
        return STATUS_NOT_SUPPORTED;
    }
}

static FORCEINLINE VOID
__BlkifRingInsertRequest(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_REQUEST     Request,
    IN  blkif_request_t     *req
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Frontend);

    switch (Request->Operation) {
    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        if (Request->NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            // Indirect
            ULONG                       PageIdx;
            ULONG                       SegIdx;
            PLIST_ENTRY                 PageEntry;
            PLIST_ENTRY                 SegEntry;
            blkif_request_indirect_t*   req_indirect;

            req_indirect = (blkif_request_indirect_t*)req;
            req_indirect->operation = BLKIF_OP_INDIRECT;
            req_indirect->indirect_op = Request->Operation;
            req_indirect->nr_segments = Request->NrSegments;
            req_indirect->id = (ULONG64)(ULONG_PTR)Request;
            req_indirect->sector_number = Request->FirstSector;
            req_indirect->handle = (USHORT)FrontendGetDeviceId(Frontend);

            for (PageIdx = 0,
                 PageEntry = Request->Indirects.Flink,
                 SegEntry = Request->Segments.Flink;
                 PageIdx < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST &&
                 PageEntry != &Request->Indirects &&
                 SegEntry != &Request->Segments;
                 ++PageIdx, PageEntry = PageEntry->Flink) {
                PXENVBD_INDIRECT Page = CONTAINING_RECORD(PageEntry, XENVBD_INDIRECT, ListEntry);

                req_indirect->indirect_grefs[PageIdx] = GranterReference(Granter, Page->Grant);

                for (SegIdx = 0;
                     SegIdx < XENVBD_MAX_SEGMENTS_PER_PAGE &&
                     SegEntry != &Request->Segments;
                     ++SegIdx, SegEntry = SegEntry->Flink) {
                    PXENVBD_SEGMENT Segment = CONTAINING_RECORD(SegEntry, XENVBD_SEGMENT, ListEntry);

                    Page->Page[SegIdx].GrantRef = GranterReference(Granter, Segment->Grant);
                    Page->Page[SegIdx].First = Segment->FirstSector;
                    Page->Page[SegIdx].Last = Segment->LastSector;
                }
            }
            InterlockedIncrement(&Ring->Stats[(Request->Operation == BLKIF_OP_READ) ?
                                 XENVBD_STAT_BLKIF_OP_READ_INDIRECT :
                                 XENVBD_STAT_BLKIF_OP_WRITE_INDIRECT]);
        } else {
            // Direct
            ULONG           Index;
            PLIST_ENTRY     Entry;

            req->operation = Request->Operation;
            req->nr_segments = (UCHAR)Request->NrSegments;
            req->handle = (USHORT)FrontendGetDeviceId(Frontend);
            req->id = (ULONG64)(ULONG_PTR)Request;
            req->sector_number = Request->FirstSector;

            for (Index = 0, Entry = Request->Segments.Flink;
                 Index < BLKIF_MAX_SEGMENTS_PER_REQUEST &&
                 Entry != &Request->Segments;
                 ++Index, Entry = Entry->Flink) {
                PXENVBD_SEGMENT Segment = CONTAINING_RECORD(Entry, XENVBD_SEGMENT, ListEntry);
                req->seg[Index].gref = GranterReference(Granter, Segment->Grant);
                req->seg[Index].first_sect = Segment->FirstSector;
                req->seg[Index].last_sect = Segment->LastSector;
            }
            InterlockedIncrement(&Ring->Stats[(Request->Operation == BLKIF_OP_READ) ?
                                 XENVBD_STAT_BLKIF_OP_READ_DIRECT :
                                 XENVBD_STAT_BLKIF_OP_WRITE_DIRECT]);
        }
        break;

    case BLKIF_OP_WRITE_BARRIER:
    case BLKIF_OP_FLUSH_DISKCACHE:
        req->operation = Request->Operation;
        req->nr_segments = 0;
        req->handle = (USHORT)FrontendGetDeviceId(Ring->Frontend);
        req->id = (ULONG64)(ULONG_PTR)Request;
        req->sector_number = Request->FirstSector;
        InterlockedIncrement(&Ring->Stats[(Request->Operation == BLKIF_OP_WRITE_BARRIER) ?
                             XENVBD_STAT_BLKIF_OP_WRITE_BARRIER :
                             XENVBD_STAT_BLKIF_OP_FLUSH_DISKCACHE]);
        break;

    case BLKIF_OP_DISCARD:
    {
        blkif_request_discard_t*        req_discard;
        req_discard = (blkif_request_discard_t*)req;
        req_discard->operation = BLKIF_OP_DISCARD;
        req_discard->flag = Request->Flags;
        req_discard->handle = (USHORT)FrontendGetDeviceId(Frontend);
        req_discard->id = (ULONG64)(ULONG_PTR)Request;
        req_discard->sector_number = Request->FirstSector;
        req_discard->nr_sectors = Request->NrSectors;
        InterlockedIncrement(&Ring->Stats[XENVBD_STAT_BLKIF_OP_DISCARD]);
    } break;

    default:
        ASSERT(FALSE);
        break;
    }
}

static FORCEINLINE NTSTATUS
__BlkifRingPostRequests(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_SRB_STATE       State;

    State = &BlkifRing->State;

    for (;;) {
        blkif_request_t     *req;
        PXENVBD_REQUEST     Request;
        PLIST_ENTRY         ListEntry;

        if (State->Count == 0)
            return STATUS_SUCCESS;

        if (RING_FULL(&BlkifRing->Front))
            return STATUS_ALLOTTED_SPACE_EXCEEDED;

        --State->Count;

        ListEntry = RemoveHeadList(&State->List);
        ASSERT3P(ListEntry, != , &State->List);

        RtlZeroMemory(ListEntry, sizeof(LIST_ENTRY));

        Request = CONTAINING_RECORD(ListEntry,
                                    XENVBD_REQUEST,
                                    ListEntry);

        req = RING_GET_REQUEST(&BlkifRing->Front, BlkifRing->Front.req_prod_pvt);
        BlkifRing->Front.req_prod_pvt++;
        BlkifRing->RequestsPosted++;

        __BlkifRingInsertRequest(BlkifRing,
                                 Request,
                                 req);

        InsertTailList(&BlkifRing->SubmittedList, ListEntry);
    }
}

static FORCEINLINE PXENVBD_REQUEST
__BlkifRingGetSubmittedRequest(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  ULONG64             Id
    )
{
    PLIST_ENTRY             ListEntry;
    PXENVBD_REQUEST         Request;

    for (ListEntry = BlkifRing->SubmittedList.Flink;
         ListEntry != &BlkifRing->SubmittedList;
         ListEntry = ListEntry->Flink) {
        Request = CONTAINING_RECORD(ListEntry,
                                    XENVBD_REQUEST,
                                    ListEntry);
        if ((ULONG64)(ULONG_PTR)Request != Id)
            continue;

        RemoveEntryList(ListEntry);
        return Request;
    }
    return NULL;
}

static FORCEINLINE VOID
__BlkifRingCompleteResponse(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_REQUEST     Request,
    IN  SHORT               Status
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PSCSI_REQUEST_BLOCK     Srb;
    PXENVBD_SRBEXT          SrbExt;
    PLIST_ENTRY             ListEntry;

    SrbExt = Request->SrbExt;
    Srb = SrbExt->Srb;

    switch (Status) {
    case BLKIF_RSP_OKAY:
        if (Request->Operation != BLKIF_OP_READ)
            break;

        for (ListEntry = Request->Segments.Flink;
             ListEntry != &Request->Segments;
             ListEntry = ListEntry->Flink) {
            PXENVBD_SEGMENT Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);
            PXENVBD_BOUNCE  Bounce = Segment->Bounce;

            if (Bounce) {
                RtlCopyMemory(Bounce->SourcePtr,
                              Bounce->BouncePtr,
                              MmGetMdlByteCount(&Bounce->SourceMdl));
            }
        }
        break;

    case BLKIF_RSP_EOPNOTSUPP:
        // Remove appropriate feature support
        FrontendRemoveFeature(Frontend, Request->Operation);
        // Succeed this SRB, subsiquent SRBs will be succeeded instead of being passed to the backend.
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case BLKIF_RSP_ERROR:
    default: {
        LARGE_INTEGER TimeNow;

        KeQuerySystemTime(&TimeNow);

        // If last log message was more than 10 seconds ago
        if (TimeNow.QuadPart - BlkifRing->TimeOfLastErrorLog.QuadPart > 100000000ull) {
            Warning("Target[%u][%u] : %s BLKIF_RSP_ERROR\n",
                    FrontendGetTargetId(Frontend),
                    BlkifRing->Index,
                    __BlkifOperationName(Request->Operation));
            KeQuerySystemTime(&BlkifRing->TimeOfLastErrorLog);
        }
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
        }
    }

    BlkifRingPutRequest(BlkifRing, Request);

    // complete srb
    if (InterlockedDecrement(&SrbExt->RequestCount) == 0) {
        __BlkifRingCompleteSrb(BlkifRing, SrbExt);
    }
}

static FORCEINLINE BOOLEAN
BlkifRingPoll(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
#define XENVBD_BATCH(_Ring) (RING_SIZE(&(_Ring)->Front) / 4)

    PXENVBD_RING            Ring;
    BOOLEAN                 Retry;

    Ring = BlkifRing->Ring;
    Retry = FALSE;

    if (!BlkifRing->Enabled)
        goto done;

    for (;;) {
        RING_IDX            rsp_prod;
        RING_IDX            rsp_cons;

        KeMemoryBarrier();

        rsp_prod = BlkifRing->Shared->rsp_prod;
        rsp_cons = BlkifRing->Front.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod || Retry)
            break;

        while (rsp_cons != rsp_prod && !Retry) {
            blkif_response_t    *rsp;
            PXENVBD_REQUEST     Request;

            rsp = RING_GET_RESPONSE(&BlkifRing->Front, rsp_cons);
            rsp_cons++;
            BlkifRing->ResponsesProcessed++;

            BlkifRing->Stopped = FALSE;

            Request = __BlkifRingGetSubmittedRequest(BlkifRing,
                                                     rsp->id);
            ASSERT3P(Request, != , NULL);

            __BlkifRingCompleteResponse(BlkifRing,
                                        Request,
                                        rsp->status);

            if (rsp_cons - BlkifRing->Front.rsp_cons > XENVBD_BATCH(BlkifRing))
                Retry = TRUE;
        }

        KeMemoryBarrier();

        BlkifRing->Front.rsp_cons = rsp_cons;
        BlkifRing->Shared->rsp_event = rsp_cons + 1;
    }

done:
    return Retry;

#undef XENVBD_BATCH
}

static FORCEINLINE VOID
__BlkifRingSend(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;

    XENBUS_EVTCHN(Send,
                  &Ring->EvtchnInterface,
                  BlkifRing->Channel);
}

static FORCEINLINE VOID
__BlkifRingPushRequests(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    BOOLEAN                 Notify;

    if (BlkifRing->RequestsPosted == BlkifRing->RequestsPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&BlkifRing->Front, Notify);

#pragma warning (pop)

    if (Notify)
        __BlkifRingSend(BlkifRing);

    BlkifRing->RequestsPushed = BlkifRing->RequestsPosted;
}

#define XENVBD_LOCK_BIT ((ULONG_PTR)1)

static DECLSPEC_NOINLINE VOID
BlkifRingSwizzle(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    ULONG_PTR               Old;
    ULONG_PTR               New;
    PLIST_ENTRY             ListEntry;
    LIST_ENTRY              List;
    ULONG                   Count;

    ASSERT3P(BlkifRing->LockThread, == , KeGetCurrentThread());

    InitializeListHead(&List);

    New = XENVBD_LOCK_BIT;
    Old = (ULONG_PTR)InterlockedExchangePointer(&BlkifRing->Lock, (PVOID)New);

    ASSERT(Old & XENVBD_LOCK_BIT);
    ListEntry = (PVOID)(Old & ~XENVBD_LOCK_BIT);

    if (ListEntry == NULL)
        return;

    // SRBs are held in the atomic packet list in reverse order
    // so that the most recent is always head of the list. This is
    // necessary to allow addition to the list to be done atomically.

    for (Count = 0; ListEntry != NULL; ++Count) {
        PLIST_ENTRY     NextEntry;

        NextEntry = ListEntry->Blink;
        ListEntry->Flink = ListEntry->Blink = ListEntry;

        InsertHeadList(&List, ListEntry);

        ListEntry = NextEntry;
    }

    if (!IsListEmpty(&List)) {
        ListEntry = List.Flink;

        RemoveEntryList(&List);
        AppendTailList(&BlkifRing->SrbQueue, ListEntry);

        BlkifRing->SrbsQueued += Count;
    }
}

static DECLSPEC_NOINLINE VOID
BlkifRingSchedule(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_SRB_STATE       State;
    BOOLEAN                 Polled;

    if (!BlkifRing->Enabled)
        return;

    State = &BlkifRing->State;
    Polled = FALSE;

    while (!BlkifRing->Stopped) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_SRBEXT      SrbExt;
        NTSTATUS            status;

        if (State->Count != 0) {
            status = __BlkifRingPostRequests(BlkifRing);
            if (!NT_SUCCESS(status))
                BlkifRing->Stopped = TRUE;
        }

        if (BlkifRing->Stopped) {
            if (!Polled) {
                (VOID)BlkifRingPoll(BlkifRing);
                Polled = TRUE;
            }

            continue;
        }

        __BlkifRingPushRequests(BlkifRing);

        if (IsListEmpty(&BlkifRing->SrbQueue))
            break;

        ListEntry = RemoveHeadList(&BlkifRing->SrbQueue);
        ASSERT3P(ListEntry, != , &BlkifRing->SrbQueue);

        RtlZeroMemory(ListEntry, sizeof(LIST_ENTRY));

        SrbExt = CONTAINING_RECORD(ListEntry,
                                   XENVBD_SRBEXT,
                                   ListEntry);

        status = __BlkifRingPrepareSrb(BlkifRing, SrbExt);
        if (!NT_SUCCESS(status)) {
            PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
            Srb->SrbStatus = SRB_STATUS_BUSY;
            __BlkifRingCompleteSrb(BlkifRing, SrbExt);
        }
    }

    __BlkifRingPushRequests(BlkifRing);

    if (IsListEmpty(&BlkifRing->ShutdownQueue))
        return;

    if (!IsListEmpty(&BlkifRing->SrbQueue) ||
        !IsListEmpty(&BlkifRing->SubmittedList))
        return;

    for (;;) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_SRBEXT      SrbExt;
        PSCSI_REQUEST_BLOCK Srb;

        ListEntry = RemoveHeadList(&BlkifRing->ShutdownQueue);
        if (ListEntry == &BlkifRing->ShutdownQueue)
            break;

        SrbExt = CONTAINING_RECORD(ListEntry,
                                   XENVBD_SRBEXT,
                                   ListEntry);

        Srb = SrbExt->Srb;
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        __BlkifRingCompleteSrb(BlkifRing, SrbExt);
    }
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__BlkifRingTryAcquireLock(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    ULONG_PTR               Old;
    ULONG_PTR               New;
    BOOLEAN                 Acquired;

    ASSERT3U(KeGetCurrentIrql(), == , DISPATCH_LEVEL);

    KeMemoryBarrier();

    Old = (ULONG_PTR)BlkifRing->Lock & ~XENVBD_LOCK_BIT;
    New = Old | XENVBD_LOCK_BIT;

    Acquired = ((ULONG_PTR)InterlockedCompareExchangePointer(&BlkifRing->Lock,
        (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (Acquired) {
        ASSERT3P(BlkifRing->LockThread, == , NULL);
        BlkifRing->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Acquired;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__BlkifRingAcquireLock(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    ASSERT3U(KeGetCurrentIrql(), == , DISPATCH_LEVEL);

    for (;;) {
        if (__BlkifRingTryAcquireLock(BlkifRing))
            break;

        _mm_pause();
    }
}

static VOID
BlkifRingAcquireLock(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    __BlkifRingAcquireLock(BlkifRing);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__BlkifRingTryReleaseLock(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    ULONG_PTR               Old;
    ULONG_PTR               New;
    BOOLEAN                 Released;

    ASSERT3U(KeGetCurrentIrql(), == , DISPATCH_LEVEL);
    ASSERT3P(KeGetCurrentThread(), == , BlkifRing->LockThread);

    Old = XENVBD_LOCK_BIT;
    New = 0;

    BlkifRing->LockThread = NULL;

    KeMemoryBarrier();

    Released = ((ULONG_PTR)InterlockedCompareExchangePointer(&BlkifRing->Lock,
        (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (!Released) {
        ASSERT3P(BlkifRing->LockThread, == , NULL);
        BlkifRing->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Released;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__BlkifRingReleaseLock(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    ASSERT3U(KeGetCurrentIrql(), == , DISPATCH_LEVEL);

    // As lock holder it is our responsibility to drain the atomic
    // packet list into the transmit queue before we actually drop the
    // lock. This may, of course, take a few attempts as another
    // thread could be simuntaneously adding to the list.

    do {
        BlkifRingSwizzle(BlkifRing);
        BlkifRingSchedule(BlkifRing);
    } while (!__BlkifRingTryReleaseLock(BlkifRing));
}

static VOID
BlkifRingReleaseLock(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    __BlkifRingReleaseLock(BlkifRing);
}

KSERVICE_ROUTINE    BlkifRingInterrupt;

BOOLEAN
BlkifRingInterrupt(
    IN  PKINTERRUPT     InterruptObject,
    IN  PVOID           Argument
    )
{
    PXENVBD_BLKIF_RING  BlkifRing = Argument;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(BlkifRing != NULL);

    BlkifRing->Events++;

    if (KeInsertQueueDpc(&BlkifRing->Dpc, NULL, NULL))
        BlkifRing->Dpcs++;

    return TRUE;
}

__drv_functionClass(KDEFERRED_ROUTINE)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
static VOID
BlkifRingDpc(
    IN  PKDPC           Dpc,
    IN  PVOID           Context,
    IN  PVOID           Argument1,
    IN  PVOID           Argument2
    )
{
    PXENVBD_BLKIF_RING  BlkifRing = Context;
    PXENVBD_RING        Ring;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(BlkifRing != NULL);

    Ring = BlkifRing->Ring;

    for (;;) {
        BOOLEAN         Retry;
        KIRQL           Irql;

        KeRaiseIrql(DISPATCH_LEVEL, &Irql);
        __BlkifRingAcquireLock(BlkifRing);
        Retry = BlkifRingPoll(BlkifRing);
        __BlkifRingReleaseLock(BlkifRing);
        KeLowerIrql(Irql);

        if (!Retry)
            break;
    }

    XENBUS_EVTCHN(Unmask,
                  &Ring->EvtchnInterface,
                  BlkifRing->Channel,
                  FALSE,
                  TRUE);
}

static NTSTATUS
BlkifRingCreate(
    IN  PXENVBD_RING        Ring,
    IN  ULONG               Index,
    OUT PXENVBD_BLKIF_RING* BlkifRing
    )
{
    PXENVBD_FRONTEND        Frontend;
    ULONG                   Length;
    PCHAR                   Path;
    CHAR                    Name[MAX_NAME_LEN];
    NTSTATUS                status;

    Frontend = Ring->Frontend;

    Length = (ULONG)strlen(FrontendGetFrontendPath(Frontend)) +
        (ULONG)strlen("/queue-xxx");

    Path = __RingAllocate(Length + 1);

    status = STATUS_NO_MEMORY;
    if (Path == NULL)
        goto fail1;

    status = RtlStringCchPrintfA(Path,
                                 Length,
                                 "%s/queue-%u",
                                 FrontendGetFrontendPath(Frontend),
                                 Index);
    if (!NT_SUCCESS(status))
        goto fail2;

    *BlkifRing = __RingAllocate(sizeof(XENVBD_BLKIF_RING));

    status = STATUS_NO_MEMORY;
    if (*BlkifRing == NULL)
        goto fail3;

    (*BlkifRing)->Ring = Ring;
    (*BlkifRing)->Index = Index;
    (*BlkifRing)->Path = Path;
    Path = NULL;

    InitializeListHead(&(*BlkifRing)->SrbQueue);
    InitializeListHead(&(*BlkifRing)->ShutdownQueue);
    InitializeListHead(&(*BlkifRing)->SubmittedList);
    InitializeListHead(&(*BlkifRing)->State.List);

    KeInitializeThreadedDpc(&(*BlkifRing)->Dpc, BlkifRingDpc, *BlkifRing);

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_queue_%u_request",
                                FrontendGetTargetId(Frontend),
                                Index);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_CACHE(Create,
                          &Ring->CacheInterface,
                          Name,
                          sizeof(XENVBD_REQUEST),
                          0,
                          BlkifRingRequestCtor,
                          BlkifRingRequestDtor,
                          BlkifRingAcquireLock,
                          BlkifRingReleaseLock,
                          *BlkifRing,
                          &(*BlkifRing)->RequestCache);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_queue_%u_segment",
                                FrontendGetTargetId(Frontend),
                                Index);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = XENBUS_CACHE(Create,
                          &Ring->CacheInterface,
                          Name,
                          sizeof(XENVBD_SEGMENT),
                          0,
                          BlkifRingSegmentCtor,
                          BlkifRingSegmentDtor,
                          BlkifRingAcquireLock,
                          BlkifRingReleaseLock,
                          *BlkifRing,
                          &(*BlkifRing)->SegmentCache);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_queue_%u_indirect",
                                FrontendGetTargetId(Frontend),
                                Index);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = XENBUS_CACHE(Create,
                          &Ring->CacheInterface,
                          Name,
                          sizeof(XENVBD_INDIRECT),
                          0,
                          BlkifRingIndirectCtor,
                          BlkifRingIndirectDtor,
                          BlkifRingAcquireLock,
                          BlkifRingReleaseLock,
                          *BlkifRing,
                          &(*BlkifRing)->IndirectCache);
    if (!NT_SUCCESS(status))
        goto fail9;

    return STATUS_SUCCESS;

fail9:
    Error("fail9\n");
fail8:
    Error("fail8\n");
    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 (*BlkifRing)->SegmentCache);
    (*BlkifRing)->SegmentCache = NULL;
fail7:
    Error("fail7\n");
fail6:
    Error("fail6\n");
    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 (*BlkifRing)->RequestCache);
    (*BlkifRing)->RequestCache = NULL;
fail5:
    Error("fail5\n");
fail4:
    Error("fail4\n");

    RtlZeroMemory(&(*BlkifRing)->Dpc, sizeof(KDPC));

    RtlZeroMemory(&(*BlkifRing)->State.List, sizeof(LIST_ENTRY));
    RtlZeroMemory(&(*BlkifRing)->SubmittedList, sizeof(LIST_ENTRY));
    RtlZeroMemory(&(*BlkifRing)->ShutdownQueue, sizeof(LIST_ENTRY));
    RtlZeroMemory(&(*BlkifRing)->SrbQueue, sizeof(LIST_ENTRY));

    __RingFree((*BlkifRing)->Path);
    (*BlkifRing)->Path;
    (*BlkifRing)->Index = 0;
    (*BlkifRing)->Ring = NULL;

    ASSERT(IsZeroMemory(*BlkifRing, sizeof(XENVBD_BLKIF_RING)));
    __RingFree(*BlkifRing);
    *BlkifRing = NULL;
fail3:
    Error("fail3\n");
fail2:
    Error("fail2\n");
    __RingFree(Path);
fail1:
    Error("fail1 (%08x)\n", status);
    return status;
}

static VOID
BlkifRingDestroy(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;

    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 BlkifRing->IndirectCache);
    BlkifRing->IndirectCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 BlkifRing->SegmentCache);
    BlkifRing->SegmentCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 BlkifRing->RequestCache);
    BlkifRing->RequestCache = NULL;

    RtlZeroMemory(&BlkifRing->Dpc, sizeof(KDPC));

    ASSERT3U(BlkifRing->State.Count, == , 0);
    ASSERT(IsListEmpty(&BlkifRing->State.List));
    RtlZeroMemory(&BlkifRing->State.List, sizeof(LIST_ENTRY));

    RtlZeroMemory(&BlkifRing->SubmittedList, sizeof(LIST_ENTRY));
    RtlZeroMemory(&BlkifRing->SrbQueue, sizeof(LIST_ENTRY));
    RtlZeroMemory(&BlkifRing->ShutdownQueue, sizeof(LIST_ENTRY));

    __RingFree(BlkifRing->Path);
    BlkifRing->Path = NULL;
    BlkifRing->Index = 0;
    BlkifRing->Ring = NULL;

    ASSERT(IsZeroMemory(BlkifRing, sizeof(XENVBD_BLKIF_RING)));
    __RingFree(BlkifRing);
}

static NTSTATUS
BlkifRingConnect(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Frontend);
    CHAR                    Name[MAX_NAME_LEN];
    ULONG                   Index;
    NTSTATUS                status;

    Trace("====> %u\n", BlkifRing->Index);
    ASSERT(!BlkifRing->Connected);

    if (FrontendGetNumQueues(Frontend) != 1) {
        PROCESSOR_NUMBER    ProcNumber;

        status = KeGetProcessorNumberFromIndex(BlkifRing->Index, &ProcNumber);
        ASSERT(NT_SUCCESS(status));

        status = KeSetTargetProcessorDpcEx(&BlkifRing->Dpc, &ProcNumber);
        ASSERT(NT_SUCCESS(status));
    }
    KeSetImportanceDpc(&BlkifRing->Dpc, MediumHighImportance);

    BlkifRing->Mdl = __AllocatePages(1 << Ring->Order);

    status = STATUS_NO_MEMORY;
    if (BlkifRing->Mdl == NULL)
        goto fail1;

    BlkifRing->Shared = MmGetSystemAddressForMdlSafe(BlkifRing->Mdl,
                                                     NormalPagePriority);
    ASSERT(BlkifRing->Shared != NULL);

#pragma warning(push)
#pragma warning(disable: 4305)
#pragma warning(disable: 4311) // 'type cast' pointer truncation from 'blkif_sring_entry[1]' to 'long'
    SHARED_RING_INIT(BlkifRing->Shared);
    FRONT_RING_INIT(&BlkifRing->Front, BlkifRing->Shared, PAGE_SIZE << Ring->Order);
#pragma warning(pop)

    for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
        status = GranterGet(Granter,
                            MmGetMdlPfnArray(BlkifRing->Mdl)[Index],
                            FALSE,
                            &BlkifRing->Grants[Index]);
        if (!NT_SUCCESS(status))
            goto fail2;
    }

    BlkifRing->Channel = XENBUS_EVTCHN(Open,
                                       &Ring->EvtchnInterface,
                                       XENBUS_EVTCHN_TYPE_UNBOUND,
                                       BlkifRingInterrupt,
                                       BlkifRing,
                                       FrontendGetBackendDomain(Ring->Frontend),
                                       TRUE);
    status = STATUS_NO_MEMORY;
    if (BlkifRing->Channel == NULL)
        goto fail3;

    XENBUS_EVTCHN(Unmask,
                  &Ring->EvtchnInterface,
                  BlkifRing->Channel,
                  FALSE,
                  TRUE);

    status = RtlStringCchPrintfA(Name,
                                 MAX_NAME_LEN,
                                 __MODULE__"|RING[%u]",
                                 BlkifRing->Index);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_DEBUG(Register,
                          &Ring->DebugInterface,
                          Name,
                          BlkifRingDebugCallback,
                          BlkifRing,
                          &BlkifRing->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail5;

    BlkifRing->Connected = TRUE;
    Trace("<==== %u\n", BlkifRing->Index);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");
fail4:
    Error("fail4\n");
    XENBUS_EVTCHN(Close,
                  &Ring->EvtchnInterface,
                  BlkifRing->Channel);
    BlkifRing->Channel = NULL;
fail3:
    Error("fail3\n");
fail2:
    Error("fail2\n");
    for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
        if (BlkifRing->Grants[Index] == NULL)
            continue;

        GranterPut(Granter, BlkifRing->Grants[Index]);
        BlkifRing->Grants[Index] = NULL;
    }

    RtlZeroMemory(&BlkifRing->Front, sizeof(blkif_front_ring_t));

    __FreePages(BlkifRing->Mdl);
    BlkifRing->Shared = NULL;
    BlkifRing->Mdl = NULL;
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static NTSTATUS
BlkifRingStoreWrite(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PVOID               Transaction
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_FRONTEND        Frontend = Ring->Frontend;
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Frontend);
    PCHAR                   Path;
    NTSTATUS                status;

    Path = (FrontendGetNumQueues(Frontend) == 1) ?
        FrontendGetFrontendPath(Frontend) :
        BlkifRing->Path;

    status = XENBUS_STORE(Printf,
                          &Ring->StoreInterface,
                          Transaction,
                          Path,
                          "event-channel",
                          "%u",
                          XENBUS_EVTCHN(GetPort,
                                        &Ring->EvtchnInterface,
                                        BlkifRing->Channel));
    if (!NT_SUCCESS(status))
        goto fail1;

    if (Ring->Order == 0) {
        status = XENBUS_STORE(Printf,
                              &Ring->StoreInterface,
                              Transaction,
                              Path,
                              "ring-ref",
                              "%u",
                              GranterReference(Granter, BlkifRing->Grants[0]));
        if (!NT_SUCCESS(status))
            goto fail2;
    } else {
        ULONG           Index;

        for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
            CHAR        Name[MAX_NAME_LEN + 1];

            status = RtlStringCchPrintfA(Name,
                                         MAX_NAME_LEN,
                                         "ring-ref%u",
                                         Index);
            if (!NT_SUCCESS(status))
                goto fail3;

            status = XENBUS_STORE(Printf,
                                  &Ring->StoreInterface,
                                  Transaction,
                                  Path,
                                  Name,
                                  "%u",
                                  GranterReference(Granter, BlkifRing->Grants[Index]));
            if (!NT_SUCCESS(status))
                goto fail4;
        }
    }

    return STATUS_SUCCESS;

fail4:
fail3:
fail2:
fail1:
    return status;
}

static VOID
BlkifRingEnable(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    Trace("====> %u\n", BlkifRing->Index);

    __BlkifRingAcquireLock(BlkifRing);
    ASSERT(!BlkifRing->Enabled);
    BlkifRing->Enabled = TRUE;
    __BlkifRingReleaseLock(BlkifRing);

    Trace("<==== %u\n", BlkifRing->Index);
}

static VOID
BlkifRingDisable(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    ULONG                   Attempt;

    Trace("====> %u\n", BlkifRing->Index);

    __BlkifRingAcquireLock(BlkifRing);
    ASSERT(BlkifRing->Enabled);

    // Discard any pending requests
    while (!IsListEmpty(&BlkifRing->State.List)) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_REQUEST     Request;
        PXENVBD_SRBEXT      SrbExt;
        PSCSI_REQUEST_BLOCK Srb;

        ListEntry = RemoveHeadList(&BlkifRing->State.List);
        ASSERT3P(ListEntry, != , &BlkifRing->State.List);
        --BlkifRing->State.Count;

        Request = CONTAINING_RECORD(ListEntry,
                                    XENVBD_REQUEST,
                                    ListEntry);
        SrbExt = Request->SrbExt;
        Srb = SrbExt->Srb;
        Srb->SrbStatus = SRB_STATUS_ABORTED;
        Srb->ScsiStatus = 0x40; // SCSI_ABORTED

        BlkifRingPutRequest(BlkifRing, Request);

        if (InterlockedDecrement(&SrbExt->RequestCount) == 0)
            __BlkifRingCompleteSrb(BlkifRing, SrbExt);
    }

    ASSERT3U(BlkifRing->State.Count, == , 0);

    Attempt = 0;
    ASSERT3U(BlkifRing->RequestsPushed, == , BlkifRing->RequestsPosted);
    while (BlkifRing->ResponsesProcessed != BlkifRing->RequestsPushed) {
        Attempt++;
        ASSERT(Attempt < 100);

        // Try to move things along
        __BlkifRingSend(BlkifRing);
        (VOID)BlkifRingPoll(BlkifRing);

        // We are waiting for a watch event at DISPATCH_LEVEL so
        // it is our responsibility to poll the store ring.
        XENBUS_STORE(Poll,
                     &Ring->StoreInterface);

        KeStallExecutionProcessor(1000);    // 1ms
    }

    BlkifRing->Enabled = FALSE;
    __BlkifRingReleaseLock(BlkifRing);

    Trace("<==== %u\n", BlkifRing->Index);
}

static VOID
BlkifRingDisconnect(
    IN  PXENVBD_BLKIF_RING  BlkifRing
    )
{
    PXENVBD_RING            Ring = BlkifRing->Ring;
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Ring->Frontend);
    ULONG                   Index;

    Trace("====> %u\n", BlkifRing->Index);
    ASSERT(BlkifRing->Connected);

    XENBUS_DEBUG(Deregister,
                 &Ring->DebugInterface,
                 BlkifRing->DebugCallback);
    BlkifRing->DebugCallback = NULL;

    XENBUS_EVTCHN(Close,
                  &Ring->EvtchnInterface,
                  BlkifRing->Channel);
    BlkifRing->Channel = NULL;

    for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
        if (BlkifRing->Grants[Index] == NULL)
            continue;

        GranterPut(Granter, BlkifRing->Grants[Index]);
        BlkifRing->Grants[Index] = NULL;
    }

    RtlZeroMemory(&BlkifRing->Front, sizeof(blkif_front_ring_t));

    __FreePages(BlkifRing->Mdl);
    BlkifRing->Shared = NULL;
    BlkifRing->Mdl = NULL;

    BlkifRing->Events = 0;
    BlkifRing->Dpcs = 0;
    BlkifRing->RequestsPosted = 0;
    BlkifRing->RequestsPushed = 0;
    BlkifRing->ResponsesProcessed = 0;

    BlkifRing->Connected = FALSE;

    Trace("<==== %u\n", BlkifRing->Index);
}

static VOID
__BlkifRingQueueSrb(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PLIST_ENTRY             ListEntry;
    ULONG_PTR               Old;
    ULONG_PTR               LockBit;
    ULONG_PTR               New;

    ListEntry = &SrbExt->ListEntry;

    do {
        Old = (ULONG_PTR)BlkifRing->Lock;
        LockBit = Old & XENVBD_LOCK_BIT;

        ListEntry->Blink = (PVOID)(Old & ~XENVBD_LOCK_BIT);
        New = (ULONG_PTR)ListEntry;
        ASSERT((New & XENVBD_LOCK_BIT) == 0);
        New |= LockBit;
    } while ((ULONG_PTR)InterlockedCompareExchangePointer(&BlkifRing->Lock, (PVOID)New, (PVOID)Old) != Old);

    // __BlkifRingReleaseLock() drains the atomic SRB list into the queue therefore,
    // after adding to the list we need to attempt to grab and release the lock. If we can't
    // grab it then that's ok because whichever thread is holding it will have to call
    // __BlkifRingReleaseLock() and will therefore drain the atomic packet list.

    if (__BlkifRingTryAcquireLock(BlkifRing))
        __BlkifRingReleaseLock(BlkifRing);
}

static VOID
__BlkifRingQueueShutdown(
    IN  PXENVBD_BLKIF_RING  BlkifRing,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    __BlkifRingAcquireLock(BlkifRing);
    InsertTailList(&BlkifRing->ShutdownQueue, &SrbExt->ListEntry);
    __BlkifRingReleaseLock(BlkifRing);
}

static DECLSPEC_NOINLINE VOID
RingDebugCallback(
    IN  PVOID       Argument,
    IN  BOOLEAN     Crashing
    )
{
    PXENVBD_RING    Ring = Argument;
    XENVBD_STAT     Index;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Order: %d\n",
                 Ring->Order);

    for (Index = 0; Index < XENVBD_STAT__MAX; ++Index) {
        XENBUS_DEBUG(Printf,
                     &Ring->DebugInterface,
                     "%s: %u\n",
                     __StatName(Index),
                     Ring->Stats[Index]);
    }
}

NTSTATUS
RingCreate(
    IN  PXENVBD_FRONTEND    Frontend,
    OUT PXENVBD_RING*       Ring
    )
{
    PXENVBD_TARGET          Target = FrontendGetTarget(Frontend);
    PXENVBD_ADAPTER         Adapter = TargetGetAdapter(Target);
    ULONG                   MaxQueues;
    ULONG                   Index;
    NTSTATUS                status;

    *Ring = __RingAllocate(sizeof(XENVBD_RING));

    status = STATUS_NO_MEMORY;
    if (*Ring == NULL)
        goto fail1;

    AdapterGetDebugInterface(Adapter,
                             &(*Ring)->DebugInterface);
    AdapterGetStoreInterface(Adapter,
                             &(*Ring)->StoreInterface);
    AdapterGetCacheInterface(Adapter,
                             &(*Ring)->CacheInterface);
    AdapterGetEvtchnInterface(Adapter,
                              &(*Ring)->EvtchnInterface);

    (*Ring)->Frontend = Frontend;

    MaxQueues = FrontendGetMaxQueues(Frontend);
    (*Ring)->Ring = __RingAllocate(sizeof(PXENVBD_BLKIF_RING) *
                                   MaxQueues);

    status = STATUS_NO_MEMORY;
    if ((*Ring)->Ring == NULL)
        goto fail2;

    Index = 0;
    while (Index < MaxQueues) {
        PXENVBD_BLKIF_RING  BlkifRing;

        status = BlkifRingCreate(*Ring, Index, &BlkifRing);
        if (!NT_SUCCESS(status))
            goto fail3;

        (*Ring)->Ring[Index] = BlkifRing;
        Index++;
    }

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    while (--Index > 0) {
        PXENVBD_BLKIF_RING  BlkifRing = (*Ring)->Ring[Index];

        (*Ring)->Ring[Index] = NULL;
        BlkifRingDestroy(BlkifRing);
    }

    __RingFree((*Ring)->Ring);
    (*Ring)->Ring = NULL;

fail2:
    Error("fail2\n");

    (*Ring)->Frontend = NULL;

    RtlZeroMemory(&(*Ring)->CacheInterface,
                  sizeof(XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&(*Ring)->EvtchnInterface,
                  sizeof(XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&(*Ring)->StoreInterface,
                  sizeof(XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Ring)->DebugInterface,
                  sizeof(XENBUS_DEBUG_INTERFACE));

    ASSERT(IsZeroMemory(*Ring, sizeof(XENVBD_RING)));
    __RingFree(*Ring);

fail1:
    Error("fail1 (%08x)\n", status);
    return status;
}

VOID
RingDestroy(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               Index;

    Index = FrontendGetMaxQueues(Ring->Frontend);
    ASSERT3U(Index, !=, 0);

    while (--Index != 0) {
        PXENVBD_BLKIF_RING  BlkifRing = Ring->Ring[Index];

        Ring->Ring[Index] = NULL;
        BlkifRingDestroy(BlkifRing);
    }

    __RingFree(Ring->Ring);
    Ring->Ring = NULL;

    Ring->Frontend = NULL;

    RtlZeroMemory(&Ring->CacheInterface,
                  sizeof(XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&Ring->EvtchnInterface,
                  sizeof(XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&Ring->StoreInterface,
                  sizeof(XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Ring->DebugInterface,
                  sizeof(XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(Ring->Stats, sizeof(Ring->Stats));

    ASSERT(IsZeroMemory(Ring, sizeof(XENVBD_RING)));
    __RingFree(Ring);
}

NTSTATUS
RingConnect(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               MaxQueues;
    ULONG               Index;
    PCHAR               Buffer;
    NTSTATUS            status;

    status = XENBUS_DEBUG(Acquire, &Ring->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Ring->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_CACHE(Acquire, &Ring->CacheInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_EVTCHN(Acquire, &Ring->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_STORE(Read,
                          &Ring->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Ring->Frontend),
                          "max-ring-page-order",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        ULONG           MaxOrder;

        if (DriverGetFeatureOverride(FeatureMaxRingPageOrder,
                                     &MaxOrder)) {
            MaxOrder = min(MaxOrder, XENVBD_MAX_RING_PAGE_ORDER);
        } else {
            MaxOrder = XENVBD_MAX_RING_PAGE_ORDER;
        }

        Ring->Order = strtoul(Buffer, NULL, 10);
        Ring->Order = min(Ring->Order, MaxOrder);

        XENBUS_STORE(Free,
                     &Ring->StoreInterface,
                     Buffer);
    } else {
        Ring->Order = 0;
    }

    MaxQueues = FrontendGetNumQueues(Ring->Frontend);
    Index = 0;
    while (Index < MaxQueues) {
        PXENVBD_BLKIF_RING  BlkifRing = Ring->Ring[Index];

        status = BlkifRingConnect(BlkifRing);
        if (!NT_SUCCESS(status))
            goto fail5;

        ++Index;
    }

    status = XENBUS_DEBUG(Register,
                          &Ring->DebugInterface,
                          __MODULE__"|RING",
                          RingDebugCallback,
                          Ring,
                          &Ring->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail6;

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");
    Index = FrontendGetNumQueues(Ring->Frontend);
fail5:
    Error("fail5\n");

    while (Index != 0) {
        PXENVBD_BLKIF_RING  BlkifRing;

        --Index;
        BlkifRing = Ring->Ring[Index];

        BlkifRingDisconnect(BlkifRing);
    }

    XENBUS_EVTCHN(Release, &Ring->EvtchnInterface);

fail4:
    Error("fail4\n");

    XENBUS_CACHE(Release, &Ring->CacheInterface);

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Ring->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Ring->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);
    return status;
}

NTSTATUS
RingStoreWrite(
    IN  PXENVBD_RING    Ring,
    IN  PVOID           Transaction
    )
{
    ULONG               NumQueues;
    ULONG               Index;
    NTSTATUS            status;

    NumQueues = FrontendGetNumQueues(Ring->Frontend);
    Index = 0;
    while (Index < NumQueues) {
        PXENVBD_BLKIF_RING  BlkifRing = Ring->Ring[Index];

        status = BlkifRingStoreWrite(BlkifRing, Transaction);
        if (!NT_SUCCESS(status))
            goto fail1;

        ++Index;
    }

    status = XENBUS_STORE(Printf,
                          &Ring->StoreInterface,
                          Transaction,
                          FrontendGetFrontendPath(Ring->Frontend),
                          "multi-queue-num-queues",
                          "%u",
                          NumQueues);
    if (!NT_SUCCESS(status))
        goto fail2;

    if (Ring->Order != 0) {
        status = XENBUS_STORE(Printf,
                              &Ring->StoreInterface,
                              Transaction,
                              FrontendGetFrontendPath(Ring->Frontend),
                              "ring-page-order",
                              "%u",
                              Ring->Order);
        if (!NT_SUCCESS(status))
            goto fail3;
    }

    status = XENBUS_STORE(Printf,
                          &Ring->StoreInterface,
                          Transaction,
                          FrontendGetFrontendPath(Ring->Frontend),
                          "protocol",
                          XEN_IO_PROTO_ABI);
    if (!NT_SUCCESS(status))
        goto fail4;

    return STATUS_SUCCESS;

fail4:
fail3:
fail2:
fail1:
    return status;
}

VOID
RingEnable(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               NumQueues;
    ULONG               Index;

    NumQueues = FrontendGetNumQueues(Ring->Frontend);
    Index = 0;
    while (Index < NumQueues) {
        PXENVBD_BLKIF_RING  BlkifRing = Ring->Ring[Index];

        BlkifRingEnable(BlkifRing);

        ++Index;
    }
}

VOID
RingDisable(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               Index;

    Index = FrontendGetNumQueues(Ring->Frontend);
    while (Index != 0) {
        PXENVBD_BLKIF_RING  BlkifRing;

        --Index;
        BlkifRing = Ring->Ring[Index];
        BlkifRingDisable(BlkifRing);
    }
}

VOID
RingDisconnect(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               Index;

    XENBUS_DEBUG(Deregister,
                 &Ring->DebugInterface,
                 Ring->DebugCallback);
    Ring->DebugCallback = NULL;

    Index = FrontendGetNumQueues(Ring->Frontend);

    while (Index != 0) {
        PXENVBD_BLKIF_RING  BlkifRing;

        --Index;
        BlkifRing = Ring->Ring[Index];

        BlkifRingDisconnect(BlkifRing);
    }

    Ring->Order = 0;

    XENBUS_EVTCHN(Release, &Ring->EvtchnInterface);
    XENBUS_CACHE(Release, &Ring->CacheInterface);
    XENBUS_STORE(Release, &Ring->StoreInterface);
    XENBUS_DEBUG(Release, &Ring->DebugInterface);
}

static FORCEINLINE PXENVBD_BLKIF_RING
__RingGetBlkifRing(
    IN  PXENVBD_RING    Ring,
    IN  ULONG           Tag
    )
{
    ULONG               Value;
    ULONG               Index;

    if (Tag == 0)
        Value = KeGetCurrentProcessorNumberEx(NULL);
    else
        Value = Tag;

    Index = Value % FrontendGetNumQueues(Ring->Frontend);

    return Ring->Ring[Index];
}

BOOLEAN
RingQueueRequest(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PXENVBD_BLKIF_RING  BlkifRing;

    BlkifRing = __RingGetBlkifRing(Ring, Srb->QueueTag);
    ASSERT(BlkifRing != NULL);

    __BlkifRingQueueSrb(BlkifRing, SrbExt);

    return TRUE;
}

VOID
RingQueueShutdown(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PXENVBD_BLKIF_RING  BlkifRing;

    BlkifRing = __RingGetBlkifRing(Ring, Srb->QueueTag);
    ASSERT(BlkifRing != NULL);

    __BlkifRingQueueShutdown(BlkifRing, SrbExt);
}
