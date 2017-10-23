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
#include "queue.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

#define XENVBD_MAX_RING_PAGE_ORDER  (4)
#define XENVBD_MAX_RING_PAGES       (1 << XENVBD_MAX_RING_PAGE_ORDER)

struct _XENVBD_RING {
    PXENVBD_FRONTEND                Frontend;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;

    XENBUS_CACHE_INTERFACE          CacheInterface;
    XENBUS_STORE_INTERFACE          StoreInterface;
    XENBUS_EVTCHN_INTERFACE         EvtchnInterface;
    XENBUS_DEBUG_INTERFACE          DebugInterface;

    PXENBUS_DEBUG_CALLBACK          DebugCallback;

    KSPIN_LOCK                      Lock;
    PMDL                            Mdl;
    blkif_sring_t*                  Shared;
    blkif_front_ring_t              Front;
    ULONG                           Order;
    PVOID                           Grants[XENVBD_MAX_RING_PAGES];
    PXENBUS_EVTCHN_CHANNEL          Channel;
    KDPC                            Dpc;
    KDPC                            TimerDpc;
    KTIMER                          Timer;

    PXENBUS_CACHE                   RequestCache;
    PXENBUS_CACHE                   SegmentCache;
    PXENBUS_CACHE                   IndirectCache;
    XENVBD_QUEUE                    FreshSrbs;
    XENVBD_QUEUE                    PreparedReqs;
    XENVBD_QUEUE                    SubmittedReqs;
    XENVBD_QUEUE                    ShutdownSrbs;

    ULONG                           Submitted;
    ULONG                           Received;
    ULONG                           Events;
    ULONG                           Dpcs;
    ULONG                           BlkOpRead;
    ULONG                           BlkOpWrite;
    ULONG                           BlkOpIndirectRead;
    ULONG                           BlkOpIndirectWrite;
    ULONG                           BlkOpBarrier;
    ULONG                           BlkOpDiscard;
    ULONG                           BlkOpFlush;
    ULONG64                         SegsGranted;
    ULONG64                         SegsBounced;
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

static FORCEINLINE VOID
xen_mb()
{
    KeMemoryBarrier();
    _ReadWriteBarrier();
}

static FORCEINLINE VOID
xen_wmb()
{
    KeMemoryBarrier();
    _WriteBarrier();
}

static FORCEINLINE PFN_NUMBER
__Pfn(
    __in  PVOID                   VirtAddr
    )
{
    return (PFN_NUMBER)(ULONG_PTR)(MmGetPhysicalAddress(VirtAddr).QuadPart >> PAGE_SHIFT);
}

static FORCEINLINE VOID
__RingInsert(
    IN  PXENVBD_RING        Ring,
    IN  PXENVBD_REQUEST     Request,
    IN  blkif_request_t*    req
    )
{
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Ring->Frontend);

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
            req_indirect->operation         = BLKIF_OP_INDIRECT;
            req_indirect->indirect_op       = Request->Operation;
            req_indirect->nr_segments       = Request->NrSegments;
            req_indirect->id                = (ULONG64)(ULONG_PTR)Request;
            req_indirect->sector_number     = Request->FirstSector;
            req_indirect->handle            = (USHORT)FrontendGetDeviceId(Ring->Frontend);

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
                    Page->Page[SegIdx].First    = Segment->FirstSector;
                    Page->Page[SegIdx].Last     = Segment->LastSector;
                }
            }
        } else {
            // Direct
            ULONG           Index;
            PLIST_ENTRY     Entry;

            req->operation                  = Request->Operation;
            req->nr_segments                = (UCHAR)Request->NrSegments;
            req->handle                     = (USHORT)FrontendGetDeviceId(Ring->Frontend);
            req->id                         = (ULONG64)(ULONG_PTR)Request;
            req->sector_number              = Request->FirstSector;

            for (Index = 0, Entry = Request->Segments.Flink;
                    Index < BLKIF_MAX_SEGMENTS_PER_REQUEST &&
                    Entry != &Request->Segments;
                        ++Index, Entry = Entry->Flink) {
                PXENVBD_SEGMENT Segment = CONTAINING_RECORD(Entry, XENVBD_SEGMENT, ListEntry);
                req->seg[Index].gref        = GranterReference(Granter, Segment->Grant);
                req->seg[Index].first_sect  = Segment->FirstSector;
                req->seg[Index].last_sect   = Segment->LastSector;
            }
        }
        break;

    case BLKIF_OP_WRITE_BARRIER:
    case BLKIF_OP_FLUSH_DISKCACHE:
        req->operation                  = Request->Operation;
        req->nr_segments                = 0;
        req->handle                     = (USHORT)FrontendGetDeviceId(Ring->Frontend);
        req->id                         = (ULONG64)(ULONG_PTR)Request;
        req->sector_number              = Request->FirstSector;
        break;

    case BLKIF_OP_DISCARD: {
        blkif_request_discard_t*        req_discard;
        req_discard = (blkif_request_discard_t*)req;
        req_discard->operation          = BLKIF_OP_DISCARD;
        req_discard->flag               = Request->Flags;
        req_discard->handle             = (USHORT)FrontendGetDeviceId(Ring->Frontend);
        req_discard->id                 = (ULONG64)(ULONG_PTR)Request;
        req_discard->sector_number      = Request->FirstSector;
        req_discard->nr_sectors         = Request->NrSectors;
        } break;

    default:
        ASSERT(FALSE);
        break;
    }
    ++Ring->Submitted;
}

static PXENVBD_INDIRECT
RingGetIndirect(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_INDIRECT    Indirect;
    NTSTATUS            status;
    PXENVBD_GRANTER     Granter = FrontendGetGranter(Ring->Frontend);

    Indirect = XENBUS_CACHE(Get,
                            &Ring->CacheInterface,
                            Ring->IndirectCache,
                            FALSE);
    if (Indirect == NULL)
        goto fail1;

    ASSERT3P(Indirect->Mdl, !=, NULL);
    ASSERT3P(Indirect->Page, !=, NULL);
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
                 Ring->IndirectCache,
                 Indirect,
                 FALSE);
fail1:
    return NULL;
}

static VOID
RingPutIndirect(
    IN  PXENVBD_RING        Ring,
    IN  PXENVBD_INDIRECT    Indirect
    )
{
    PXENVBD_GRANTER         Granter = FrontendGetGranter(Ring->Frontend);

    if (Indirect->Grant)
        GranterPut(Granter, Indirect->Grant);
    Indirect->Grant = NULL;

    RtlZeroMemory(&Indirect->ListEntry, sizeof(LIST_ENTRY));

    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 Ring->IndirectCache,
                 Indirect,
                 FALSE);
}

static PXENVBD_SEGMENT
RingGetSegment(
    IN  PXENVBD_RING    Ring
    )
{
    return XENBUS_CACHE(Get,
                        &Ring->CacheInterface,
                        Ring->SegmentCache,
                        FALSE);
}

static VOID
RingPutSegment(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SEGMENT Segment
    )
{
    PXENVBD_GRANTER     Granter = FrontendGetGranter(Ring->Frontend);
    PXENVBD_BOUNCE      Bounce = Segment->Bounce;

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

        AdapterPutBounce(TargetGetAdapter(FrontendGetTarget(Ring->Frontend)),
                         Bounce);
    }
    Segment->Bounce = NULL;

    Segment->FirstSector = 0;
    Segment->LastSector = 0;
    RtlZeroMemory(&Segment->ListEntry, sizeof(LIST_ENTRY));

    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 Ring->SegmentCache,
                 Segment,
                 FALSE);
}

static PXENVBD_REQUEST
RingGetRequest(
    IN  PXENVBD_RING    Ring
    )
{
    return XENBUS_CACHE(Get,
                        &Ring->CacheInterface,
                        Ring->RequestCache,
                        FALSE);
}

static VOID
RingPutRequest(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_REQUEST Request
    )
{
    PLIST_ENTRY         ListEntry;

    for (;;) {
        PXENVBD_SEGMENT Segment;

        ListEntry = RemoveHeadList(&Request->Segments);
        if (ListEntry == &Request->Segments)
            break;
        Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);
        RingPutSegment(Ring, Segment);
    }

    for (;;) {
        PXENVBD_INDIRECT    Indirect;

        ListEntry = RemoveHeadList(&Request->Indirects);
        if (ListEntry == &Request->Indirects)
            break;
        Indirect = CONTAINING_RECORD(ListEntry, XENVBD_INDIRECT, ListEntry);
        RingPutIndirect(Ring, Indirect);
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
                 Ring->RequestCache,
                 Request,
                 FALSE);
}

static FORCEINLINE PXENVBD_REQUEST
RingFindRequest(
    IN  PXENVBD_RING    Ring,
    IN  ULONG64         Id
    )
{
    KIRQL               Irql;
    PLIST_ENTRY         ListEntry;
    PXENVBD_REQUEST     Request;
    PXENVBD_QUEUE       Queue = &Ring->SubmittedReqs;

    KeAcquireSpinLock(&Queue->Lock, &Irql);

    for (ListEntry = Queue->List.Flink;
         ListEntry != &Queue->List;
         ListEntry = ListEntry->Flink) {
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        if ((ULONG64)(ULONG_PTR)Request == Id) {
            RemoveEntryList(&Request->ListEntry);
            --Queue->Current;
            KeReleaseSpinLock(&Queue->Lock, Irql);
            return Request;
        }
    }

    KeReleaseSpinLock(&Queue->Lock, Irql);
    Warning("Target[%d] : Tag %llx not found in submitted list (%u items)\n",
            FrontendGetTargetId(Ring->Frontend),
            Id,
            QueueCount(Queue));
    return NULL;
}

static FORCEINLINE VOID
__RingIncBlkifOpCount(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_REQUEST Request
    )
{
    switch (Request->Operation) {
    case BLKIF_OP_READ:
        if (Request->NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST)
            ++Ring->BlkOpIndirectRead;
        else
            ++Ring->BlkOpRead;
        break;
    case BLKIF_OP_WRITE:
        if (Request->NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST)
            ++Ring->BlkOpIndirectWrite;
        else
            ++Ring->BlkOpWrite;
        break;
    case BLKIF_OP_WRITE_BARRIER:
        ++Ring->BlkOpBarrier;
        break;
    case BLKIF_OP_DISCARD:
        ++Ring->BlkOpDiscard;
        break;
    case BLKIF_OP_FLUSH_DISKCACHE:
        ++Ring->BlkOpFlush;
        break;
    default:
        ASSERT(FALSE);
        break;
    }
}

static FORCEINLINE ULONG
__RingSectorsPerPage(
    IN  ULONG   SectorSize
    )
{
    ASSERT3U(SectorSize, !=, 0);
    return PAGE_SIZE / SectorSize;
}

static FORCEINLINE VOID
__RingOperation(
    IN  UCHAR       CdbOp,
    OUT PUCHAR      RingOp,
    OUT PBOOLEAN    ReadOnly
    )
{
    switch (CdbOp) {
    case SCSIOP_READ:
        *RingOp     = BLKIF_OP_READ;
        *ReadOnly   = FALSE;
        break;
    case SCSIOP_WRITE:
        *RingOp     = BLKIF_OP_WRITE;
        *ReadOnly   = TRUE;
        break;
    default:
        ASSERT(FALSE);
    }
}

static FORCEINLINE MM_PAGE_PRIORITY
__RingPriority(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_CAPS        Caps = FrontendGetCaps(Ring->Frontend);
    if (!(Caps->Paging ||
          Caps->Hibernation ||
          Caps->DumpFile))
        return NormalPagePriority;

    return HighPagePriority;
}

static FORCEINLINE VOID
RingRequestCopyOutput(
    IN  PXENVBD_REQUEST Request
    )
{
    PLIST_ENTRY         ListEntry;

    if (Request->Operation != BLKIF_OP_READ)
        return;

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
}

static BOOLEAN
RingPrepareSegment(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SEGMENT Segment,
    IN  PXENVBD_SRBEXT  SrbExt,
    IN  BOOLEAN         ReadOnly,
    IN  ULONG           SectorsLeft,
    OUT PULONG          SectorsNow
    )
{
    PFN_NUMBER          Pfn;
    ULONG               Offset;
    ULONG               Length;
    NTSTATUS            Status;
    PXENVBD_GRANTER     Granter = FrontendGetGranter(Ring->Frontend);
    const ULONG         SectorSize = FrontendGetDiskInfo(Ring->Frontend)->SectorSize;
    const ULONG         SectorsPerPage = __RingSectorsPerPage(SectorSize);
    PXENVBD_TARGET      Target = FrontendGetTarget(Ring->Frontend);
    PXENVBD_ADAPTER     Adapter = TargetGetAdapter(Target);

    Pfn = AdapterGetNextSGEntry(Adapter,
                                SrbExt,
                                0,
                                &Offset,
                                &Length);
    if ((Offset & (SectorSize - 1)) == 0 &&
        (Length & (SectorSize - 1)) == 0) {
        ++Ring->SegsGranted;
        // get first sector, last sector and count
        Segment->FirstSector    = (UCHAR)((Offset + SectorSize - 1) / SectorSize);
        *SectorsNow             = __min(SectorsLeft, SectorsPerPage - Segment->FirstSector);
        Segment->LastSector     = (UCHAR)(Segment->FirstSector + *SectorsNow - 1);

        ASSERT3U((Length / SectorSize), ==, *SectorsNow);
    } else {
        PXENVBD_BOUNCE      Bounce;
        PMDL                Mdl;

        ++Ring->SegsBounced;
        // get first sector, last sector and count
        Segment->FirstSector    = 0;
        *SectorsNow             = __min(SectorsLeft, SectorsPerPage);
        Segment->LastSector     = (UCHAR)(*SectorsNow - 1);

        Bounce = AdapterGetBounce(Adapter);
        if (Bounce == NULL)
            goto fail1;
        Segment->Bounce = Bounce;

#pragma warning(push)
#pragma warning(disable:28145)
        Mdl = &Bounce->SourceMdl;
        Mdl->Next               = NULL;
        Mdl->Size               = (SHORT)(sizeof(MDL) + sizeof(PFN_NUMBER));
        Mdl->MdlFlags           = MDL_PAGES_LOCKED;
        Mdl->Process            = NULL;
        Mdl->MappedSystemVa     = NULL;
        Mdl->StartVa            = NULL;
        Mdl->ByteCount          = Length;
        Mdl->ByteOffset         = Offset;
        Bounce->SourcePfn[0]    = Pfn;

        if (Length < *SectorsNow * SectorSize) {
            Pfn = AdapterGetNextSGEntry(Adapter,
                                        SrbExt,
                                        Length,
                                        &Offset,
                                        &Length);
            Mdl->Size           += sizeof(PFN_NUMBER);
            Mdl->ByteCount      += Length;
            Bounce->SourcePfn[1] = Pfn;
        }
#pragma warning(pop)

        ASSERT((Mdl->ByteCount & (SectorSize - 1)) == 0);
        ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE);
        ASSERT3U(*SectorsNow, ==, (Mdl->ByteCount / SectorSize));

        Bounce->SourcePtr = MmMapLockedPagesSpecifyCache(Mdl,
                                                         KernelMode,
                                                         MmCached,
                                                         NULL,
                                                         FALSE,
                                                         __RingPriority(Ring));
        if (Bounce->SourcePtr == NULL)
            goto fail2;

        ASSERT3P(MmGetMdlPfnArray(Mdl)[0], ==, Bounce->SourcePfn[0]);
        ASSERT3P(MmGetMdlPfnArray(Mdl)[1], ==, Bounce->SourcePfn[1]);

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

static BOOLEAN
RingPrepareBlkifReadWrite(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_REQUEST Request,
    IN  PXENVBD_SRBEXT  SrbExt,
    IN  ULONG           MaxSegments,
    IN  ULONG64         SectorStart,
    IN  ULONG           SectorsLeft,
    OUT PULONG          SectorsDone
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    UCHAR               Operation;
    BOOLEAN             ReadOnly;
    ULONG               Index;
    __RingOperation(Cdb_OperationEx(Srb), &Operation, &ReadOnly);

    Request->Operation  = Operation;
    Request->NrSegments = 0;
    Request->FirstSector = SectorStart;

    for (Index = 0;
                Index < MaxSegments &&
                SectorsLeft > 0;
                        ++Index) {
        PXENVBD_SEGMENT Segment;
        ULONG           SectorsNow;

        Segment = RingGetSegment(Ring);
        if (Segment == NULL)
            goto fail1;

        InsertTailList(&Request->Segments, &Segment->ListEntry);
        ++Request->NrSegments;

        if (!RingPrepareSegment(Ring,
                                Segment,
                                SrbExt,
                                ReadOnly,
                                SectorsLeft,
                                &SectorsNow))
            goto fail2;

        *SectorsDone += SectorsNow;
        SectorsLeft  -= SectorsNow;
    }
    ASSERT3U(Request->NrSegments, >, 0);
    ASSERT3U(Request->NrSegments, <=, MaxSegments);

    return TRUE;

fail2:
fail1:
    return FALSE;
}

static BOOLEAN
RingPrepareBlkifIndirect(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_REQUEST Request
    )
{
    ULONG               Index;
    ULONG               NrSegments = 0;

    for (Index = 0;
            Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST &&
            NrSegments < Request->NrSegments;
                ++Index) {
        PXENVBD_INDIRECT    Indirect;

        Indirect = RingGetIndirect(Ring);
        if (Indirect == NULL)
            goto fail1;
        InsertTailList(&Request->Indirects, &Indirect->ListEntry);

        NrSegments += XENVBD_MAX_SEGMENTS_PER_PAGE;
    }

    return TRUE;

fail1:
    return FALSE;
}

static FORCEINLINE ULONG
RingUseIndirect(
    IN  PXENVBD_RING    Ring,
    IN  ULONG           SectorsLeft
    )
{
    const ULONG SectorsPerPage = __RingSectorsPerPage(FrontendGetDiskInfo(Ring->Frontend)->SectorSize);
    const ULONG MaxIndirectSegs = FrontendGetFeatures(Ring->Frontend)->Indirect;

    if (MaxIndirectSegs <= BLKIF_MAX_SEGMENTS_PER_REQUEST)
        return BLKIF_MAX_SEGMENTS_PER_REQUEST; // not supported

    if (SectorsLeft < BLKIF_MAX_SEGMENTS_PER_REQUEST * SectorsPerPage)
        return BLKIF_MAX_SEGMENTS_PER_REQUEST; // first into a single BLKIF_OP_{READ/WRITE}

    return MaxIndirectSegs;
}

static FORCEINLINE ULONG
RingQueueRequestList(
    IN  PXENVBD_RING    Ring,
    IN  PLIST_ENTRY     List
    )
{
    ULONG               Count = 0;
    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     ListEntry;

        ListEntry = RemoveHeadList(List);
        if (ListEntry == List)
            break;

        ++Count;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        __RingIncBlkifOpCount(Ring, Request);
        QueueAppend(&Ring->PreparedReqs, &Request->ListEntry);
    }
    return Count;
}

static FORCEINLINE VOID
RingCancelRequestList(
    IN  PXENVBD_RING    Ring,
    IN  PLIST_ENTRY     List
    )
{
    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     ListEntry;

        ListEntry = RemoveHeadList(List);
        if (ListEntry == List)
            break;

        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        RingPutRequest(Ring, Request);
    }
}

static BOOLEAN
RingPrepareReadWrite(
    IN  PXENVBD_RING        Ring,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT          SrbExt = Srb->SrbExtension;
    ULONG64                 SectorStart = Cdb_LogicalBlock(Srb);
    ULONG                   SectorsLeft = Cdb_TransferBlock(Srb);
    LIST_ENTRY              List;
    ULONG                   DebugCount;

    Srb->SrbStatus = SRB_STATUS_PENDING;

    InitializeListHead(&List);
    SrbExt->RequestCount = 0;

    while (SectorsLeft > 0) {
        ULONG           MaxSegments;
        ULONG           SectorsDone = 0;
        PXENVBD_REQUEST Request;

        Request = RingGetRequest(Ring);
        if (Request == NULL)
            goto fail1;
        InsertTailList(&List, &Request->ListEntry);
        InterlockedIncrement(&SrbExt->RequestCount);

        Request->SrbExt = SrbExt;
        MaxSegments = RingUseIndirect(Ring, SectorsLeft);

        if (!RingPrepareBlkifReadWrite(Ring,
                                       Request,
                                       SrbExt,
                                       MaxSegments,
                                       SectorStart,
                                       SectorsLeft,
                                       &SectorsDone))
            goto fail2;

        if (MaxSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            if (!RingPrepareBlkifIndirect(Ring, Request))
                goto fail3;
        }

        SectorsLeft -= SectorsDone;
        SectorStart += SectorsDone;
    }

    DebugCount = RingQueueRequestList(Ring, &List);
    if (DebugCount != (ULONG)SrbExt->RequestCount) {
        Trace("[%u] %d != %u\n",
              FrontendGetTargetId(Ring->Frontend),
              SrbExt->RequestCount,
              DebugCount);
    }
    return TRUE;

fail3:
fail2:
fail1:
    RingCancelRequestList(Ring, &List);
    SrbExt->RequestCount = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return FALSE;
}

static BOOLEAN
RingPrepareSyncCache(
    IN  PXENVBD_RING        Ring,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT          SrbExt = Srb->SrbExtension;
    PXENVBD_REQUEST         Request;
    LIST_ENTRY              List;
    UCHAR                   Operation;
    ULONG                   DebugCount;

    Srb->SrbStatus = SRB_STATUS_PENDING;

    if (FrontendGetDiskInfo(Ring->Frontend)->FlushCache)
        Operation = BLKIF_OP_FLUSH_DISKCACHE;
    else
        Operation = BLKIF_OP_WRITE_BARRIER;

    InitializeListHead(&List);
    SrbExt->RequestCount = 0;

    Request = RingGetRequest(Ring);
    if (Request == NULL)
        goto fail1;
    InsertTailList(&List, &Request->ListEntry);
    InterlockedIncrement(&SrbExt->RequestCount);

    Request->SrbExt     = SrbExt;
    Request->Operation  = Operation;
    Request->FirstSector = Cdb_LogicalBlock(Srb);

    DebugCount = RingQueueRequestList(Ring, &List);
    if (DebugCount != (ULONG)SrbExt->RequestCount) {
        Trace("[%u] %d != %u\n",
              FrontendGetTargetId(Ring->Frontend),
              SrbExt->RequestCount,
              DebugCount);
    }
    return TRUE;

fail1:
    RingCancelRequestList(Ring, &List);
    SrbExt->RequestCount = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return FALSE;
}

static BOOLEAN
RingPrepareUnmap(
    IN  PXENVBD_RING        Ring,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT          SrbExt = Srb->SrbExtension;
    PUNMAP_LIST_HEADER      Unmap = Srb->DataBuffer;
	ULONG                   Count = _byteswap_ushort(*(PUSHORT)Unmap->BlockDescrDataLength) / sizeof(UNMAP_BLOCK_DESCRIPTOR);
    ULONG                   Index;
    LIST_ENTRY              List;
    ULONG                   DebugCount;

    Srb->SrbStatus = SRB_STATUS_PENDING;

    InitializeListHead(&List);
    SrbExt->RequestCount = 0;

    for (Index = 0; Index < Count; ++Index) {
        PUNMAP_BLOCK_DESCRIPTOR Descr = &Unmap->Descriptors[Index];
        PXENVBD_REQUEST         Request;

        Request = RingGetRequest(Ring);
        if (Request == NULL)
            goto fail1;
        InsertTailList(&List, &Request->ListEntry);
        InterlockedIncrement(&SrbExt->RequestCount);

        Request->SrbExt         = SrbExt;
        Request->Operation      = BLKIF_OP_DISCARD;
        Request->FirstSector    = _byteswap_uint64(*(PULONG64)Descr->StartingLba);
        Request->NrSectors      = _byteswap_ulong(*(PULONG)Descr->LbaCount);
        Request->Flags          = 0;
    }

    DebugCount = RingQueueRequestList(Ring, &List);
    if (DebugCount != (ULONG)SrbExt->RequestCount) {
        Trace("[%u] %d != %u\n",
              FrontendGetTargetId(Ring->Frontend),
              SrbExt->RequestCount,
              DebugCount);
    }
    return TRUE;

fail1:
    RingCancelRequestList(Ring, &List);
    SrbExt->RequestCount = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return FALSE;
}

static FORCEINLINE BOOLEAN
RingPrepareFresh(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_SRBEXT      SrbExt;
    PLIST_ENTRY         ListEntry;

    ListEntry = QueuePop(&Ring->FreshSrbs);
    if (ListEntry == NULL)
        return FALSE;   // fresh queue is empty

    SrbExt = CONTAINING_RECORD(ListEntry, XENVBD_SRBEXT, ListEntry);

    switch (Cdb_OperationEx(SrbExt->Srb)) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        if (RingPrepareReadWrite(Ring, SrbExt->Srb))
            return TRUE;    // prepared this SRB
        break;
    case SCSIOP_SYNCHRONIZE_CACHE:
        if (RingPrepareSyncCache(Ring, SrbExt->Srb))
            return TRUE;    // prepared this SRB
        break;
    case SCSIOP_UNMAP:
        if (RingPrepareUnmap(Ring, SrbExt->Srb))
            return TRUE;    // prepared this SRB
        break;
    default:
        ASSERT(FALSE);
        break;
    }
    QueueUnPop(&Ring->FreshSrbs, &SrbExt->ListEntry);

    return FALSE;       // prepare failed
}

static BOOLEAN
RingSubmit(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_REQUEST Request
    )
{
    KIRQL               Irql;
    blkif_request_t*    req;
    BOOLEAN             Notify;

    KeAcquireSpinLock(&Ring->Lock, &Irql);
    if (RING_FULL(&Ring->Front)) {
        KeReleaseSpinLock(&Ring->Lock, Irql);
        return FALSE;
    }

    req = RING_GET_REQUEST(&Ring->Front, Ring->Front.req_prod_pvt);
    __RingInsert(Ring, Request, req);
    KeMemoryBarrier();
    ++Ring->Front.req_prod_pvt;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Ring->Front, Notify);
    KeReleaseSpinLock(&Ring->Lock, Irql);

    if (Notify) {
        if (!Ring->Enabled)
            return TRUE;

        XENBUS_EVTCHN(Send,
                      &Ring->EvtchnInterface,
                      Ring->Channel);
    }

    return TRUE;
}

static FORCEINLINE BOOLEAN
RingSubmitPrepared(
    IN  PXENVBD_RING    Ring
    )
{
    if (!Ring->Enabled) {
        if (QueueCount(&Ring->PreparedReqs))
            Warning("Target[%d] : Paused, not submitting new requests (%u)\n",
                    FrontendGetTargetId(Ring->Frontend),
                    QueueCount(&Ring->PreparedReqs));
        return FALSE;
    }

    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     ListEntry;

        ListEntry = QueuePop(&Ring->PreparedReqs);
        if (ListEntry == NULL)
            break;

        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);

        QueueAppend(&Ring->SubmittedReqs, &Request->ListEntry);
        KeMemoryBarrier();

        if (RingSubmit(Ring, Request))
            continue;

        QueueRemove(&Ring->SubmittedReqs, &Request->ListEntry);
        QueueUnPop(&Ring->PreparedReqs, &Request->ListEntry);
        return FALSE;   // ring full
    }

    return TRUE;
}

static FORCEINLINE VOID
RingCompleteShutdown(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_TARGET      Target;
    PXENVBD_ADAPTER     Adapter;

    if (QueueCount(&Ring->ShutdownSrbs) == 0)
        return;

    if (QueueCount(&Ring->FreshSrbs) ||
        QueueCount(&Ring->PreparedReqs) ||
        QueueCount(&Ring->SubmittedReqs))
        return;

    Target = FrontendGetTarget(Ring->Frontend);
    Adapter = TargetGetAdapter(Target);
    for (;;) {
        PXENVBD_SRBEXT      SrbExt;
        PSCSI_REQUEST_BLOCK Srb;
        PLIST_ENTRY         ListEntry;

        ListEntry = QueuePop(&Ring->ShutdownSrbs);
        if (ListEntry == NULL)
            break;
        SrbExt = CONTAINING_RECORD(ListEntry, XENVBD_SRBEXT, ListEntry);
        Srb = SrbExt->Srb;
        
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        AdapterCompleteSrb(Adapter, SrbExt);
    }
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

static BOOLEAN
RingSubmitRequests(
    IN  PXENVBD_RING    Ring
    )
{
    BOOLEAN             Retry = FALSE;

    for (;;) {
        // submit all prepared requests (0 or more requests)
        // return TRUE if submitted 0 or more requests from prepared queue
        // return FALSE iff ring is full
        if (!RingSubmitPrepared(Ring))
            break;

        // prepare a single SRB (into 1 or more requests)
        // return TRUE if prepare succeeded
        // return FALSE if prepare failed or fresh queue empty
        if (!RingPrepareFresh(Ring))
            break;

        // back off, check DPC timeout and try again
        Retry = TRUE;
        break;
    }

    // if no requests/SRBs outstanding, complete any shutdown SRBs
    if (!Retry)
        RingCompleteShutdown(Ring);

    return Retry;
}

static VOID
RingCompleteResponse(
    IN  PXENVBD_RING    Ring,
    IN  ULONG64         Id,
    IN  SHORT           Status
    )
{
    PXENVBD_REQUEST     Request;
    PSCSI_REQUEST_BLOCK Srb;
    PXENVBD_SRBEXT      SrbExt;

    Request = RingFindRequest(Ring, Id);
    if (Request == NULL)
        return;

    SrbExt  = Request->SrbExt;
    Srb     = SrbExt->Srb;

    switch (Status) {
    case BLKIF_RSP_OKAY:
        RingRequestCopyOutput(Request);
        break;

    case BLKIF_RSP_EOPNOTSUPP:
        // Remove appropriate feature support
        FrontendRemoveFeature(Ring->Frontend, Request->Operation);
        // Succeed this SRB, subsiquent SRBs will be succeeded instead of being passed to the backend.
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case BLKIF_RSP_ERROR:
    default:
        Warning("Target[%d] : %s BLKIF_RSP_ERROR (Tag %llx)\n",
                FrontendGetTargetId(Ring->Frontend),
                __BlkifOperationName(Request->Operation),
                Id);
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
    }

    RingPutRequest(Ring, Request);

    // complete srb
    if (InterlockedDecrement(&SrbExt->RequestCount) == 0) {
        PXENVBD_TARGET  Target = FrontendGetTarget(Ring->Frontend);
        PXENVBD_ADAPTER Adapter = TargetGetAdapter(Target);

        if (Srb->SrbStatus == SRB_STATUS_PENDING) {
            // SRB has not hit a failure condition (BLKIF_RSP_ERROR | BLKIF_RSP_EOPNOTSUPP)
            // from any of its responses. SRB must have succeeded
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            Srb->ScsiStatus = 0x00; // SCSI_GOOD
        } else {
            // Srb->SrbStatus has already been set by 1 or more requests with Status != BLKIF_RSP_OKAY
            Srb->ScsiStatus = 0x40; // SCSI_ABORTED
        }

        AdapterCompleteSrb(Adapter, SrbExt);
    }
}

static BOOLEAN
RingPoll(
    IN  PXENVBD_RING    Ring
    )
{
    BOOLEAN             Retry = FALSE;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Ring->Lock);

    // Guard against this locked region being called after the
    // lock on FrontendSetState
    if (Ring->Enabled == FALSE)
        goto done;

    for (;;) {
        ULONG   rsp_prod;
        ULONG   rsp_cons;

        KeMemoryBarrier();

        rsp_prod = Ring->Shared->rsp_prod;
        rsp_cons = Ring->Front.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod || Retry)
            break;

        while (rsp_cons != rsp_prod && !Retry) {
            blkif_response_t*   rsp;

            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
            ++rsp_cons;
            ++Ring->Received;

            RingCompleteResponse(Ring, rsp->id, rsp->status);
            RtlZeroMemory(rsp, sizeof(union blkif_sring_entry));

            if (rsp_cons - Ring->Front.rsp_cons > RING_SIZE(&Ring->Front) / 4)
                Retry = TRUE;
        }

        KeMemoryBarrier();

        Ring->Front.rsp_cons = rsp_cons;
        Ring->Shared->rsp_event = rsp_cons + 1;
    }

done:
    KeReleaseSpinLockFromDpcLevel(&Ring->Lock);

    return Retry;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static BOOLEAN
RingNotifyResponses(
    IN  PXENVBD_RING    Ring
    )
{
    BOOLEAN             Retry = FALSE;

    Retry |= RingPoll(Ring);
    Retry |= RingSubmitRequests(Ring);

    return Retry;
}

KSERVICE_ROUTINE    RingInterrupt;

BOOLEAN
RingInterrupt(
    IN  PKINTERRUPT Interrupt,
    IN  PVOID       Context
    )
{
    PXENVBD_RING    Ring = Context;

    UNREFERENCED_PARAMETER(Interrupt);

    ASSERT(Ring != NULL);

    ++Ring->Events;
    if (!Ring->Connected)
        return TRUE;

    if (KeInsertQueueDpc(&Ring->Dpc, NULL, NULL))
        ++Ring->Dpcs;

    return TRUE;
}

static FORCEINLINE BOOLEAN
__RingDpcTimeout(
    IN  PXENVBD_RING            Ring
    )
{
    KDPC_WATCHDOG_INFORMATION   Watchdog;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Ring);

    RtlZeroMemory(&Watchdog, sizeof (Watchdog));

    status = KeQueryDpcWatchdogInformation(&Watchdog);
    ASSERT(NT_SUCCESS(status));

    if (Watchdog.DpcTimeLimit == 0 ||
        Watchdog.DpcWatchdogLimit == 0)
        return FALSE;

    if (Watchdog.DpcTimeCount > (Watchdog.DpcTimeLimit / 2) &&
        Watchdog.DpcWatchdogCount > (Watchdog.DpcWatchdogLimit / 2))
        return FALSE;

    return TRUE;
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

KDEFERRED_ROUTINE RingDpc;

VOID
RingDpc(
    __in  PKDPC     Dpc,
    __in_opt PVOID  Context,
    __in_opt PVOID  Arg1,
    __in_opt PVOID  Arg2
    )
{
    PXENVBD_RING    Ring = Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ASSERT(Ring != NULL);

    if (!Ring->Connected)
        return;

    for (;;) {
        if (!RingNotifyResponses(Ring)) {
            XENBUS_EVTCHN(Unmask,
                          &Ring->EvtchnInterface,
                          Ring->Channel,
                          FALSE);
            break;
        }
        if (__RingDpcTimeout(Ring)) {
            LARGE_INTEGER   Delay;

            Delay.QuadPart = TIME_RELATIVE(TIME_US(100));

            KeSetTimer(&Ring->Timer,
                       Delay,
                       &Ring->TimerDpc);
            break;
        }
    }
}

static DECLSPEC_NOINLINE VOID
RingDebugCallback(
    IN  PVOID       Argument,
    IN  BOOLEAN     Crashing
    )
{
    PXENVBD_RING    Ring = Argument;
    PXENVBD_GRANTER Granter = FrontendGetGranter(Ring->Frontend);
    ULONG           Index;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Submitted: %u Received: %u\n",
                 Ring->Submitted,
                 Ring->Received);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Events: %u Dpcs: %u\n",
                 Ring->Events,
                 Ring->Dpcs);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Shared : 0x%p\n",
                 Ring->Shared);

    if (Ring->Shared) {
        XENBUS_DEBUG(Printf,
                     &Ring->DebugInterface,
                     "Shared: %d / %d - %d / %d\n",
                     Ring->Shared->req_prod,
                     Ring->Shared->req_event,
                     Ring->Shared->rsp_prod,
                     Ring->Shared->rsp_event);
    }

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Front: %d / %d (%d)\n",
                 Ring->Front.req_prod_pvt,
                 Ring->Front.rsp_cons,
                 Ring->Front.nr_ents);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Order: %d\n",
                 Ring->Order);

    for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
        XENBUS_DEBUG(Printf,
                     &Ring->DebugInterface,
                     "Grants[%-2d]: 0x%p (%u)\n",
                     Index,
                     Ring->Grants[Index],
                     GranterReference(Granter, Ring->Grants[Index]));
    }

    if (Ring->Channel) {
        ULONG       Port = XENBUS_EVTCHN(GetPort,
                                         &Ring->EvtchnInterface,
                                         Ring->Channel);

        XENBUS_DEBUG(Printf,
                     &Ring->DebugInterface,
                     "Channel : %p (%d)\n",
                     Ring->Channel,
                     Port);
    }

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "TARGET: BLKIF_OPs: READ=%u WRITE=%u\n",
                 Ring->BlkOpRead,
                 Ring->BlkOpWrite);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "TARGET: BLKIF_OPs: INDIRECT_READ=%u INDIRECT_WRITE=%u\n",
                 Ring->BlkOpIndirectRead,
                 Ring->BlkOpIndirectWrite);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "TARGET: BLKIF_OPs: BARRIER=%u DISCARD=%u FLUSH=%u\n",
                 Ring->BlkOpBarrier,
                 Ring->BlkOpDiscard,
                 Ring->BlkOpFlush);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "TARGET: Segments Granted=%llu Bounced=%llu\n",
                 Ring->SegsGranted,
                 Ring->SegsBounced);

    QueueDebugCallback(&Ring->FreshSrbs,
                       "Fresh    ",
                       &Ring->DebugInterface);
    QueueDebugCallback(&Ring->PreparedReqs,
                       "Prepared ",
                       &Ring->DebugInterface);
    QueueDebugCallback(&Ring->SubmittedReqs,
                       "Submitted",
                       &Ring->DebugInterface);
    QueueDebugCallback(&Ring->ShutdownSrbs,
                       "Shutdown ",
                       &Ring->DebugInterface);
}

static DECLSPEC_NOINLINE VOID
RingAcquireLock(
    IN  PVOID       Argument
    )
{
    PXENVBD_RING    Ring = Argument;
    KeAcquireSpinLockAtDpcLevel(&Ring->Lock);
}

static DECLSPEC_NOINLINE VOID
RingReleaseLock(
    IN  PVOID       Argument
    )
{
    PXENVBD_RING    Ring = Argument;
    KeReleaseSpinLockFromDpcLevel(&Ring->Lock);
}

static DECLSPEC_NOINLINE NTSTATUS
RingRequestCtor(
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
RingRequestDtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static DECLSPEC_NOINLINE NTSTATUS
RingSegmentCtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
RingSegmentDtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static DECLSPEC_NOINLINE NTSTATUS
RingIndirectCtor(
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
RingIndirectDtor(
    IN  PVOID       Argument,
    IN  PVOID       Object
    )
{
    PXENVBD_INDIRECT    Indirect = Object;

    UNREFERENCED_PARAMETER(Argument);

    __FreePages(Indirect->Mdl);
    Indirect->Page = NULL;
    Indirect->Mdl = NULL;
}

NTSTATUS
RingCreate(
    IN  PXENVBD_FRONTEND    Frontend,
    OUT PXENVBD_RING*       Ring
    )
{
    PXENVBD_TARGET          Target = FrontendGetTarget(Frontend);
    PXENVBD_ADAPTER         Adapter = TargetGetAdapter(Target);
    CHAR                    Name[MAX_NAME_LEN];
    NTSTATUS                status;

    *Ring = __RingAllocate(sizeof(XENVBD_RING));

    status = STATUS_NO_MEMORY;
    if (*Ring == NULL)
        goto fail1;

    (*Ring)->Frontend = Frontend;
    KeInitializeSpinLock(&(*Ring)->Lock);
    KeInitializeDpc(&(*Ring)->Dpc, RingDpc, *Ring);
    KeInitializeDpc(&(*Ring)->TimerDpc, RingDpc, *Ring);
    KeInitializeTimer(&(*Ring)->Timer);

    QueueInit(&(*Ring)->FreshSrbs);
    QueueInit(&(*Ring)->PreparedReqs);
    QueueInit(&(*Ring)->SubmittedReqs);
    QueueInit(&(*Ring)->ShutdownSrbs);

    AdapterGetCacheInterface(Adapter, &(*Ring)->CacheInterface);

    status = XENBUS_CACHE(Acquire, &(*Ring)->CacheInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_req",
                                FrontendGetTargetId(Frontend));
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_CACHE(Create,
                          &(*Ring)->CacheInterface,
                          Name,
                          sizeof(XENVBD_REQUEST),
                          32,
                          RingRequestCtor,
                          RingRequestDtor,
                          RingAcquireLock,
                          RingReleaseLock,
                          *Ring,
                          &(*Ring)->RequestCache);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_seg",
                                FrontendGetTargetId(Frontend));
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_CACHE(Create,
                          &(*Ring)->CacheInterface,
                          Name,
                          sizeof(XENVBD_SEGMENT),
                          32,
                          RingSegmentCtor,
                          RingSegmentDtor,
                          RingAcquireLock,
                          RingReleaseLock,
                          *Ring,
                          &(*Ring)->SegmentCache);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_ind",
                                FrontendGetTargetId(Frontend));
    if (!NT_SUCCESS(status))
        goto fail7;

    status = XENBUS_CACHE(Create,
                          &(*Ring)->CacheInterface,
                          Name,
                          sizeof(XENVBD_INDIRECT),
                          1,
                          RingIndirectCtor,
                          RingIndirectDtor,
                          RingAcquireLock,
                          RingReleaseLock,
                          *Ring,
                          &(*Ring)->IndirectCache);
    if (!NT_SUCCESS(status))
        goto fail8;

    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");
fail7:
    Error("fail7\n");
    XENBUS_CACHE(Destroy,
                 &(*Ring)->CacheInterface,
                 (*Ring)->SegmentCache);
    (*Ring)->SegmentCache = NULL;
fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
    XENBUS_CACHE(Destroy,
                 &(*Ring)->CacheInterface,
                 (*Ring)->RequestCache);
    (*Ring)->RequestCache = NULL;
fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
    XENBUS_CACHE(Release,
                 &(*Ring)->CacheInterface);
fail2:
    Error("fail2\n");

    RtlZeroMemory(&(*Ring)->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&(*Ring)->FreshSrbs, sizeof(XENVBD_QUEUE));
    RtlZeroMemory(&(*Ring)->PreparedReqs, sizeof(XENVBD_QUEUE));
    RtlZeroMemory(&(*Ring)->SubmittedReqs, sizeof(XENVBD_QUEUE));
    RtlZeroMemory(&(*Ring)->ShutdownSrbs, sizeof(XENVBD_QUEUE));

    RtlZeroMemory(&(*Ring)->Timer, sizeof(KTIMER));
    RtlZeroMemory(&(*Ring)->TimerDpc, sizeof(KDPC));
    RtlZeroMemory(&(*Ring)->Dpc, sizeof(KDPC));
    RtlZeroMemory(&(*Ring)->Lock, sizeof(KSPIN_LOCK));
    (*Ring)->Frontend = NULL;

    ASSERT(IsZeroMemory(*Ring, sizeof(XENVBD_RING)));
    __RingFree(*Ring);
    *Ring = NULL;
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

VOID
RingDestroy(
    IN  PXENVBD_RING    Ring
    )
{
    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 Ring->IndirectCache);
    Ring->IndirectCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 Ring->SegmentCache);
    Ring->SegmentCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 Ring->RequestCache);
    Ring->RequestCache = NULL;

    XENBUS_CACHE(Release,
                 &Ring->CacheInterface);

    RtlZeroMemory(&Ring->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&Ring->FreshSrbs, sizeof(XENVBD_QUEUE));
    RtlZeroMemory(&Ring->PreparedReqs, sizeof(XENVBD_QUEUE));
    RtlZeroMemory(&Ring->SubmittedReqs, sizeof(XENVBD_QUEUE));
    RtlZeroMemory(&Ring->ShutdownSrbs, sizeof(XENVBD_QUEUE));

    RtlZeroMemory(&Ring->Timer, sizeof(KTIMER));
    RtlZeroMemory(&Ring->TimerDpc, sizeof(KDPC));
    RtlZeroMemory(&Ring->Dpc, sizeof(KDPC));
    RtlZeroMemory(&Ring->Lock, sizeof(KSPIN_LOCK));
    Ring->Frontend = NULL;

    ASSERT(IsZeroMemory(Ring, sizeof(XENVBD_RING)));
    __RingFree(Ring);
}

NTSTATUS
RingConnect(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_TARGET      Target = FrontendGetTarget(Ring->Frontend);
    PXENVBD_ADAPTER     Adapter = TargetGetAdapter(Target);
    PXENVBD_GRANTER     Granter = FrontendGetGranter(Ring->Frontend);
    PCHAR               Buffer;
    ULONG               Index;
    NTSTATUS            status;

    ASSERT(Ring->Connected == FALSE);

    AdapterGetStoreInterface(Adapter, &Ring->StoreInterface);
    AdapterGetEvtchnInterface(Adapter, &Ring->EvtchnInterface);
    AdapterGetDebugInterface(Adapter, &Ring->DebugInterface);

    status = XENBUS_STORE(Acquire, &Ring->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_EVTCHN(Acquire, &Ring->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_DEBUG(Acquire, &Ring->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

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

    Ring->Mdl = __AllocatePages(1 << Ring->Order);

    status = STATUS_NO_MEMORY;
    if (Ring->Mdl == NULL)
        goto fail4;

    Ring->Shared = MmGetSystemAddressForMdlSafe(Ring->Mdl,
                                                NormalPagePriority);
    ASSERT(Ring->Shared != NULL);

#pragma warning(push)
#pragma warning(disable: 4305)
#pragma warning(disable: 4311) // 'type cast' pointer truncation from 'blkif_sring_entry[1]' to 'long'
    SHARED_RING_INIT(Ring->Shared);
    FRONT_RING_INIT(&Ring->Front, Ring->Shared, PAGE_SIZE << Ring->Order);
#pragma warning(pop)

    for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
        status = GranterGet(Granter,
                            MmGetMdlPfnArray(Ring->Mdl)[Index],
                            FALSE,
                            &Ring->Grants[Index]);
        if (!NT_SUCCESS(status))
            goto fail5;
    }

    Ring->Channel = XENBUS_EVTCHN(Open,
                                  &Ring->EvtchnInterface,
                                  XENBUS_EVTCHN_TYPE_UNBOUND,
                                  RingInterrupt,
                                  Ring,
                                  FrontendGetBackendDomain(Ring->Frontend),
                                  TRUE);
    status = STATUS_NO_MEMORY;
    if (Ring->Channel == NULL)
        goto fail6;

    XENBUS_EVTCHN(Unmask,
                  &Ring->EvtchnInterface,
                  Ring->Channel,
                  FALSE);

    status = XENBUS_DEBUG(Register,
                          &Ring->DebugInterface,
                          __MODULE__"|RING",
                          RingDebugCallback,
                          Ring,
                          &Ring->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail7;

    Ring->Connected = TRUE;
    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");
    XENBUS_EVTCHN(Close,
                  &Ring->EvtchnInterface,
                  Ring->Channel);
    Ring->Channel = NULL;
fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
    for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
        if (Ring->Grants[Index] == NULL)
            continue;

        GranterPut(Granter, Ring->Grants[Index]);
        Ring->Grants[Index] = NULL;
    }

    RtlZeroMemory(&Ring->Front, sizeof(blkif_front_ring_t));

    __FreePages(Ring->Mdl);
    Ring->Shared = NULL;
    Ring->Mdl = NULL;

    Ring->Order = 0;
fail4:
    Error("fail4\n");
    XENBUS_DEBUG(Release, &Ring->DebugInterface);
fail3:
    Error("fail3\n");
    XENBUS_EVTCHN(Release, &Ring->EvtchnInterface);
fail2:
    Error("fail2\n");
    XENBUS_STORE(Release, &Ring->StoreInterface);
fail1:
    Error("fail1 %08x\n", status);

    RtlZeroMemory(&Ring->DebugInterface,
                  sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Ring->EvtchnInterface,
                  sizeof(XENBUS_EVTCHN_INTERFACE));
    RtlZeroMemory(&Ring->StoreInterface,
                  sizeof(XENBUS_STORE_INTERFACE));

    return status;
}

NTSTATUS
RingStoreWrite(
    IN  PXENVBD_RING    Ring,
    IN  PVOID           Transaction
    )
{
    PXENVBD_GRANTER     Granter = FrontendGetGranter(Ring->Frontend);
    ULONG               Port;
    NTSTATUS            status;

    if (Ring->Order == 0) {
        status = XENBUS_STORE(Printf,
                              &Ring->StoreInterface,
                              Transaction,
                              FrontendGetFrontendPath(Ring->Frontend),
                              "ring-ref",
                              "%u",
                              GranterReference(Granter, Ring->Grants[0]));
        if (!NT_SUCCESS(status))
            return status;
    } else {
        ULONG           Index;

        status = XENBUS_STORE(Printf,
                              &Ring->StoreInterface,
                              Transaction,
                              FrontendGetFrontendPath(Ring->Frontend),
                              "ring-page-order",
                              "%u",
                              Ring->Order);
        if (!NT_SUCCESS(status))
            return status;

        for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
            CHAR        Name[MAX_NAME_LEN+1];

            status = RtlStringCchPrintfA(Name,
                                         MAX_NAME_LEN,
                                         "ring-ref%u",
                                         Index);
            if (!NT_SUCCESS(status))
                return status;

            status = XENBUS_STORE(Printf,
                                  &Ring->StoreInterface,
                                  Transaction,
                                  FrontendGetFrontendPath(Ring->Frontend),
                                  Name,
                                  "%u",
                                  GranterReference(Granter, Ring->Grants[Index]));
            if (!NT_SUCCESS(status))
                return status;
        }
    }

    status = XENBUS_STORE(Printf,
                          &Ring->StoreInterface,
                          Transaction,
                          FrontendGetFrontendPath(Ring->Frontend),
                          "protocol",
                          XEN_IO_PROTO_ABI);
    if (!NT_SUCCESS(status))
        return status;

    Port = XENBUS_EVTCHN(GetPort,
                         &Ring->EvtchnInterface,
                         Ring->Channel);

    status = XENBUS_STORE(Printf,
                          &Ring->StoreInterface,
                          Transaction,
                          FrontendGetFrontendPath(Ring->Frontend),
                          "event-channel",
                          "%u",
                          Port);
    if (!NT_SUCCESS(status))
        return status;

    return STATUS_SUCCESS;
}

VOID
RingEnable(
    IN  PXENVBD_RING    Ring
    )
{
    ASSERT(Ring->Enabled == FALSE);
    Ring->Enabled = TRUE;

    XENBUS_EVTCHN(Trigger,
                  &Ring->EvtchnInterface,
                  Ring->Channel);
}

VOID
RingDisable(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               Count;
    KIRQL               Irql;
    PXENVBD_TARGET      Target = FrontendGetTarget(Ring->Frontend);
    PXENVBD_ADAPTER     Adapter = TargetGetAdapter(Target);

    ASSERT(Ring->Enabled == TRUE);
    Ring->Enabled = FALSE;

    // poll ring and send event channel notification every 1ms (for up to 3 minutes)
    Count = 0;
    while (QueueCount(&Ring->SubmittedReqs)) {
        if (Count > 180000)
            break;
        KeRaiseIrql(DISPATCH_LEVEL, &Irql);
        RingPoll(Ring);
        KeLowerIrql(Irql);
        XENBUS_EVTCHN(Send,
                      &Ring->EvtchnInterface,
                      Ring->Channel);
        StorPortStallExecution(1000);   // 1000 micro-seconds
        ++Count;
    }

    Verbose("Target[%d] : %u Submitted requests left (%u iterrations)\n",
            FrontendGetTargetId(Ring->Frontend),
            QueueCount(&Ring->SubmittedReqs),
            Count);

    // Abort Fresh SRBs
    for (;;) {
        PXENVBD_SRBEXT      SrbExt;
        PSCSI_REQUEST_BLOCK Srb;
        PLIST_ENTRY         ListEntry;

        ListEntry = QueuePop(&Ring->FreshSrbs);
        if (ListEntry == NULL)
            break;
        SrbExt = CONTAINING_RECORD(ListEntry, XENVBD_SRBEXT, ListEntry);
        Srb = SrbExt->Srb;

        Srb->SrbStatus = SRB_STATUS_ABORTED;
        Srb->ScsiStatus = 0x40; // SCSI_ABORTED;
        AdapterCompleteSrb(Adapter, SrbExt);
    }

    // Fail PreparedReqs
    for (;;) {
        PXENVBD_SRBEXT      SrbExt;
        PSCSI_REQUEST_BLOCK Srb;
        PXENVBD_REQUEST     Request;
        PLIST_ENTRY         ListEntry;

        ListEntry = QueuePop(&Ring->PreparedReqs);
        if (ListEntry == NULL)
            break;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        SrbExt = Request->SrbExt;
        Srb = SrbExt->Srb;

        RingPutRequest(Ring, Request);

        if (InterlockedDecrement(&SrbExt->RequestCount) == 0) {
            Srb->SrbStatus = SRB_STATUS_ABORTED;
            Srb->ScsiStatus = 0x40; // SCSI_ABORTED
            AdapterCompleteSrb(Adapter, SrbExt);
        }
    }

    //
    // No new timers can be scheduled once Enabled goes to FALSE.
    // Cancel any existing ones.
    //
    (VOID) KeCancelTimer(&Ring->Timer);
}

VOID
RingDisconnect(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_GRANTER     Granter = FrontendGetGranter(Ring->Frontend);
    ULONG               Index;

    ASSERT3U(Ring->Submitted, ==, Ring->Received);
    ASSERT(Ring->Connected);
    Ring->Connected = FALSE;

    XENBUS_DEBUG(Deregister,
                 &Ring->DebugInterface,
                 Ring->DebugCallback);
    Ring->DebugCallback = NULL;

    XENBUS_EVTCHN(Close,
                  &Ring->EvtchnInterface,
                  Ring->Channel);
    Ring->Channel = NULL;

    for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
        if (Ring->Grants[Index] == NULL)
            continue;

        GranterPut(Granter, Ring->Grants[Index]);
        Ring->Grants[Index] = NULL;
    }

    RtlZeroMemory(&Ring->Front, sizeof(blkif_front_ring_t));

    __FreePages(Ring->Mdl);
    Ring->Shared = NULL;
    Ring->Mdl = NULL;

    Ring->Order = 0;

    XENBUS_DEBUG(Release, &Ring->DebugInterface);
    XENBUS_EVTCHN(Release, &Ring->EvtchnInterface);
    XENBUS_STORE(Release, &Ring->StoreInterface);

    RtlZeroMemory(&Ring->DebugInterface,
                  sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Ring->EvtchnInterface,
                  sizeof(XENBUS_EVTCHN_INTERFACE));
    RtlZeroMemory(&Ring->StoreInterface,
                  sizeof(XENBUS_STORE_INTERFACE));

    Ring->Events = 0;
    Ring->Dpcs = 0;
    Ring->Submitted = 0;
    Ring->Received = 0;
}

VOID
RingTrigger(
    IN  PXENVBD_RING    Ring
    )
{
    if (!Ring->Enabled)
        return;

    XENBUS_EVTCHN(Trigger,
                  &Ring->EvtchnInterface,
                  Ring->Channel);
}

VOID
RingQueueRequest(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    QueueAppend(&Ring->FreshSrbs,
                &SrbExt->ListEntry);

    if (!Ring->Enabled)
        return;

    if (KeInsertQueueDpc(&Ring->Dpc, NULL, NULL))
	    ++Ring->Dpcs;
}

VOID
RingQueueShutdown(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    QueueAppend(&Ring->ShutdownSrbs,
                &SrbExt->ListEntry);

    if (!Ring->Enabled)
        return;

    if (KeInsertQueueDpc(&Ring->Dpc, NULL, NULL))
	    ++Ring->Dpcs;
}
