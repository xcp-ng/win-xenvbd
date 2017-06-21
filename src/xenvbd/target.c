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

#include "target.h"
#include "driver.h"
#include "adapter.h"
#include "frontend.h"
#include "queue.h"
#include "srbext.h"
#include "buffer.h"
#include "pdoinquiry.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <stdlib.h>

#define TARGET_SIGNATURE           'odpX'

typedef struct _XENVBD_LOOKASIDE {
    KEVENT                      Empty;
    LONG                        Used;
    LONG                        Max;
    ULONG                       Failed;
    ULONG                       Size;
    NPAGED_LOOKASIDE_LIST       List;
} XENVBD_LOOKASIDE, *PXENVBD_LOOKASIDE;

struct _XENVBD_TARGET {
    ULONG                       Signature;
    PXENVBD_ADAPTER                 Adapter;
    PDEVICE_OBJECT              DeviceObject;
    DEVICE_PNP_STATE            DevicePnpState;
    DEVICE_PNP_STATE            PrevPnpState;
    DEVICE_POWER_STATE          DevicePowerState;
    KSPIN_LOCK                  Lock;

    // Frontend (Ring, includes XenBus interfaces)
    PXENVBD_FRONTEND            Frontend;

    // State
    LONG                        Paused;

    // Eject
    BOOLEAN                     WrittenEjected;
    BOOLEAN                     EjectRequested;
    BOOLEAN                     EjectPending;
    BOOLEAN                     Missing;
    const CHAR*                 Reason;

    // SRBs
    XENVBD_LOOKASIDE            RequestList;
    XENVBD_LOOKASIDE            SegmentList;
    XENVBD_LOOKASIDE            IndirectList;
    XENVBD_QUEUE                FreshSrbs;
    XENVBD_QUEUE                PreparedReqs;
    XENVBD_QUEUE                SubmittedReqs;
    XENVBD_QUEUE                ShutdownSrbs;
    ULONG                       NextTag;

    // Stats - SRB Counts by BLKIF_OP_
    ULONG                       BlkOpRead;
    ULONG                       BlkOpWrite;
    ULONG                       BlkOpIndirectRead;
    ULONG                       BlkOpIndirectWrite;
    ULONG                       BlkOpBarrier;
    ULONG                       BlkOpDiscard;
    ULONG                       BlkOpFlush;
    // Stats - Failures
    ULONG                       FailedMaps;
    ULONG                       FailedBounces;
    ULONG                       FailedGrants;
    // Stats - Segments
    ULONG64                     SegsGranted;
    ULONG64                     SegsBounced;
};

//=============================================================================
#define TARGET_POOL_TAG            'odPX'
#define REQUEST_POOL_TAG        'qeRX'
#define SEGMENT_POOL_TAG        'geSX'
#define INDIRECT_POOL_TAG       'dnIX'

__checkReturn
__drv_allocatesMem(mem)
__bcount(Size)
static FORCEINLINE PVOID
#pragma warning(suppress: 28195)
__TargetAlloc(
    __in ULONG  Size
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Size, TARGET_POOL_TAG);
}

static FORCEINLINE VOID
#pragma warning(suppress: 28197)
__TargetFree(
    __in __drv_freesMem(mem) PVOID Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, TARGET_POOL_TAG);
}

//=============================================================================
// Lookasides
static FORCEINLINE VOID
__LookasideInit(
    IN OUT  PXENVBD_LOOKASIDE   Lookaside,
    IN  ULONG                   Size,
    IN  ULONG                   Tag
    )
{
    RtlZeroMemory(Lookaside, sizeof(XENVBD_LOOKASIDE));
    Lookaside->Size = Size;
    KeInitializeEvent(&Lookaside->Empty, SynchronizationEvent, TRUE);
    ExInitializeNPagedLookasideList(&Lookaside->List, NULL, NULL, 0,
                                    Size, Tag, 0);
}

static FORCEINLINE VOID
__LookasideTerm(
    IN  PXENVBD_LOOKASIDE       Lookaside
    )
{
    ASSERT3U(Lookaside->Used, ==, 0);
    ExDeleteNPagedLookasideList(&Lookaside->List);
    RtlZeroMemory(Lookaside, sizeof(XENVBD_LOOKASIDE));
}

static FORCEINLINE PVOID
__LookasideAlloc(
    IN  PXENVBD_LOOKASIDE       Lookaside
    )
{
    LONG    Result;
    PVOID   Buffer;

    Buffer = ExAllocateFromNPagedLookasideList(&Lookaside->List);
    if (Buffer == NULL) {
        ++Lookaside->Failed;
        return NULL;
    }

    RtlZeroMemory(Buffer, Lookaside->Size);
    Result = InterlockedIncrement(&Lookaside->Used);
    ASSERT3S(Result, >, 0);
    if (Result > Lookaside->Max)
        Lookaside->Max = Result;
    KeClearEvent(&Lookaside->Empty);

    return Buffer;
}

static FORCEINLINE VOID
__LookasideFree(
    IN  PXENVBD_LOOKASIDE       Lookaside,
    IN  PVOID                   Buffer
    )
{
    LONG            Result;

    ExFreeToNPagedLookasideList(&Lookaside->List, Buffer);
    Result = InterlockedDecrement(&Lookaside->Used);
    ASSERT3S(Result, >=, 0);

    if (Result == 0) {
        KeSetEvent(&Lookaside->Empty, IO_NO_INCREMENT, FALSE);
    }
}

static FORCEINLINE VOID
__LookasideDebug(
    IN  PXENVBD_LOOKASIDE           Lookaside,
    IN  PXENBUS_DEBUG_INTERFACE     Debug,
    IN  PCHAR                       Name
    )
{
    XENBUS_DEBUG(Printf, Debug,
                 "LOOKASIDE: %s: %u / %u (%u failed)\n",
                 Name, Lookaside->Used,
                 Lookaside->Max, Lookaside->Failed);

    Lookaside->Max = Lookaside->Used;
    Lookaside->Failed = 0;
}

//=============================================================================
// Debug
static FORCEINLINE PCHAR
__PnpStateName(
    __in DEVICE_PNP_STATE        State
    )
{
    switch (State) {
    case Invalid:               return "Invalid";
    case Present:               return "Present";
    case Enumerated:            return "Enumerated";
    case Added:                 return "Added";
    case Started:               return "Started";
    case StopPending:           return "StopPending";
    case Stopped:               return "Stopped";
    case RemovePending:         return "RemovePending";
    case SurpriseRemovePending: return "SurpriseRemovePending";
    case Deleted:               return "Deleted";
    default:                    return "UNKNOWN";
    }
}

DECLSPEC_NOINLINE VOID
TargetDebugCallback(
    __in PXENVBD_TARGET Target,
    __in PXENBUS_DEBUG_INTERFACE DebugInterface
    )
{
    if (Target == NULL || DebugInterface == NULL)
        return;
    if (Target->Signature != TARGET_SIGNATURE)
        return;

    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: Adapter 0x%p DeviceObject 0x%p\n",
                 Target->Adapter,
                 Target->DeviceObject);
    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: DevicePnpState %s (%s)\n",
                 __PnpStateName(Target->DevicePnpState),
                 __PnpStateName(Target->PrevPnpState));
    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: DevicePowerState %s\n",
                 PowerDeviceStateName(Target->DevicePowerState));
    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: %s\n",
                 Target->Missing ? Target->Reason : "Not Missing");

    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: BLKIF_OPs: READ=%u WRITE=%u\n",
                 Target->BlkOpRead, Target->BlkOpWrite);
    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: BLKIF_OPs: INDIRECT_READ=%u INDIRECT_WRITE=%u\n",
                 Target->BlkOpIndirectRead, Target->BlkOpIndirectWrite);
    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: BLKIF_OPs: BARRIER=%u DISCARD=%u FLUSH=%u\n",
                 Target->BlkOpBarrier, Target->BlkOpDiscard, Target->BlkOpFlush);
    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: Failed: Maps=%u Bounces=%u Grants=%u\n",
                 Target->FailedMaps, Target->FailedBounces, Target->FailedGrants);
    XENBUS_DEBUG(Printf, DebugInterface,
                 "TARGET: Segments Granted=%llu Bounced=%llu\n",
                 Target->SegsGranted, Target->SegsBounced);

    __LookasideDebug(&Target->RequestList, DebugInterface, "REQUESTs");
    __LookasideDebug(&Target->SegmentList, DebugInterface, "SEGMENTs");
    __LookasideDebug(&Target->IndirectList, DebugInterface, "INDIRECTs");

    QueueDebugCallback(&Target->FreshSrbs,    "Fresh    ", DebugInterface);
    QueueDebugCallback(&Target->PreparedReqs, "Prepared ", DebugInterface);
    QueueDebugCallback(&Target->SubmittedReqs, "Submitted", DebugInterface);
    QueueDebugCallback(&Target->ShutdownSrbs, "Shutdown ", DebugInterface);

    FrontendDebugCallback(Target->Frontend, DebugInterface);

    Target->BlkOpRead = Target->BlkOpWrite = 0;
    Target->BlkOpIndirectRead = Target->BlkOpIndirectWrite = 0;
    Target->BlkOpBarrier = Target->BlkOpDiscard = Target->BlkOpFlush = 0;
    Target->FailedMaps = Target->FailedBounces = Target->FailedGrants = 0;
    Target->SegsGranted = Target->SegsBounced = 0;
}

//=============================================================================
// Power States
__checkReturn
static FORCEINLINE BOOLEAN
TargetSetDevicePowerState(
    __in PXENVBD_TARGET             Target,
    __in DEVICE_POWER_STATE      State
    )
{
    KIRQL       Irql;
    BOOLEAN     Changed = FALSE;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->DevicePowerState != State) {
        Verbose("Target[%d] : POWER %s to %s\n", TargetGetTargetId(Target), PowerDeviceStateName(Target->DevicePowerState), PowerDeviceStateName(State));
        Target->DevicePowerState = State;
        Changed = TRUE;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);

    return Changed;
}

//=============================================================================
// PnP States
FORCEINLINE VOID
TargetSetMissing(
    __in PXENVBD_TARGET             Target,
    __in __nullterminated const CHAR* Reason
    )
{
    KIRQL   Irql;

    ASSERT3P(Reason, !=, NULL);

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->Missing) {
        Verbose("Target[%d] : Already MISSING (%s) when trying to set (%s)\n", TargetGetTargetId(Target), Target->Reason, Reason);
    } else {
        Verbose("Target[%d] : MISSING %s\n", TargetGetTargetId(Target), Reason);
        Target->Missing = TRUE;
        Target->Reason = Reason;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);
}

__checkReturn
FORCEINLINE BOOLEAN
TargetIsMissing(
    __in PXENVBD_TARGET             Target
    )
{
    KIRQL   Irql;
    BOOLEAN Missing;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    Missing = Target->Missing;
    KeReleaseSpinLock(&Target->Lock, Irql);

    return Missing;
}

FORCEINLINE VOID
TargetSetDevicePnpState(
    __in PXENVBD_TARGET             Target,
    __in DEVICE_PNP_STATE        State
    )
{
    Verbose("Target[%d] : PNP %s to %s\n",
            TargetGetTargetId(Target),
            __PnpStateName(Target->DevicePnpState),
            __PnpStateName(State));

    if (Target->DevicePnpState == Deleted)
        return;

    Target->PrevPnpState = Target->DevicePnpState;
    Target->DevicePnpState = State;
}

__checkReturn
FORCEINLINE DEVICE_PNP_STATE
TargetGetDevicePnpState(
    __in PXENVBD_TARGET             Target
    )
{
    return Target->DevicePnpState;
}

static FORCEINLINE VOID
__TargetRestoreDevicePnpState(
    __in PXENVBD_TARGET             Target,
    __in DEVICE_PNP_STATE        State
    )
{
    if (Target->DevicePnpState == State) {
        Verbose("Target[%d] : PNP %s to %s\n", TargetGetTargetId(Target), __PnpStateName(Target->DevicePnpState), __PnpStateName(Target->PrevPnpState));
        Target->DevicePnpState = Target->PrevPnpState;
    }
}

//=============================================================================
// Query Methods
FORCEINLINE ULONG
TargetGetTargetId(
    __in PXENVBD_TARGET             Target
    )
{
    ASSERT3P(Target, !=, NULL);
    return FrontendGetTargetId(Target->Frontend);
}

ULONG
TargetGetDeviceId(
    __in PXENVBD_TARGET             Target
    )
{
    ASSERT3P(Target, !=, NULL);
    return FrontendGetDeviceId(Target->Frontend);
}

__checkReturn
FORCEINLINE PDEVICE_OBJECT
TargetGetDeviceObject(
    __in PXENVBD_TARGET             Target
    )
{
    ASSERT3P(Target, !=, NULL);
    return Target->DeviceObject;
}

FORCEINLINE VOID
TargetSetDeviceObject(
    __in PXENVBD_TARGET             Target,
    __in PDEVICE_OBJECT          DeviceObject
    )
{
    Verbose("Target[%d] : Setting DeviceObject = 0x%p\n", TargetGetTargetId(Target), DeviceObject);

    ASSERT3P(Target->DeviceObject, ==, NULL);
    Target->DeviceObject = DeviceObject;
}

__checkReturn
FORCEINLINE BOOLEAN
TargetIsPaused(
    __in PXENVBD_TARGET             Target
    )
{
    BOOLEAN Paused;
    KIRQL   Irql;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    Paused = (Target->Paused > 0);
    KeReleaseSpinLock(&Target->Lock, Irql);

    return Paused;
}

__checkReturn
FORCEINLINE PXENVBD_ADAPTER
TargetGetAdapter(
    __in PXENVBD_TARGET             Target
    )
{
    return Target->Adapter;
}

static FORCEINLINE ULONG
TargetSectorSize(
    __in PXENVBD_TARGET             Target
    )
{
    return FrontendGetDiskInfo(Target->Frontend)->SectorSize;
}

//=============================================================================
static PXENVBD_INDIRECT
TargetGetIndirect(
    IN  PXENVBD_TARGET             Target
    )
{
    PXENVBD_INDIRECT    Indirect;
    NTSTATUS            status;
    PXENVBD_GRANTER     Granter = FrontendGetGranter(Target->Frontend);

    Indirect = __LookasideAlloc(&Target->IndirectList);
    if (Indirect == NULL)
        goto fail1;

    RtlZeroMemory(Indirect, sizeof(XENVBD_INDIRECT));

    Indirect->Mdl = __AllocatePage();
    if (Indirect->Mdl == NULL)
        goto fail2;

    Indirect->Page = MmGetSystemAddressForMdlSafe(Indirect->Mdl,
                                                  NormalPagePriority);

    status = GranterGet(Granter,
                        MmGetMdlPfnArray(Indirect->Mdl)[0],
                        TRUE,
                        &Indirect->Grant);
    if (!NT_SUCCESS(status))
        goto fail3;

    return Indirect;

fail3:
    __FreePage(Indirect->Mdl);
fail2:
    __LookasideFree(&Target->IndirectList, Indirect);
fail1:
    return NULL;
}

static VOID
TargetPutIndirect(
    IN  PXENVBD_TARGET             Target,
    IN  PXENVBD_INDIRECT        Indirect
    )
{
    PXENVBD_GRANTER Granter = FrontendGetGranter(Target->Frontend);

    if (Indirect->Grant)
        GranterPut(Granter, Indirect->Grant);
    if (Indirect->Page)
        __FreePage(Indirect->Mdl);

    RtlZeroMemory(Indirect, sizeof(XENVBD_INDIRECT));
    __LookasideFree(&Target->IndirectList, Indirect);
}

static PXENVBD_SEGMENT
TargetGetSegment(
    IN  PXENVBD_TARGET             Target
    )
{
    PXENVBD_SEGMENT             Segment;

    Segment = __LookasideAlloc(&Target->SegmentList);
    if (Segment == NULL)
        goto fail1;

    RtlZeroMemory(Segment, sizeof(XENVBD_SEGMENT));
    return Segment;

fail1:
    return NULL;
}

static VOID
TargetPutSegment(
    IN  PXENVBD_TARGET             Target,
    IN  PXENVBD_SEGMENT         Segment
    )
{
    PXENVBD_GRANTER Granter = FrontendGetGranter(Target->Frontend);

    if (Segment->Grant)
        GranterPut(Granter, Segment->Grant);

    if (Segment->BufferId)
        BufferPut(Segment->BufferId);

    if (Segment->Buffer)
        MmUnmapLockedPages(Segment->Buffer, &Segment->Mdl);

    RtlZeroMemory(Segment, sizeof(XENVBD_SEGMENT));
    __LookasideFree(&Target->SegmentList, Segment);
}

static PXENVBD_REQUEST
TargetGetRequest(
    IN  PXENVBD_TARGET             Target
    )
{
    PXENVBD_REQUEST             Request;

    Request = __LookasideAlloc(&Target->RequestList);
    if (Request == NULL)
        goto fail1;

    RtlZeroMemory(Request, sizeof(XENVBD_REQUEST));
    Request->Id = (ULONG)InterlockedIncrement((PLONG)&Target->NextTag);
    InitializeListHead(&Request->Segments);
    InitializeListHead(&Request->Indirects);

    return Request;

fail1:
    return NULL;
}

static VOID
TargetPutRequest(
    IN  PXENVBD_TARGET             Target,
    IN  PXENVBD_REQUEST         Request
    )
{
    PLIST_ENTRY     Entry;

    for (;;) {
        PXENVBD_SEGMENT Segment;

        Entry = RemoveHeadList(&Request->Segments);
        if (Entry == &Request->Segments)
            break;
        Segment = CONTAINING_RECORD(Entry, XENVBD_SEGMENT, Entry);
        TargetPutSegment(Target, Segment);
    }

    for (;;) {
        PXENVBD_INDIRECT    Indirect;

        Entry = RemoveHeadList(&Request->Indirects);
        if (Entry == &Request->Indirects)
            break;
        Indirect = CONTAINING_RECORD(Entry, XENVBD_INDIRECT, Entry);
        TargetPutIndirect(Target, Indirect);
    }

    RtlZeroMemory(Request, sizeof(XENVBD_REQUEST));
    __LookasideFree(&Target->RequestList, Request);
}

static FORCEINLINE PXENVBD_REQUEST
TargetRequestFromTag(
    IN  PXENVBD_TARGET             Target,
    IN  ULONG                   Tag
    )
{
    KIRQL           Irql;
    PLIST_ENTRY     Entry;
    PXENVBD_QUEUE   Queue = &Target->SubmittedReqs;

    KeAcquireSpinLock(&Queue->Lock, &Irql);

    for (Entry = Queue->List.Flink; Entry != &Queue->List; Entry = Entry->Flink) {
        PXENVBD_REQUEST Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        if (Request->Id == Tag) {
            RemoveEntryList(&Request->Entry);
            --Queue->Current;
            KeReleaseSpinLock(&Queue->Lock, Irql);
            return Request;
        }
    }

    KeReleaseSpinLock(&Queue->Lock, Irql);
    Warning("Target[%d] : Tag %x not found in submitted list (%u items)\n",
            TargetGetTargetId(Target), Tag, QueueCount(Queue));
    return NULL;
}

static FORCEINLINE VOID
__TargetIncBlkifOpCount(
    __in PXENVBD_TARGET             Target,
    __in PXENVBD_REQUEST         Request
    )
{
    switch (Request->Operation) {
    case BLKIF_OP_READ:
        if (Request->NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST)
            ++Target->BlkOpIndirectRead;
        else
            ++Target->BlkOpRead;
        break;
    case BLKIF_OP_WRITE:
        if (Request->NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST)
            ++Target->BlkOpIndirectWrite;
        else
            ++Target->BlkOpWrite;
        break;
    case BLKIF_OP_WRITE_BARRIER:
        ++Target->BlkOpBarrier;
        break;
    case BLKIF_OP_DISCARD:
        ++Target->BlkOpDiscard;
        break;
    case BLKIF_OP_FLUSH_DISKCACHE:
        ++Target->BlkOpFlush;
        break;
    default:
        ASSERT(FALSE);
        break;
    }
}

static FORCEINLINE ULONG
__SectorsPerPage(
    __in ULONG                   SectorSize
    )
{
    ASSERT3U(SectorSize, !=, 0);
    return PAGE_SIZE / SectorSize;
}

static FORCEINLINE VOID
__Operation(
    __in UCHAR                   CdbOp,
    __out PUCHAR                 RingOp,
    __out PBOOLEAN               ReadOnly
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
__TargetPriority(
    __in PXENVBD_TARGET             Target
    )
{
    PXENVBD_CAPS   Caps = FrontendGetCaps(Target->Frontend);
    if (!(Caps->Paging ||
          Caps->Hibernation ||
          Caps->DumpFile))
        return NormalPagePriority;

    return HighPagePriority;
}

static FORCEINLINE VOID
RequestCopyOutput(
    __in PXENVBD_REQUEST         Request
    )
{
    PLIST_ENTRY     Entry;

    if (Request->Operation != BLKIF_OP_READ)
        return;

    for (Entry = Request->Segments.Flink;
            Entry != &Request->Segments;
            Entry = Entry->Flink) {
        PXENVBD_SEGMENT Segment = CONTAINING_RECORD(Entry, XENVBD_SEGMENT, Entry);

        if (Segment->BufferId)
            BufferCopyOut(Segment->BufferId, Segment->Buffer, Segment->Length);
    }
}

static BOOLEAN
PrepareSegment(
    IN  PXENVBD_TARGET          Target,
    IN  PXENVBD_SEGMENT         Segment,
    IN  PXENVBD_SRBEXT          SrbExt,
    IN  BOOLEAN                 ReadOnly,
    IN  ULONG                   SectorsLeft,
    OUT PULONG                  SectorsNow
    )
{
    PFN_NUMBER      Pfn;
    ULONG           Offset;
    ULONG           Length;
    NTSTATUS        Status;
    PXENVBD_GRANTER Granter = FrontendGetGranter(Target->Frontend);
    const ULONG     SectorSize = TargetSectorSize(Target);
    const ULONG     SectorsPerPage = __SectorsPerPage(SectorSize);

    Pfn = AdapterGetNextSGEntry(TargetGetAdapter(Target),
                                SrbExt,
                                0,
                                &Offset,
                                &Length);
    if ((Offset & (SectorSize - 1)) == 0 &&
        (Length & (SectorSize - 1)) == 0) {
        ++Target->SegsGranted;
        // get first sector, last sector and count
        Segment->FirstSector    = (UCHAR)((Offset + SectorSize - 1) / SectorSize);
        *SectorsNow             = __min(SectorsLeft, SectorsPerPage - Segment->FirstSector);
        Segment->LastSector     = (UCHAR)(Segment->FirstSector + *SectorsNow - 1);
        Segment->BufferId       = NULL; // granted, ensure its null
        Segment->Buffer         = NULL; // granted, ensure its null
        Segment->Length         = 0;    // granted, ensure its 0

        ASSERT3U((Length / SectorSize), ==, *SectorsNow);
    } else {
        PMDL        Mdl;

        ++Target->SegsBounced;
        // get first sector, last sector and count
        Segment->FirstSector    = 0;
        *SectorsNow             = __min(SectorsLeft, SectorsPerPage);
        Segment->LastSector     = (UCHAR)(*SectorsNow - 1);

        // map SGList to Virtual Address. Populates Segment->Buffer and Segment->Length
#pragma warning(push)
#pragma warning(disable:28145)
        Mdl = &Segment->Mdl;
        Mdl->Next           = NULL;
        Mdl->Size           = (SHORT)(sizeof(MDL) + sizeof(PFN_NUMBER));
        Mdl->MdlFlags       = MDL_PAGES_LOCKED;
        Mdl->Process        = NULL;
        Mdl->MappedSystemVa = NULL;
        Mdl->StartVa        = NULL;
        Mdl->ByteCount      = Length;
        Mdl->ByteOffset     = Offset;
        Segment->Pfn[0]     = Pfn;

        if (Length < *SectorsNow * SectorSize) {
            Pfn = AdapterGetNextSGEntry(TargetGetAdapter(Target),
                                        SrbExt,
                                        Length,
                                        &Offset,
                                        &Length);
            Mdl->Size       += sizeof(PFN_NUMBER);
            Mdl->ByteCount  = Mdl->ByteCount + Length;
            Segment->Pfn[1] = Pfn;
        }
#pragma warning(pop)

        ASSERT((Mdl->ByteCount & (SectorSize - 1)) == 0);
        ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE);
        ASSERT3U(*SectorsNow, ==, (Mdl->ByteCount / SectorSize));

        Segment->Length = __min(Mdl->ByteCount, PAGE_SIZE);
        Segment->Buffer = MmMapLockedPagesSpecifyCache(Mdl, KernelMode,
                                MmCached, NULL, FALSE, __TargetPriority(Target));
        if (!Segment->Buffer) {
            ++Target->FailedMaps;
            goto fail1;
        }

        ASSERT3P(MmGetMdlPfnArray(Mdl)[0], ==, Segment->Pfn[0]);
        ASSERT3P(MmGetMdlPfnArray(Mdl)[1], ==, Segment->Pfn[1]);

        // get a buffer
        if (!BufferGet(Segment, &Segment->BufferId, &Pfn)) {
            ++Target->FailedBounces;
            goto fail2;
        }

        // copy contents in
        if (ReadOnly) { // Operation == BLKIF_OP_WRITE
            BufferCopyIn(Segment->BufferId, Segment->Buffer, Segment->Length);
        }
    }

    // Grant segment's page
    Status = GranterGet(Granter, Pfn, ReadOnly, &Segment->Grant);
    if (!NT_SUCCESS(Status)) {
        ++Target->FailedGrants;
        goto fail3;
    }

    return TRUE;

fail3:
fail2:
fail1:
    return FALSE;
}

static BOOLEAN
PrepareBlkifReadWrite(
    IN  PXENVBD_TARGET          Target,
    IN  PXENVBD_REQUEST         Request,
    IN  PXENVBD_SRBEXT          SrbExt,
    IN  ULONG                   MaxSegments,
    IN  ULONG64                 SectorStart,
    IN  ULONG                   SectorsLeft,
    OUT PULONG                  SectorsDone
    )
{
    UCHAR           Operation;
    BOOLEAN         ReadOnly;
    ULONG           Index;
    __Operation(Cdb_OperationEx(Request->Srb), &Operation, &ReadOnly);

    Request->Operation  = Operation;
    Request->NrSegments = 0;
    Request->FirstSector = SectorStart;

    for (Index = 0;
                Index < MaxSegments &&
                SectorsLeft > 0;
                        ++Index) {
        PXENVBD_SEGMENT Segment;
        ULONG           SectorsNow;

        Segment = TargetGetSegment(Target);
        if (Segment == NULL)
            goto fail1;

        InsertTailList(&Request->Segments, &Segment->Entry);
        ++Request->NrSegments;

        if (!PrepareSegment(Target,
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
PrepareBlkifIndirect(
    IN  PXENVBD_TARGET             Target,
    IN  PXENVBD_REQUEST         Request
    )
{
    ULONG           Index;
    ULONG           NrSegments = 0;

    for (Index = 0;
            Index < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST &&
            NrSegments < Request->NrSegments;
                ++Index) {
        PXENVBD_INDIRECT    Indirect;

        Indirect = TargetGetIndirect(Target);
        if (Indirect == NULL)
            goto fail1;
        InsertTailList(&Request->Indirects, &Indirect->Entry);

        NrSegments += XENVBD_MAX_SEGMENTS_PER_PAGE;
    }

    return TRUE;

fail1:
    return FALSE;
}

static FORCEINLINE ULONG
UseIndirect(
    IN  PXENVBD_TARGET             Target,
    IN  ULONG                   SectorsLeft
    )
{
    const ULONG SectorsPerPage = __SectorsPerPage(TargetSectorSize(Target));
    const ULONG MaxIndirectSegs = FrontendGetFeatures(Target->Frontend)->Indirect;

    if (MaxIndirectSegs <= BLKIF_MAX_SEGMENTS_PER_REQUEST)
        return BLKIF_MAX_SEGMENTS_PER_REQUEST; // not supported

    if (SectorsLeft < BLKIF_MAX_SEGMENTS_PER_REQUEST * SectorsPerPage)
        return BLKIF_MAX_SEGMENTS_PER_REQUEST; // first into a single BLKIF_OP_{READ/WRITE}

    return MaxIndirectSegs;
}

static FORCEINLINE ULONG
TargetQueueRequestList(
    IN  PXENVBD_TARGET     Target,
    IN  PLIST_ENTRY     List
    )
{
    ULONG               Count = 0;
    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry;

        Entry = RemoveHeadList(List);
        if (Entry == List)
            break;

        ++Count;
        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        __TargetIncBlkifOpCount(Target, Request);
        QueueAppend(&Target->PreparedReqs, &Request->Entry);
    }
    return Count;
}

static FORCEINLINE VOID
TargetCancelRequestList(
    IN  PXENVBD_TARGET     Target,
    IN  PLIST_ENTRY     List
    )
{
    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry;

        Entry = RemoveHeadList(List);
        if (Entry == List)
            break;

        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        TargetPutRequest(Target, Request);
    }
}

__checkReturn
static BOOLEAN
PrepareReadWrite(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT  SrbExt = GetSrbExt(Srb);
    ULONG64         SectorStart = Cdb_LogicalBlock(Srb);
    ULONG           SectorsLeft = Cdb_TransferBlock(Srb);
    LIST_ENTRY      List;
    ULONG           DebugCount;

    Srb->SrbStatus = SRB_STATUS_PENDING;

    InitializeListHead(&List);
    SrbExt->Count = 0;

    while (SectorsLeft > 0) {
        ULONG           MaxSegments;
        ULONG           SectorsDone = 0;
        PXENVBD_REQUEST Request;

        Request = TargetGetRequest(Target);
        if (Request == NULL)
            goto fail1;
        InsertTailList(&List, &Request->Entry);
        InterlockedIncrement(&SrbExt->Count);

        Request->Srb    = Srb;
        MaxSegments = UseIndirect(Target, SectorsLeft);

        if (!PrepareBlkifReadWrite(Target,
                                   Request,
                                   SrbExt,
                                   MaxSegments,
                                   SectorStart,
                                   SectorsLeft,
                                   &SectorsDone))
            goto fail2;

        if (MaxSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            if (!PrepareBlkifIndirect(Target, Request))
                goto fail3;
        }

        SectorsLeft -= SectorsDone;
        SectorStart += SectorsDone;
    }

    DebugCount = TargetQueueRequestList(Target, &List);
    if (DebugCount != (ULONG)SrbExt->Count) {
        Trace("[%u] %d != %u\n", TargetGetTargetId(Target), SrbExt->Count, DebugCount);
    }
    return TRUE;

fail3:
fail2:
fail1:
    TargetCancelRequestList(Target, &List);
    SrbExt->Count = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return FALSE;
}

__checkReturn
static BOOLEAN
PrepareSyncCache(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_REQUEST     Request;
    LIST_ENTRY          List;
    UCHAR               Operation;
    ULONG               DebugCount;

    Srb->SrbStatus = SRB_STATUS_PENDING;

    if (FrontendGetDiskInfo(Target->Frontend)->FlushCache)
        Operation = BLKIF_OP_FLUSH_DISKCACHE;
    else
        Operation = BLKIF_OP_WRITE_BARRIER;

    InitializeListHead(&List);
    SrbExt->Count = 0;

    Request = TargetGetRequest(Target);
    if (Request == NULL)
        goto fail1;
    InsertTailList(&List, &Request->Entry);
    InterlockedIncrement(&SrbExt->Count);

    Request->Srb        = Srb;
    Request->Operation  = Operation;
    Request->FirstSector = Cdb_LogicalBlock(Srb);

    DebugCount = TargetQueueRequestList(Target, &List);
    if (DebugCount != (ULONG)SrbExt->Count) {
        Trace("[%u] %d != %u\n", TargetGetTargetId(Target), SrbExt->Count, DebugCount);
    }
    return TRUE;

fail1:
    TargetCancelRequestList(Target, &List);
    SrbExt->Count = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return FALSE;
}

__checkReturn
static BOOLEAN
PrepareUnmap(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PUNMAP_LIST_HEADER  Unmap = Srb->DataBuffer;
	ULONG               Count = _byteswap_ushort(*(PUSHORT)Unmap->BlockDescrDataLength) / sizeof(UNMAP_BLOCK_DESCRIPTOR);
    ULONG               Index;
    LIST_ENTRY          List;
    ULONG               DebugCount;

    Srb->SrbStatus = SRB_STATUS_PENDING;

    InitializeListHead(&List);
    SrbExt->Count = 0;

    for (Index = 0; Index < Count; ++Index) {
        PUNMAP_BLOCK_DESCRIPTOR Descr = &Unmap->Descriptors[Index];
        PXENVBD_REQUEST         Request;

        Request = TargetGetRequest(Target);
        if (Request == NULL)
            goto fail1;
        InsertTailList(&List, &Request->Entry);
        InterlockedIncrement(&SrbExt->Count);

        Request->Srb            = Srb;
        Request->Operation      = BLKIF_OP_DISCARD;
        Request->FirstSector    = _byteswap_uint64(*(PULONG64)Descr->StartingLba);
        Request->NrSectors      = _byteswap_ulong(*(PULONG)Descr->LbaCount);
        Request->Flags          = 0;
    }

    DebugCount = TargetQueueRequestList(Target, &List);
    if (DebugCount != (ULONG)SrbExt->Count) {
        Trace("[%u] %d != %u\n", TargetGetTargetId(Target), SrbExt->Count, DebugCount);
    }
    return TRUE;

fail1:
    TargetCancelRequestList(Target, &List);
    SrbExt->Count = 0;
    Srb->SrbStatus = SRB_STATUS_ERROR;
    return FALSE;
}

//=============================================================================
// Queue-Related
static FORCEINLINE VOID
__TargetPauseDataPath(
    __in PXENVBD_TARGET             Target,
    __in BOOLEAN                 Timeout
    )
{
    KIRQL               Irql;
    ULONG               Requests;
    ULONG               Count = 0;
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Target->Frontend);
    PXENVBD_BLOCKRING   BlockRing = FrontendGetBlockRing(Target->Frontend);

    KeAcquireSpinLock(&Target->Lock, &Irql);
    ++Target->Paused;
    KeReleaseSpinLock(&Target->Lock, Irql);

    Requests = QueueCount(&Target->SubmittedReqs);
    KeMemoryBarrier();

    Verbose("Target[%d] : Waiting for %d Submitted requests\n", TargetGetTargetId(Target), Requests);

    // poll ring and send event channel notification every 1ms (for up to 3 minutes)
    while (QueueCount(&Target->SubmittedReqs)) {
        if (Timeout && Count > 180000)
            break;
        KeRaiseIrql(DISPATCH_LEVEL, &Irql);
        BlockRingPoll(BlockRing);
        KeLowerIrql(Irql);
        NotifierSend(Notifier);         // let backend know it needs to do some work
        StorPortStallExecution(1000);   // 1000 micro-seconds
        ++Count;
    }

    Verbose("Target[%d] : %u/%u Submitted requests left (%u iterrations)\n",
            TargetGetTargetId(Target), QueueCount(&Target->SubmittedReqs), Requests, Count);

    // Abort Fresh SRBs
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PLIST_ENTRY     Entry = QueuePop(&Target->FreshSrbs);
        if (Entry == NULL)
            break;
        SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, Entry);

        Verbose("Target[%d] : FreshSrb 0x%p -> SCSI_ABORTED\n", TargetGetTargetId(Target), SrbExt->Srb);
        SrbExt->Srb->SrbStatus = SRB_STATUS_ABORTED;
        SrbExt->Srb->ScsiStatus = 0x40; // SCSI_ABORTED;
        AdapterCompleteSrb(TargetGetAdapter(Target), SrbExt);
    }

    // Fail PreparedReqs
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = QueuePop(&Target->PreparedReqs);
        if (Entry == NULL)
            break;
        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        SrbExt = GetSrbExt(Request->Srb);

        Verbose("Target[%d] : PreparedReq 0x%p -> FAILED\n", TargetGetTargetId(Target), Request);

        SrbExt->Srb->SrbStatus = SRB_STATUS_ABORTED;
        TargetPutRequest(Target, Request);

        if (InterlockedDecrement(&SrbExt->Count) == 0) {
            SrbExt->Srb->ScsiStatus = 0x40; // SCSI_ABORTED
            AdapterCompleteSrb(TargetGetAdapter(Target), SrbExt);
        }
    }
}

static FORCEINLINE VOID
__TargetUnpauseDataPath(
    __in PXENVBD_TARGET             Target
    )
{
    KIRQL   Irql;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    --Target->Paused;
    KeReleaseSpinLock(&Target->Lock, Irql);
}

static FORCEINLINE BOOLEAN
TargetPrepareFresh(
    IN  PXENVBD_TARGET         Target
    )
{
    PXENVBD_SRBEXT  SrbExt;
    PLIST_ENTRY     Entry;

    Entry = QueuePop(&Target->FreshSrbs);
    if (Entry == NULL)
        return FALSE;   // fresh queue is empty

    SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, Entry);

    switch (Cdb_OperationEx(SrbExt->Srb)) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        if (PrepareReadWrite(Target, SrbExt->Srb))
            return TRUE;    // prepared this SRB
        break;
    case SCSIOP_SYNCHRONIZE_CACHE:
        if (PrepareSyncCache(Target, SrbExt->Srb))
            return TRUE;    // prepared this SRB
        break;
    case SCSIOP_UNMAP:
        if (PrepareUnmap(Target, SrbExt->Srb))
            return TRUE;    // prepared this SRB
        break;
    default:
        ASSERT(FALSE);
        break;
    }
    QueueUnPop(&Target->FreshSrbs, &SrbExt->Entry);

    return FALSE;       // prepare failed
}

static FORCEINLINE BOOLEAN
TargetSubmitPrepared(
    __in PXENVBD_TARGET             Target
    )
{
    PXENVBD_BLOCKRING   BlockRing = FrontendGetBlockRing(Target->Frontend);
    if (TargetIsPaused(Target)) {
        if (QueueCount(&Target->PreparedReqs))
            Warning("Target[%d] : Paused, not submitting new requests (%u)\n",
                    TargetGetTargetId(Target),
                    QueueCount(&Target->PreparedReqs));
        return FALSE;
    }

    for (;;) {
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry;

        Entry = QueuePop(&Target->PreparedReqs);
        if (Entry == NULL)
            break;

        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);

        QueueAppend(&Target->SubmittedReqs, &Request->Entry);
        KeMemoryBarrier();

        if (BlockRingSubmit(BlockRing, Request))
            continue;

        QueueRemove(&Target->SubmittedReqs, &Request->Entry);
        QueueUnPop(&Target->PreparedReqs, &Request->Entry);
        return FALSE;   // ring full
    }

    return TRUE;
}

static FORCEINLINE VOID
TargetCompleteShutdown(
    __in PXENVBD_TARGET             Target
    )
{
    if (QueueCount(&Target->ShutdownSrbs) == 0)
        return;

    if (QueueCount(&Target->FreshSrbs) ||
        QueueCount(&Target->PreparedReqs) ||
        QueueCount(&Target->SubmittedReqs))
        return;

    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PLIST_ENTRY     Entry = QueuePop(&Target->ShutdownSrbs);
        if (Entry == NULL)
            break;
        SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, Entry);
        SrbExt->Srb->SrbStatus = SRB_STATUS_SUCCESS;
        AdapterCompleteSrb(TargetGetAdapter(Target), SrbExt);
    }
}

static FORCEINLINE PCHAR
BlkifOperationName(
    IN  UCHAR                   Operation
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

VOID
TargetSubmitRequests(
    __in PXENVBD_TARGET             Target
    )
{
    for (;;) {
        // submit all prepared requests (0 or more requests)
        // return TRUE if submitted 0 or more requests from prepared queue
        // return FALSE iff ring is full
        if (!TargetSubmitPrepared(Target))
            break;

        // prepare a single SRB (into 1 or more requests)
        // return TRUE if prepare succeeded
        // return FALSE if prepare failed or fresh queue empty
        if (!TargetPrepareFresh(Target))
            break;
    }

    // if no requests/SRBs outstanding, complete any shutdown SRBs
    TargetCompleteShutdown(Target);
}

VOID
TargetCompleteResponse(
    __in PXENVBD_TARGET             Target,
    __in ULONG                   Tag,
    __in SHORT                   Status
    )
{
    PXENVBD_REQUEST     Request;
    PSCSI_REQUEST_BLOCK Srb;
    PXENVBD_SRBEXT      SrbExt;

    Request = TargetRequestFromTag(Target, Tag);
    if (Request == NULL)
        return;

    Srb     = Request->Srb;
    SrbExt  = GetSrbExt(Srb);
    ASSERT3P(SrbExt, !=, NULL);

    switch (Status) {
    case BLKIF_RSP_OKAY:
        RequestCopyOutput(Request);
        break;

    case BLKIF_RSP_EOPNOTSUPP:
        // Remove appropriate feature support
        FrontendRemoveFeature(Target->Frontend, Request->Operation);
        // Succeed this SRB, subsiquent SRBs will be succeeded instead of being passed to the backend.
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case BLKIF_RSP_ERROR:
    default:
        Warning("Target[%d] : %s BLKIF_RSP_ERROR (Tag %x)\n",
                TargetGetTargetId(Target), BlkifOperationName(Request->Operation), Tag);
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
    }

    TargetPutRequest(Target, Request);

    // complete srb
    if (InterlockedDecrement(&SrbExt->Count) == 0) {
        if (Srb->SrbStatus == SRB_STATUS_PENDING) {
            // SRB has not hit a failure condition (BLKIF_RSP_ERROR | BLKIF_RSP_EOPNOTSUPP)
            // from any of its responses. SRB must have succeeded
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            Srb->ScsiStatus = 0x00; // SCSI_GOOD
        } else {
            // Srb->SrbStatus has already been set by 1 or more requests with Status != BLKIF_RSP_OKAY
            Srb->ScsiStatus = 0x40; // SCSI_ABORTED
        }

        AdapterCompleteSrb(TargetGetAdapter(Target), SrbExt);
    }
}

VOID
TargetPreResume(
    __in PXENVBD_TARGET             Target
    )
{
    LIST_ENTRY          List;

    InitializeListHead(&List);

    // pop all submitted requests, cleanup and add associated SRB to a list
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = QueuePop(&Target->SubmittedReqs);
        if (Entry == NULL)
            break;
        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        SrbExt = GetSrbExt(Request->Srb);

        TargetPutRequest(Target, Request);

        if (InterlockedDecrement(&SrbExt->Count) == 0) {
            InsertTailList(&List, &SrbExt->Entry);
        }
    }

    // pop all prepared requests, cleanup and add associated SRB to a list
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PXENVBD_REQUEST Request;
        PLIST_ENTRY     Entry = QueuePop(&Target->PreparedReqs);
        if (Entry == NULL)
            break;
        Request = CONTAINING_RECORD(Entry, XENVBD_REQUEST, Entry);
        SrbExt = GetSrbExt(Request->Srb);

        TargetPutRequest(Target, Request);

        if (InterlockedDecrement(&SrbExt->Count) == 0) {
            InsertTailList(&List, &SrbExt->Entry);
        }
    }

    // foreach SRB in list, put on start of FreshSrbs
    for (;;) {
        PXENVBD_SRBEXT  SrbExt;
        PLIST_ENTRY     Entry = RemoveTailList(&List);
        if (Entry == &List)
            break;
        SrbExt = CONTAINING_RECORD(Entry, XENVBD_SRBEXT, Entry);

        QueueUnPop(&Target->FreshSrbs, &SrbExt->Entry);
    }

    // now the first set of requests popped off submitted list is the next SRB
    // to be popped off the fresh list
}

VOID
TargetPostResume(
    __in PXENVBD_TARGET             Target
    )
{
    KIRQL   Irql;

    Verbose("Target[%d] : %d Fresh SRBs\n", TargetGetTargetId(Target), QueueCount(&Target->FreshSrbs));

    // clear missing flag
    KeAcquireSpinLock(&Target->Lock, &Irql);
    Verbose("Target[%d] : %s (%s)\n", TargetGetTargetId(Target), Target->Missing ? "MISSING" : "NOT_MISSING", Target->Reason);
    Target->Missing = FALSE;
    Target->Reason = NULL;
    KeReleaseSpinLock(&Target->Lock, Irql);
}

//=============================================================================
// SRBs
__checkReturn
static FORCEINLINE BOOLEAN
__ValidateSectors(
    __in ULONG64                 SectorCount,
    __in ULONG64                 Start,
    __in ULONG                   Length
    )
{
    // Deal with overflow
    return (Start < SectorCount) && ((Start + Length) <= SectorCount);
}

__checkReturn
static FORCEINLINE BOOLEAN
__ValidateSrbBuffer(
    __in PCHAR                  Caller,
    __in PSCSI_REQUEST_BLOCK    Srb,
    __in ULONG                  MinLength
    )
{
    if (Srb->DataBuffer == NULL) {
        Error("%s: Srb[0x%p].DataBuffer = NULL\n", Caller, Srb);
        return FALSE;
    }
    if (MinLength) {
        if (Srb->DataTransferLength < MinLength) {
            Error("%s: Srb[0x%p].DataTransferLength < %d\n", Caller, Srb, MinLength);
            return FALSE;
        }
    } else {
        if (Srb->DataTransferLength == 0) {
            Error("%s: Srb[0x%p].DataTransferLength = 0\n", Caller, Srb);
            return FALSE;
        }
    }

    return TRUE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
TargetReadWrite(
    __in PXENVBD_TARGET            Target,
    __in PSCSI_REQUEST_BLOCK    Srb
    )
{
    PXENVBD_DISKINFO    DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Target->Frontend);

    if (FrontendGetCaps(Target->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    // check valid sectors
    if (!__ValidateSectors(DiskInfo->SectorCount, Cdb_LogicalBlock(Srb), Cdb_TransferBlock(Srb))) {
        Trace("Target[%d] : Invalid Sector (%d @ %lld < %lld)\n", TargetGetTargetId(Target), Cdb_TransferBlock(Srb), Cdb_LogicalBlock(Srb), DiskInfo->SectorCount);
        Srb->ScsiStatus = 0x40; // SCSI_ABORT
        return TRUE; // Complete now
    }

    QueueAppend(&Target->FreshSrbs, &SrbExt->Entry);
    NotifierKick(Notifier);

    return FALSE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
TargetSyncCache(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Target->Frontend);

    if (FrontendGetCaps(Target->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    if (FrontendGetDiskInfo(Target->Frontend)->FlushCache == FALSE &&
        FrontendGetDiskInfo(Target->Frontend)->Barrier == FALSE) {
        Trace("Target[%d] : FLUSH and BARRIER not supported, suppressing\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x00; // SCSI_GOOD
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        return TRUE;
    }

    QueueAppend(&Target->FreshSrbs, &SrbExt->Entry);
    NotifierKick(Notifier);

    return FALSE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
TargetUnmap(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Target->Frontend);

    if (FrontendGetCaps(Target->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    if (FrontendGetDiskInfo(Target->Frontend)->Discard == FALSE) {
        Trace("Target[%d] : DISCARD not supported, suppressing\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x00; // SCSI_GOOD
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        return TRUE;
    }

    QueueAppend(&Target->FreshSrbs, &SrbExt->Entry);
    NotifierKick(Notifier);

    return FALSE;
}

#define MODE_CACHING_PAGE_LENGTH 20
static DECLSPEC_NOINLINE VOID
TargetModeSense(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PMODE_PARAMETER_HEADER  Header  = Srb->DataBuffer;
    const UCHAR PageCode            = Cdb_PageCode(Srb);
    ULONG LengthLeft                = Cdb_AllocationLength(Srb);
    PVOID CurrentPage               = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, (ULONG)sizeof(struct _MODE_SENSE))) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

    // TODO : CDROM requires more ModePage entries
    // Header
    Header->ModeDataLength  = sizeof(MODE_PARAMETER_HEADER) - 1;
    Header->MediumType      = 0;
    Header->DeviceSpecificParameter = 0;
    Header->BlockDescriptorLength   = 0;
    LengthLeft -= sizeof(MODE_PARAMETER_HEADER);
    CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_PARAMETER_HEADER));

    // Fill in Block Parameters (if Specified and space)
    // when the DBD (Disable Block Descriptor) is set, ignore the block page
    if (Cdb_Dbd(Srb) == 0 &&
        LengthLeft >= sizeof(MODE_PARAMETER_BLOCK)) {
        PMODE_PARAMETER_BLOCK Block = (PMODE_PARAMETER_BLOCK)CurrentPage;
        // Fill in BlockParams
        Block->DensityCode                  =   0;
        Block->NumberOfBlocks[0]            =   0;
        Block->NumberOfBlocks[1]            =   0;
        Block->NumberOfBlocks[2]            =   0;
        Block->BlockLength[0]               =   0;
        Block->BlockLength[1]               =   0;
        Block->BlockLength[2]               =   0;

        Header->BlockDescriptorLength = sizeof(MODE_PARAMETER_BLOCK);
        Header->ModeDataLength += sizeof(MODE_PARAMETER_BLOCK);
        LengthLeft -= sizeof(MODE_PARAMETER_BLOCK);
        CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_PARAMETER_BLOCK));
    }

    // Fill in Cache Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_CACHING || PageCode == MODE_SENSE_RETURN_ALL) &&
        LengthLeft >= MODE_CACHING_PAGE_LENGTH) {
        PMODE_CACHING_PAGE Caching = (PMODE_CACHING_PAGE)CurrentPage;
        // Fill in CachingParams
        Caching->PageCode                   = MODE_PAGE_CACHING;
        Caching->PageSavable                = 0;
        Caching->PageLength                 = MODE_CACHING_PAGE_LENGTH;
        Caching->ReadDisableCache           = 0;
        Caching->MultiplicationFactor       = 0;
        Caching->WriteCacheEnable           = FrontendGetDiskInfo(Target->Frontend)->FlushCache ? 1 : 0;
        Caching->WriteRetensionPriority     = 0;
        Caching->ReadRetensionPriority      = 0;
        Caching->DisablePrefetchTransfer[0] = 0;
        Caching->DisablePrefetchTransfer[1] = 0;
        Caching->MinimumPrefetch[0]         = 0;
        Caching->MinimumPrefetch[1]         = 0;
        Caching->MaximumPrefetch[0]         = 0;
        Caching->MaximumPrefetch[1]         = 0;
        Caching->MaximumPrefetchCeiling[0]  = 0;
        Caching->MaximumPrefetchCeiling[1]  = 0;

        Header->ModeDataLength += MODE_CACHING_PAGE_LENGTH;
        LengthLeft -= MODE_CACHING_PAGE_LENGTH;
        CurrentPage = ((PUCHAR)CurrentPage + MODE_CACHING_PAGE_LENGTH);
    }

    // Fill in Informational Exception Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_FAULT_REPORTING || PageCode == MODE_SENSE_RETURN_ALL) &&
        LengthLeft >= sizeof(MODE_INFO_EXCEPTIONS)) {
        PMODE_INFO_EXCEPTIONS Exceptions = (PMODE_INFO_EXCEPTIONS)CurrentPage;
        // Fill in Exceptions
        Exceptions->PageCode                = MODE_PAGE_FAULT_REPORTING;
        Exceptions->PSBit                   = 0;
        Exceptions->PageLength              = sizeof(MODE_INFO_EXCEPTIONS);
        Exceptions->Flags                   = 0;
        Exceptions->Dexcpt                  = 1; // disabled
        Exceptions->ReportMethod            = 0;
        Exceptions->IntervalTimer[0]        = 0;
        Exceptions->IntervalTimer[1]        = 0;
        Exceptions->IntervalTimer[2]        = 0;
        Exceptions->IntervalTimer[3]        = 0;
        Exceptions->ReportCount[0]          = 0;
        Exceptions->ReportCount[1]          = 0;
        Exceptions->ReportCount[2]          = 0;
        Exceptions->ReportCount[3]          = 0;

        Header->ModeDataLength += sizeof(MODE_INFO_EXCEPTIONS);
        LengthLeft -= sizeof(MODE_INFO_EXCEPTIONS);
        CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_INFO_EXCEPTIONS));
    }

    // Finish this SRB
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    Srb->DataTransferLength = __min(Cdb_AllocationLength(Srb), (ULONG)(Header->ModeDataLength + 1));
}

static DECLSPEC_NOINLINE VOID
TargetRequestSense(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PSENSE_DATA         Sense = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, (ULONG)sizeof(SENSE_DATA))) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        return;
    }

    RtlZeroMemory(Sense, sizeof(SENSE_DATA));

    Sense->ErrorCode            = 0x70;
    Sense->Valid                = 1;
    Sense->AdditionalSenseCodeQualifier = 0;
    Sense->SenseKey             = SCSI_SENSE_NO_SENSE;
    Sense->AdditionalSenseCode  = SCSI_ADSENSE_NO_SENSE;
    Srb->DataTransferLength     = sizeof(SENSE_DATA);
    Srb->SrbStatus              = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReportLuns(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    ULONG           Length;
    ULONG           Offset;
    ULONG           AllocLength = Cdb_AllocationLength(Srb);
    PUCHAR          Buffer = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, 8)) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

    RtlZeroMemory(Buffer, AllocLength);

    Length = 0;
    Offset = 8;

    if (Offset + 8 <= AllocLength) {
        Buffer[Offset] = 0;
        Offset += 8;
        Length += 8;
    }

    if (Offset + 8 <= AllocLength) {
        Buffer[Offset] = XENVBD_MAX_TARGETS;
        Offset += 8;
        Length += 8;
    }

    REVERSE_BYTES(Buffer, &Length);

    Srb->DataTransferLength = __min(Length, AllocLength);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReadCapacity(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PREAD_CAPACITY_DATA     Capacity = Srb->DataBuffer;
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   LastBlock;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0) {
        Srb->ScsiStatus = 0x02; // CHECK_CONDITION
        return;
    }

    SectorCount = DiskInfo->SectorCount;
    SectorSize = DiskInfo->SectorSize;

    if (SectorCount == (ULONG)SectorCount)
        LastBlock = (ULONG)SectorCount - 1;
    else
        LastBlock = ~(ULONG)0;

    if (Capacity) {
        Capacity->LogicalBlockAddress = _byteswap_ulong(LastBlock);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReadCapacity16(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PREAD_CAPACITY16_DATA   Capacity = Srb->DataBuffer;
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   PhysSectorSize;
    ULONG                   LogicalPerPhysical;
    ULONG                   LogicalPerPhysicalExponent;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0) {
        Srb->ScsiStatus = 0x02; // CHECK_CONDITION
        return;
    }

    SectorCount = DiskInfo->SectorCount;
    SectorSize = DiskInfo->SectorSize;
    PhysSectorSize = DiskInfo->PhysSectorSize;

    LogicalPerPhysical = PhysSectorSize / SectorSize;

    if (!_BitScanReverse(&LogicalPerPhysicalExponent, LogicalPerPhysical))
        LogicalPerPhysicalExponent = 0;

    if (Capacity) {
        Capacity->LogicalBlockAddress.QuadPart = _byteswap_uint64(SectorCount - 1);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
        Capacity->LogicalPerPhysicalExponent = (UCHAR)LogicalPerPhysicalExponent;
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

//=============================================================================
// StorPort Methods
__checkReturn
static FORCEINLINE BOOLEAN
__TargetExecuteScsi(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    const UCHAR Operation = Cdb_OperationEx(Srb);
    PXENVBD_DISKINFO    DiskInfo = FrontendGetDiskInfo(Target->Frontend);

    if (DiskInfo->DiskInfo & VDISK_READONLY) {
        Trace("Target[%d] : (%08x) Read-Only, fail SRB (%02x:%s)\n", TargetGetTargetId(Target),
                DiskInfo->DiskInfo, Operation, Cdb_OperationName(Operation));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT
        return TRUE;
    }

    // idea: check pdo state here. still push to freshsrbs
    switch (Operation) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        return TargetReadWrite(Target, Srb);
        break;

    case SCSIOP_SYNCHRONIZE_CACHE:
        return TargetSyncCache(Target, Srb);
        break;

    case SCSIOP_UNMAP:
        return TargetUnmap(Target, Srb);
        break;

    case SCSIOP_INQUIRY:
        AdapterSetDeviceQueueDepth(TargetGetAdapter(Target),
                                   TargetGetTargetId(Target));
        PdoInquiry(TargetGetTargetId(Target), FrontendGetInquiry(Target->Frontend), Srb);
        break;
    case SCSIOP_MODE_SENSE:
        TargetModeSense(Target, Srb);
        break;
    case SCSIOP_REQUEST_SENSE:
        TargetRequestSense(Target, Srb);
        break;
    case SCSIOP_REPORT_LUNS:
        TargetReportLuns(Target, Srb);
        break;
    case SCSIOP_READ_CAPACITY:
        TargetReadCapacity(Target, Srb);
        break;
    case SCSIOP_READ_CAPACITY16:
        TargetReadCapacity16(Target, Srb);
        break;
    case SCSIOP_MEDIUM_REMOVAL:
    case SCSIOP_TEST_UNIT_READY:
    case SCSIOP_RESERVE_UNIT:
    case SCSIOP_RESERVE_UNIT10:
    case SCSIOP_RELEASE_UNIT:
    case SCSIOP_RELEASE_UNIT10:
    case SCSIOP_VERIFY:
    case SCSIOP_VERIFY16:
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    case SCSIOP_START_STOP_UNIT:
        Trace("Target[%d] : Start/Stop Unit (%02X)\n", TargetGetTargetId(Target), Srb->Cdb[4]);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    default:
        Trace("Target[%d] : Unsupported CDB (%02x:%s)\n", TargetGetTargetId(Target), Operation, Cdb_OperationName(Operation));
        break;
    }
    return TRUE;
}

static FORCEINLINE BOOLEAN
__TargetQueueShutdown(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_NOTIFIER    Notifier = FrontendGetNotifier(Target->Frontend);

    QueueAppend(&Target->ShutdownSrbs, &SrbExt->Entry);
    NotifierKick(Notifier);

    return FALSE;
}

static FORCEINLINE BOOLEAN
__TargetReset(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    Verbose("Target[%u] ====>\n", TargetGetTargetId(Target));

    TargetReset(Target);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;

    Verbose("Target[%u] <====\n", TargetGetTargetId(Target));
    return TRUE;
}

__checkReturn
static FORCEINLINE BOOLEAN
__ValidateSrbForTarget(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    const UCHAR Operation = Cdb_OperationEx(Srb);

    if (Target == NULL) {
        Error("Invalid Target(NULL) (%02x:%s)\n",
                Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_TARGET_ID;
        return FALSE;
    }

    if (Srb->PathId != 0) {
        Error("Target[%d] : Invalid PathId(%d) (%02x:%s)\n",
                TargetGetTargetId(Target), Srb->PathId, Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_PATH_ID;
        return FALSE;
    }

    if (Srb->Lun != 0) {
        Error("Target[%d] : Invalid Lun(%d) (%02x:%s)\n",
                TargetGetTargetId(Target), Srb->Lun, Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_LUN;
        return FALSE;
    }

    if (TargetIsMissing(Target)) {
        Error("Target[%d] : %s (%s) (%02x:%s)\n",
                TargetGetTargetId(Target), Target->Missing ? "MISSING" : "NOT_MISSING", Target->Reason, Operation, Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
TargetStartIo(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

    if (!__ValidateSrbForTarget(Target, Srb))
        return TRUE;

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:
        return __TargetExecuteScsi(Target, Srb);

    case SRB_FUNCTION_RESET_DEVICE:
        return __TargetReset(Target, Srb);

    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_SHUTDOWN:
        return __TargetQueueShutdown(Target, Srb);

    default:
        return TRUE;
    }
}

VOID
TargetReset(
    __in PXENVBD_TARGET             Target
    )
{
    Trace("Target[%d] ====> (Irql=%d)\n", TargetGetTargetId(Target), KeGetCurrentIrql());

    __TargetPauseDataPath(Target, TRUE);

    if (QueueCount(&Target->SubmittedReqs)) {
        Error("Target[%d] : backend has %u outstanding requests after a TargetReset\n",
                TargetGetTargetId(Target), QueueCount(&Target->SubmittedReqs));
    }

    __TargetUnpauseDataPath(Target);

    Trace("Target[%d] <==== (Irql=%d)\n", TargetGetTargetId(Target), KeGetCurrentIrql());
}


VOID
TargetSrbPnp(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_PNP_REQUEST_BLOCK Srb
    )
{
    switch (Srb->PnPAction) {
    case StorQueryCapabilities: {
        PSTOR_DEVICE_CAPABILITIES DeviceCaps = Srb->DataBuffer;
        PXENVBD_CAPS    Caps = FrontendGetCaps(Target->Frontend);

        if (Caps->Removable)
            DeviceCaps->Removable = 1;
        if (Caps->Removable)
            DeviceCaps->EjectSupported = 1;
        if (Caps->SurpriseRemovable)
            DeviceCaps->SurpriseRemovalOK = 1;

        DeviceCaps->UniqueID = 1;

        } break;

    default:
        break;
    }
}

//=============================================================================
// PnP Handler
static FORCEINLINE VOID
__TargetDeviceUsageNotification(
    __in PXENVBD_TARGET             Target,
    __in PIRP                    Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    BOOLEAN                 Value;
    DEVICE_USAGE_NOTIFICATION_TYPE  Type;
    PXENVBD_CAPS            Caps = FrontendGetCaps(Target->Frontend);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Value = StackLocation->Parameters.UsageNotification.InPath;
    Type  = StackLocation->Parameters.UsageNotification.Type;

    switch (Type) {
    case DeviceUsageTypePaging:
        if (Caps->Paging == Value)
            return;
        Caps->Paging = Value;
        break;

    case DeviceUsageTypeHibernation:
        if (Caps->Hibernation == Value)
            return;
        Caps->Hibernation = Value;
        break;

    case DeviceUsageTypeDumpFile:
        if (Caps->DumpFile == Value)
            return;
        Caps->DumpFile = Value;
        break;

    default:
        return;
    }
    FrontendWriteUsage(Target->Frontend);
}

static FORCEINLINE VOID
__TargetCheckEjectPending(
    __in PXENVBD_TARGET             Target
    )
{
    KIRQL               Irql;
    BOOLEAN             EjectPending = FALSE;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->EjectPending) {
        EjectPending = TRUE;
        Target->EjectPending = FALSE;
        Target->EjectRequested = TRUE;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);

    if (EjectPending) {
        Verbose("Target[%d] : IoRequestDeviceEject(0x%p)\n", TargetGetTargetId(Target), Target->DeviceObject);
        IoRequestDeviceEject(Target->DeviceObject);
    }
}

static FORCEINLINE VOID
__TargetCheckEjectFailed(
    __in PXENVBD_TARGET             Target
    )
{
    KIRQL               Irql;
    BOOLEAN             EjectFailed = FALSE;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->EjectRequested) {
        EjectFailed = TRUE;
        Target->EjectRequested = FALSE;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);

    if (EjectFailed) {
        Error("Target[%d] : Unplug failed due to open handle(s)!\n", TargetGetTargetId(Target));
        FrontendStoreWriteFrontend(Target->Frontend, "error", "Unplug failed due to open handle(s)!");
    }
}

static FORCEINLINE VOID
__TargetRemoveDevice(
    __in PXENVBD_TARGET             Target
    )
{
    TargetD0ToD3(Target);

    switch (TargetGetDevicePnpState(Target)) {
    case SurpriseRemovePending:
        TargetSetMissing(Target, "Surprise Remove");
        TargetSetDevicePnpState(Target, Deleted);
        AdapterTargetListChanged(TargetGetAdapter(Target));
        break;

    default:
        TargetSetMissing(Target, "Removed");
        TargetSetDevicePnpState(Target, Deleted);
        AdapterTargetListChanged(TargetGetAdapter(Target));
        break;
    }
}

static FORCEINLINE VOID
__TargetEject(
    __in PXENVBD_TARGET             Target
    )
{
    TargetSetMissing(Target, "Ejected");
    TargetSetDevicePnpState(Target, Deleted);
    AdapterTargetListChanged(TargetGetAdapter(Target));
}

__checkReturn
NTSTATUS
TargetDispatchPnp(
    __in PXENVBD_TARGET             Target,
    __in PDEVICE_OBJECT          DeviceObject,
    __in PIRP                    Irp
    )
{
    PIO_STACK_LOCATION  Stack = IoGetCurrentIrpStackLocation(Irp);

    __TargetCheckEjectPending(Target);

    switch (Stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        (VOID) TargetD3ToD0(Target);
        TargetSetDevicePnpState(Target, Started);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        TargetSetDevicePnpState(Target, StopPending);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        __TargetRestoreDevicePnpState(Target, StopPending);
        break;

    case IRP_MN_STOP_DEVICE:
        TargetD0ToD3(Target);
        TargetSetDevicePnpState(Target, Stopped);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        TargetSetDevicePnpState(Target, RemovePending);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        __TargetCheckEjectFailed(Target);
        __TargetRestoreDevicePnpState(Target, RemovePending);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        TargetSetDevicePnpState(Target, SurpriseRemovePending);
        break;

    case IRP_MN_REMOVE_DEVICE:
        __TargetRemoveDevice(Target);
        break;

    case IRP_MN_EJECT:
        __TargetEject(Target);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        __TargetDeviceUsageNotification(Target, Irp);
        break;

    default:
        break;
    }
    return DriverDispatchPnp(DeviceObject, Irp);
}

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
TargetIssueDeviceEject(
    __in PXENVBD_TARGET             Target,
    __in __nullterminated const CHAR* Reason
    )
{
    KIRQL       Irql;
    BOOLEAN     DoEject = FALSE;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->DeviceObject) {
        DoEject = TRUE;
        Target->EjectRequested = TRUE;
    } else {
        Target->EjectPending = TRUE;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);

    Verbose("Target[%d] : Ejecting (%s - %s)\n", TargetGetTargetId(Target), DoEject ? "Now" : "Next PnP IRP", Reason);
    if (!Target->WrittenEjected) {
        Target->WrittenEjected = TRUE;
        FrontendStoreWriteFrontend(Target->Frontend, "ejected", "1");
    }
    if (DoEject) {
        Verbose("Target[%d] : IoRequestDeviceEject(0x%p)\n", TargetGetTargetId(Target), Target->DeviceObject);
        IoRequestDeviceEject(Target->DeviceObject);
    } else {
        Verbose("Target[%d] : Triggering BusChangeDetected to detect device\n", TargetGetTargetId(Target));
        AdapterTargetListChanged(TargetGetAdapter(Target));
    }
}

__checkReturn
NTSTATUS
TargetD3ToD0(
    __in PXENVBD_TARGET            Target
    )
{
    NTSTATUS                    Status;
    const ULONG                 TargetId = TargetGetTargetId(Target);

    if (!TargetSetDevicePowerState(Target, PowerDeviceD0))
        return STATUS_SUCCESS;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : D3->D0\n", TargetId);

    // power up frontend
    Status = FrontendD3ToD0(Target->Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // connect frontend
    Status = FrontendSetState(Target->Frontend, XENVBD_ENABLED);
    if (!NT_SUCCESS(Status))
        goto fail2;
    __TargetUnpauseDataPath(Target);

    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");
    FrontendD0ToD3(Target->Frontend);

fail1:
    Error("Fail1 (%08x)\n", Status);

    Target->DevicePowerState = PowerDeviceD3;

    return Status;
}

VOID
TargetD0ToD3(
    __in PXENVBD_TARGET            Target
    )
{
    const ULONG                 TargetId = TargetGetTargetId(Target);

    if (!TargetSetDevicePowerState(Target, PowerDeviceD3))
        return;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : D0->D3\n", TargetId);

    // close frontend
    __TargetPauseDataPath(Target, FALSE);
    (VOID) FrontendSetState(Target->Frontend, XENVBD_CLOSED);
    ASSERT3U(QueueCount(&Target->SubmittedReqs), ==, 0);

    // power down frontend
    FrontendD0ToD3(Target->Frontend);

    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
}

static FORCEINLINE ULONG
__ParseVbd(
    IN  PCHAR   DeviceIdStr
    )
{
    ULONG   DeviceId = strtoul(DeviceIdStr, NULL, 10);

    ASSERT3U((DeviceId & ~((1 << 29) - 1)), ==, 0);

    if (DeviceId & (1 << 28))
        return (DeviceId & ((1 << 20) - 1)) >> 8;       /* xvd    */

    switch (DeviceId >> 8) {
    case 202:   return (DeviceId & 0xF0) >> 4;          /* xvd    */
    case 8:     return (DeviceId & 0xF0) >> 4;          /* sd     */
    case 3:     return (DeviceId & 0xC0) >> 6;          /* hda..b */
    case 22:    return ((DeviceId & 0xC0) >> 6) + 2;    /* hdc..d */
    case 33:    return ((DeviceId & 0xC0) >> 6) + 4;    /* hde..f */
    case 34:    return ((DeviceId & 0xC0) >> 6) + 6;    /* hdg..h */
    case 56:    return ((DeviceId & 0xC0) >> 6) + 8;    /* hdi..j */
    case 57:    return ((DeviceId & 0xC0) >> 6) + 10;   /* hdk..l */
    case 88:    return ((DeviceId & 0xC0) >> 6) + 12;   /* hdm..n */
    case 89:    return ((DeviceId & 0xC0) >> 6) + 14;   /* hdo..p */
    default:    return 0xFFFFFFFF;                      /* ERROR  */
    }
}

__checkReturn
NTSTATUS
TargetCreate(
    __in PXENVBD_ADAPTER             Adapter,
    __in __nullterminated PCHAR  DeviceId,
    OUT PXENVBD_TARGET*         _Target
    )
{
    NTSTATUS    Status;
    PXENVBD_TARGET Target;
    ULONG           TargetId;

    TargetId = __ParseVbd(DeviceId);
    if (TargetId >= XENVBD_MAX_TARGETS)
        return STATUS_RETRY;

    if (AdapterIsTargetEmulated(Adapter, TargetId))
        return STATUS_RETRY;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());

    Status = STATUS_INSUFFICIENT_RESOURCES;
#pragma warning(suppress: 6014)
    Target = __TargetAlloc(sizeof(XENVBD_TARGET));
    if (!Target)
        goto fail1;

    Verbose("Target[%d] : Creating\n", TargetId);
    Target->Signature      = TARGET_SIGNATURE;
    Target->Adapter            = Adapter;
    Target->DeviceObject   = NULL; // filled in later
    Target->Paused         = 1; // Paused until D3->D0 transition
    Target->DevicePnpState = Present;
    Target->DevicePowerState = PowerDeviceD3;

    KeInitializeSpinLock(&Target->Lock);
    QueueInit(&Target->FreshSrbs);
    QueueInit(&Target->PreparedReqs);
    QueueInit(&Target->SubmittedReqs);
    QueueInit(&Target->ShutdownSrbs);
    __LookasideInit(&Target->RequestList, sizeof(XENVBD_REQUEST), REQUEST_POOL_TAG);
    __LookasideInit(&Target->SegmentList, sizeof(XENVBD_SEGMENT), SEGMENT_POOL_TAG);
    __LookasideInit(&Target->IndirectList, sizeof(XENVBD_INDIRECT), INDIRECT_POOL_TAG);

    Status = FrontendCreate(Target, DeviceId, TargetId, &Target->Frontend);
    if (!NT_SUCCESS(Status))
        goto fail2;

    Status = TargetD3ToD0(Target);
    if (!NT_SUCCESS(Status))
        goto fail3;

    *_Target = Target;

    Verbose("Target[%d] : Created (%s)\n", TargetId, Target);
    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail3:
    Error("Fail3\n");
    FrontendDestroy(Target->Frontend);
    Target->Frontend = NULL;

fail2:
    Error("Fail2\n");
    __LookasideTerm(&Target->IndirectList);
    __LookasideTerm(&Target->SegmentList);
    __LookasideTerm(&Target->RequestList);
    __TargetFree(Target);

fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}

VOID
TargetDestroy(
    __in PXENVBD_TARGET    Target
    )
{
    const ULONG         TargetId = TargetGetTargetId(Target);
    PVOID               Objects[3];
    PKWAIT_BLOCK        WaitBlock;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : Destroying\n", TargetId);

    ASSERT3U(Target->Signature, ==, TARGET_SIGNATURE);

    TargetD0ToD3(Target);

    Verbose("Target[%d] : RequestListUsed %d\n", TargetId, Target->RequestList.Used);
    Objects[0] = &Target->RequestList.Empty;
    Objects[1] = &Target->SegmentList.Empty;
    Objects[2] = &Target->IndirectList.Empty;

    WaitBlock = (PKWAIT_BLOCK)__TargetAlloc(sizeof(KWAIT_BLOCK) * ARRAYSIZE(Objects));
    if (WaitBlock == NULL) {
        ULONG   Index;

        Error("Unable to allocate resources for KWAIT_BLOCK\n");

        for (Index = 0; Index < ARRAYSIZE(Objects); Index++)
            KeWaitForSingleObject(Objects[Index],
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);
    } else {
        KeWaitForMultipleObjects(ARRAYSIZE(Objects),
                                 Objects,
                                 WaitAll,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL,
                                 WaitBlock);
#pragma prefast(suppress:6102)
        __TargetFree(WaitBlock);
    }

    ASSERT3U(TargetGetDevicePnpState(Target), ==, Deleted);

    FrontendDestroy(Target->Frontend);
    Target->Frontend = NULL;

    __LookasideTerm(&Target->IndirectList);
    __LookasideTerm(&Target->SegmentList);
    __LookasideTerm(&Target->RequestList);

    ASSERT3U(Target->Signature, ==, TARGET_SIGNATURE);
    RtlZeroMemory(Target, sizeof(XENVBD_TARGET));
    __TargetFree(Target);

    Verbose("Target[%d] : Destroyed\n", TargetId);
    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
}
