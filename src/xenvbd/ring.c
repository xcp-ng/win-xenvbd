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
#include <stdlib.h>
#include <ntstrsafe.h>

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

#define TAG_HEADER                  'gaTX'
#define XENVBD_MAX_RING_PAGE_ORDER  (4)
#define XENVBD_MAX_RING_PAGES       (1 << XENVBD_MAX_RING_PAGE_ORDER)

struct _XENVBD_RING {
    PXENVBD_FRONTEND                Frontend;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;

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

    ULONG                           Submitted;
    ULONG                           Received;
    ULONG                           Events;
    ULONG                           Dpcs;
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

static FORCEINLINE ULONG64
__RingGetTag(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_REQUEST Request
    )
{
    UNREFERENCED_PARAMETER(Ring);
    return ((ULONG64)TAG_HEADER << 32) | (ULONG64)Request->Id;
}

static FORCEINLINE BOOLEAN
__RingPutTag(
    IN  PXENVBD_RING    Ring,
    IN  ULONG64         Id,
    OUT PULONG          Tag
    )
{
    ULONG   Header = (ULONG)((Id >> 32) & 0xFFFFFFFF);

    UNREFERENCED_PARAMETER(Ring);

    *Tag    = (ULONG)(Id & 0xFFFFFFFF);
    if (Header != TAG_HEADER) {
        Error("PUT_TAG (%llx) TAG_HEADER (%08x%08x)\n", Id, Header, *Tag);
        return FALSE;
    }

    return TRUE;
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
            req_indirect->id                = __RingGetTag(Ring, Request);
            req_indirect->sector_number     = Request->FirstSector;
            req_indirect->handle            = (USHORT)FrontendGetDeviceId(Ring->Frontend);

            for (PageIdx = 0,
                 PageEntry = Request->Indirects.Flink,
                 SegEntry = Request->Segments.Flink;
                    PageIdx < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST &&
                    PageEntry != &Request->Indirects &&
                    SegEntry != &Request->Segments;
                        ++PageIdx, PageEntry = PageEntry->Flink) {
                PXENVBD_INDIRECT Page = CONTAINING_RECORD(PageEntry, XENVBD_INDIRECT, Entry);

                req_indirect->indirect_grefs[PageIdx] = GranterReference(Granter, Page->Grant);

                for (SegIdx = 0;
                        SegIdx < XENVBD_MAX_SEGMENTS_PER_PAGE &&
                        SegEntry != &Request->Segments;
                            ++SegIdx, SegEntry = SegEntry->Flink) {
                    PXENVBD_SEGMENT Segment = CONTAINING_RECORD(SegEntry, XENVBD_SEGMENT, Entry);

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
            req->id                         = __RingGetTag(Ring, Request);
            req->sector_number              = Request->FirstSector;

            for (Index = 0, Entry = Request->Segments.Flink;
                    Index < BLKIF_MAX_SEGMENTS_PER_REQUEST &&
                    Entry != &Request->Segments;
                        ++Index, Entry = Entry->Flink) {
                PXENVBD_SEGMENT Segment = CONTAINING_RECORD(Entry, XENVBD_SEGMENT, Entry);
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
        req->id                         = __RingGetTag(Ring, Request);
        req->sector_number              = Request->FirstSector;
        break;

    case BLKIF_OP_DISCARD: {
        blkif_request_discard_t*        req_discard;
        req_discard = (blkif_request_discard_t*)req;
        req_discard->operation          = BLKIF_OP_DISCARD;
        req_discard->flag               = Request->Flags;
        req_discard->handle             = (USHORT)FrontendGetDeviceId(Ring->Frontend);
        req_discard->id                 = __RingGetTag(Ring, Request);
        req_discard->sector_number      = Request->FirstSector;
        req_discard->nr_sectors         = Request->NrSectors;
        } break;

    default:
        ASSERT(FALSE);
        break;
    }
    ++Ring->Submitted;
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
        if (!FrontendNotifyResponses(Ring->Frontend)) {
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
}

NTSTATUS
RingCreate(
    IN  PXENVBD_FRONTEND    Frontend,
    OUT PXENVBD_RING*       Ring
    )
{
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

    return STATUS_SUCCESS;

fail1:
    Error("fail1 %08x\n", status);
    return status;
}

VOID
RingDestroy(
    IN  PXENVBD_RING    Ring
    )
{
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
        Ring->Order = strtoul(Buffer, NULL, 10);
        if (Ring->Order > XENVBD_MAX_RING_PAGE_ORDER)
            Ring->Order = XENVBD_MAX_RING_PAGE_ORDER;

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
    ASSERT(Ring->Enabled == TRUE);
    Ring->Enabled = FALSE;

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

BOOLEAN
RingPoll(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_TARGET      Target = FrontendGetTarget(Ring->Frontend);
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
            blkif_response_t*   Response;
            ULONG               Tag;

            Response = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
            ++rsp_cons;

            if (__RingPutTag(Ring, Response->id, &Tag)) {
                ++Ring->Received;
                TargetCompleteResponse(Target, Tag, Response->status);
            }

            RtlZeroMemory(Response, sizeof(union blkif_sring_entry));

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

BOOLEAN
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

    if (Notify)
        RingSend(Ring);

    return TRUE;
}

VOID
RingKick(
    IN  PXENVBD_RING    Ring
    )
{
    if (!Ring->Enabled)
        return;

    if (KeInsertQueueDpc(&Ring->Dpc, NULL, NULL))
	    ++Ring->Dpcs;
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
RingSend(
    IN  PXENVBD_RING    Ring
    )
{
    if (!Ring->Enabled)
        return;

    XENBUS_EVTCHN(Send,
                  &Ring->EvtchnInterface,
                  Ring->Channel);
}
