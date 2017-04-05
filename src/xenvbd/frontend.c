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

#include "frontend.h"
#include "registry.h"
#include "driver.h"
#include "adapter.h"
#include "pdoinquiry.h"
#include "srbext.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include "names.h"
#include "notifier.h"
#include "blockring.h"
#include "granter.h"
#include "thread.h"
#include <store_interface.h>
#include <suspend_interface.h>

#include <stdlib.h>

struct _XENVBD_FRONTEND {
    // Frontend
    PXENVBD_TARGET                 Target;
    ULONG                       TargetId;
    ULONG                       DeviceId;
    PCHAR                       FrontendPath;
    PCHAR                       BackendPath;
    PCHAR                       TargetPath;
    USHORT                      BackendId;
    XENVBD_STATE                State;
    KSPIN_LOCK                  StateLock;

    XENVBD_CAPS                 Caps;
    XENVBD_FEATURES             Features;
    XENVBD_DISKINFO             DiskInfo;
    PVOID                       Inquiry;

    // Interfaces to XenBus
    PXENBUS_STORE_INTERFACE     Store;
    PXENBUS_SUSPEND_INTERFACE   Suspend;

    PXENBUS_SUSPEND_CALLBACK    SuspendLateCallback;

    // Ring
    PXENVBD_NOTIFIER            Notifier;
    PXENVBD_BLOCKRING           BlockRing;
    PXENVBD_GRANTER             Granter;

    // Backend State Watch
    BOOLEAN                     Active;
    PXENVBD_THREAD              BackendThread;
    PXENBUS_STORE_WATCH         BackendWatch;
};

#define DOMID_INVALID (0x7FF4U)

static const PCHAR
__XenvbdStateName(
    IN  XENVBD_STATE                        State
    )
{
    switch (State) {
    case XENVBD_STATE_INVALID:      return "STATE_INVALID";
    case XENVBD_INITIALIZED:        return "INITIALIZED";
    case XENVBD_CLOSING:            return "CLOSING";
    case XENVBD_CLOSED:             return "CLOSED";
    case XENVBD_PREPARED:           return "PREPARED";
    case XENVBD_CONNECTED:          return "CONNECTED";
    case XENVBD_ENABLED:            return "ENABLED";
    default:                        return "UNKNOWN";
    }
}
//=============================================================================
#define FRONTEND_POOL_TAG            'tnFX'
__checkReturn
__drv_allocatesMem(mem)
__bcount(Size)
static FORCEINLINE PVOID
#pragma warning(suppress: 28195)
__FrontendAlloc(
    __in  ULONG Size
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Size, FRONTEND_POOL_TAG);
}

static FORCEINLINE VOID
#pragma warning(suppress: 28197)
__FrontendFree(
    __in __drv_freesMem(mem) PVOID Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, FRONTEND_POOL_TAG);
}

//=============================================================================
// Accessors
VOID
FrontendRemoveFeature(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  UCHAR                   BlkifOperation
    )
{
    switch (BlkifOperation) {
    case BLKIF_OP_FLUSH_DISKCACHE:
        Verbose("FLUSH_DISKCACHE\n");
        Frontend->DiskInfo.FlushCache = FALSE;
        break;
    case BLKIF_OP_WRITE_BARRIER:    
        Verbose("WRITE_BARRIER\n");
        Frontend->DiskInfo.Barrier = FALSE;
        break;
    case BLKIF_OP_DISCARD:
        Verbose("DISCARD\n");
        Frontend->DiskInfo.Discard = FALSE;
        break;
    case BLKIF_OP_INDIRECT:
        Verbose("INDIRECT\n");
        Frontend->Features.Indirect = 0;
        break;
    default:
        break;
    }
}
PXENVBD_CAPS
FrontendGetCaps(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return &Frontend->Caps;
}
PXENVBD_FEATURES
FrontendGetFeatures(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return &Frontend->Features;
}
PXENVBD_DISKINFO
FrontendGetDiskInfo(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return &Frontend->DiskInfo;
}
ULONG
FrontendGetTargetId(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return Frontend->TargetId;
}
PVOID
FrontendGetInquiry(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return Frontend->Inquiry;
}
PXENVBD_TARGET
FrontendGetTarget(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return Frontend->Target;
}
PXENVBD_BLOCKRING
FrontendGetBlockRing(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return Frontend->BlockRing;
}
PXENVBD_NOTIFIER
FrontendGetNotifier(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return Frontend->Notifier;
}
PXENVBD_GRANTER
FrontendGetGranter(
    __in  PXENVBD_FRONTEND      Frontend
    )
{
    return Frontend->Granter;
}

NTSTATUS
FrontendStoreWriteFrontend(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Name,
    __in  PCHAR                 Value
    )
{
    return XENBUS_STORE(Printf,
                        Frontend->Store,
                        NULL,
                        Frontend->FrontendPath,
                        Name,
                        Value);
}
NTSTATUS
FrontendStoreReadBackend(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Name,
    __out PCHAR*                Value
    )
{
    NTSTATUS    Status;

    Status = STATUS_INVALID_PARAMETER;
    if (Frontend->Store == NULL) 
        goto fail1;

    if (Frontend->BackendPath == NULL)
        goto fail2;

    Status = XENBUS_STORE(Read,
                          Frontend->Store,
                          NULL,
                          Frontend->BackendPath,
                          Name,
                          Value);
    if (!NT_SUCCESS(Status))
        goto fail3;

    return STATUS_SUCCESS;

fail3:
fail2:
fail1:
    return Status;
}
VOID
FrontendStoreFree(
    __in  PXENVBD_FRONTEND      Frontend,
    __in  PCHAR                 Value
    )
{
    XENBUS_STORE(Free,
                 Frontend->Store,
                 Value);
}
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FrontendWriteUsage(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;

    Status = XENBUS_STORE(Printf,
                          Frontend->Store,
                          NULL,
                          Frontend->TargetPath, 
                          "paging",
                          "%u",
                          Frontend->Caps.Paging);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = XENBUS_STORE(Printf,
                          Frontend->Store,
                          NULL,
                          Frontend->TargetPath, 
                          "hibernation",
                          "%u",
                          Frontend->Caps.Hibernation);
    if (!NT_SUCCESS(Status))
        goto out;

    Status = XENBUS_STORE(Printf,
                          Frontend->Store,
                          NULL,
                          Frontend->TargetPath, 
                          "dump",
                          "%u",
                          Frontend->Caps.DumpFile);
    if (!NT_SUCCESS(Status))
        goto out;

    Verbose("Target[%d] : %s %s %s\n", Frontend->TargetId,
            Frontend->Caps.DumpFile ? "DUMP" : "NOT_DUMP", 
            Frontend->Caps.Hibernation ? "HIBER" : "NOT_HIBER",
            Frontend->Caps.Paging ? "PAGE" : "NOT_PAGE");

out:
    return Status;
}

//=============================================================================
__drv_requiresIRQL(DISPATCH_LEVEL)
VOID
FrontendNotifyResponses(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    BlockRingPoll(Frontend->BlockRing);
    TargetSubmitRequests(Frontend->Target);
}

//=============================================================================
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
__UpdateBackendPath(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    PCHAR       Value;
    ULONG       Length;

    Status = XENBUS_STORE(Read,
                          Frontend->Store,
                          NULL,
                          Frontend->FrontendPath, 
                          "backend-id",
                          &Value);
    if (NT_SUCCESS(Status)) {
        Frontend->BackendId = (USHORT)strtoul(Value, NULL, 10);
        XENBUS_STORE(Free,
                     Frontend->Store,
                     Value);
    } else {
        Frontend->BackendId = 0;
    }

    Status = XENBUS_STORE(Read,
                          Frontend->Store,
                          NULL,
                          Frontend->FrontendPath,
                          "backend",
                          &Value);
    if (NT_SUCCESS(Status)) {
        if (Frontend->BackendPath) {
            Trace("<< %s\n", Frontend->BackendPath);
            __FrontendFree(Frontend->BackendPath);
            Frontend->BackendPath = NULL;
        }

        Length = (ULONG)strlen(Value);
        Frontend->BackendPath = (PCHAR)__FrontendAlloc(Length + 1);

        if (Frontend->BackendPath) {
            RtlCopyMemory(Frontend->BackendPath, Value, Length);
            Trace(">> %s\n", Frontend->BackendPath);
        }

        XENBUS_STORE(Free,
                     Frontend->Store,
                     Value);
    } else {
        Warning("Failed to read \'backend\' from \'%s\' (%08x)\n", 
                    Frontend->FrontendPath, Status);
    }

    return Status;
}
__drv_maxIRQL(DISPATCH_LEVEL)
static NTSTATUS
__ReadState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in_opt PXENBUS_STORE_TRANSACTION Transaction,
    __in  PCHAR                   Path,
    __out XenbusState*            State
    )
{
    NTSTATUS        Status;
    PCHAR           Buffer;

    Status = XENBUS_STORE(Read,
                          Frontend->Store,
                          Transaction,
                          Path, 
                          "state",
                          &Buffer);
    if (!NT_SUCCESS(Status))
        goto fail;

    *State = (XenbusState)strtoul(Buffer, NULL, 10);
    XENBUS_STORE(Free,
                 Frontend->Store,
                 Buffer);

    return STATUS_SUCCESS;

fail:
    *State = XenbusStateUnknown;
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
__WaitState(
    __in  PXENVBD_FRONTEND        Frontend,
    __inout  XenbusState*         State
    )
{
    NTSTATUS        Status;
    XenbusState     OldState = *State;
    PXENBUS_STORE_WATCH Watch;
    KEVENT          Event;
    LARGE_INTEGER   Timeout;

    LARGE_INTEGER   StartTime;
    LARGE_INTEGER   CurrentTime;
    ULONG           Count = 0;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Timeout.QuadPart = 0;

    ASSERT3P(Frontend->BackendPath, !=, NULL);
    Status = XENBUS_STORE(WatchAdd,
                          Frontend->Store,
                          Frontend->BackendPath,
                          "state", 
                          &Event,
                          &Watch);
    if (!NT_SUCCESS(Status))
        goto fail1;

    KeQuerySystemTime(&StartTime);

    while (OldState == *State) {
        // check event and spin or read
#pragma prefast(suppress:28121)
        if (KeWaitForSingleObject(&Event, Executive, KernelMode, 
                                    FALSE, &Timeout) == STATUS_TIMEOUT) {
            XENBUS_STORE(Poll,
                         Frontend->Store);

            KeQuerySystemTime(&CurrentTime);
            if ((CurrentTime.QuadPart - StartTime.QuadPart) > 10000) {
                Warning("Target[%d] : %d Waited for %d ms\n", Frontend->TargetId, 
                            Count, (ULONG)((CurrentTime.QuadPart - StartTime.QuadPart) / 10));
                StartTime.QuadPart = CurrentTime.QuadPart;
                ++Count;
            }

            continue;
        }

        Status = __ReadState(Frontend, NULL, Frontend->BackendPath, State);
        if (!NT_SUCCESS(Status))
            goto fail2;
    }

    XENBUS_STORE(WatchRemove,
                 Frontend->Store,
                 Watch);

    Trace("Target[%d] : BACKEND_STATE  -> %s\n",
          Frontend->TargetId,
          XenbusStateName(*State));

    return STATUS_SUCCESS;

fail2:
    Error("Fail2\n");

    XENBUS_STORE(WatchRemove,
                 Frontend->Store,
                 Watch);
fail1:
    Error("Fail1 (%08x)\n", Status);

    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
___SetState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  XenbusState             State
    )
{
    NTSTATUS    Status;

    Status = XENBUS_STORE(Printf,
                          Frontend->Store,
                          NULL,
                          Frontend->FrontendPath,
                          "state",
                          "%u",
                          State);
    if (NT_SUCCESS(Status)) {
        Trace("Target[%d] : FRONTEND_STATE -> %s\n",
              Frontend->TargetId,
              XenbusStateName(State));
    } else {
        Error("Fail (%08x)\n", Status);
    }

    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
__CheckBackendForEject(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    XenbusState     FrontendState;
    XenbusState     BackendState;
    BOOLEAN         Online;
    ULONG           Attempt;
    NTSTATUS        Status;

    if (Frontend->Store == NULL)
        return;
    if (Frontend->FrontendPath == NULL)
        return;
    if (Frontend->BackendPath == NULL)
        return;

    // get FrontendState, BackendState and Online
    Attempt         = 0;
    FrontendState   = XenbusStateUnknown;
    BackendState    = XenbusStateUnknown;
    Online          = TRUE;
    for (;;) {
        PXENBUS_STORE_TRANSACTION   Transaction;
        PCHAR                       Buffer;

        Status = XENBUS_STORE(TransactionStart,
                              Frontend->Store,
                              &Transaction);
        if (!NT_SUCCESS(Status))
            break;

        Status = __ReadState(Frontend,
                             Transaction,
                             Frontend->FrontendPath,
                             &FrontendState);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = __ReadState(Frontend,
                             Transaction,
                             Frontend->BackendPath,
                             &BackendState);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = XENBUS_STORE(Read,
                              Frontend->Store,
                              Transaction,
                              Frontend->BackendPath, 
                              "online",
                              &Buffer);
        if (!NT_SUCCESS(Status))
            goto abort;

        Online = (BOOLEAN)strtol(Buffer, NULL, 2);
        XENBUS_STORE(Free,
                     Frontend->Store,
                     Buffer);

        Status = XENBUS_STORE(TransactionEnd,
                              Frontend->Store,
                              Transaction,
                              TRUE);
        if (Status != STATUS_RETRY || ++Attempt > 10)
            break;

        continue;

abort:
        (VOID) XENBUS_STORE(TransactionEnd,
                            Frontend->Store,
                            Transaction,
                            FALSE);
        break;
    }
    if (!NT_SUCCESS(Status))
        return;

    // check to see eject required
    if (!Online && BackendState == XenbusStateClosing) {
        Trace("Target[%d] : BackendState(%s) FrontendState(%s)\n", 
                Frontend->TargetId, XenbusStateName(BackendState), XenbusStateName(FrontendState));

        TargetIssueDeviceEject(Frontend->Target, XenbusStateName(BackendState));
    }    
}

static FORCEINLINE BOOLEAN
FrontendReadFeature(
    IN  PXENVBD_FRONTEND            Frontend,
    IN  PCHAR                       Name,
    IN  PBOOLEAN                    Value
    )
{
    NTSTATUS        status;
    PCHAR           Buffer;
    ULONG           Override;
    BOOLEAN         Old = *Value;

    status = XENBUS_STORE(Read,
                          Frontend->Store,
                          NULL,
                          Frontend->BackendPath,
                          Name,
                          &Buffer);
    if (!NT_SUCCESS(status))
        return FALSE;   // no value, unchanged

    *Value = !!(strtoul(Buffer, NULL, 10));
    XENBUS_STORE(Free,
                    Frontend->Store,
                    Buffer);

    // check registry for disable-override
    status = RegistryQueryDwordValue(DriverGetParametersKey(),
                                    Name,
                                    &Override);
    if (NT_SUCCESS(status)) {
        if (Override == 0)
            *Value = FALSE;
    }

    return Old != *Value;
}

static FORCEINLINE BOOLEAN
FrontendReadValue32(
    IN  PXENVBD_FRONTEND            Frontend,
    IN  PCHAR                       Name,
    IN  BOOLEAN                     AllowOverride,
    IN  PULONG                      Value
    )
{
    NTSTATUS        status;
    PCHAR           Buffer;
    ULONG           Override;
    ULONG           Old = *Value;

    status = XENBUS_STORE(Read,
                          Frontend->Store,
                          NULL,
                          Frontend->BackendPath,
                          Name,
                          &Buffer);
    if (!NT_SUCCESS(status))
        return FALSE;   // no value, unchanged

    *Value = strtoul(Buffer, NULL, 10);
    XENBUS_STORE(Free,
                    Frontend->Store,
                    Buffer);

    // check registry for disable-override
    if (AllowOverride) {
        status = RegistryQueryDwordValue(DriverGetParametersKey(),
                                        Name,
                                        &Override);
        if (NT_SUCCESS(status)) {
            *Value = Override;
        }
    }

    return Old != *Value;
}

static FORCEINLINE BOOLEAN
FrontendReadValue64(
    IN  PXENVBD_FRONTEND            Frontend,
    IN  PCHAR                       Name,
    IN OUT PULONG64                 Value
    )
{
    NTSTATUS        status;
    PCHAR           Buffer;
    ULONG64         Old = *Value;

    status = XENBUS_STORE(Read,
                          Frontend->Store,
                          NULL,
                          Frontend->BackendPath,
                          Name,
                          &Buffer);
    if (!NT_SUCCESS(status))
        return FALSE;   // no value, unchanged

    *Value = _strtoui64(Buffer, NULL, 10);
    XENBUS_STORE(Free,
                    Frontend->Store,
                    Buffer);

    return Old != *Value;
}

static FORCEINLINE ULONG
__Size(
    __in  PXENVBD_DISKINFO          Info
    )
{
    ULONG64 MBytes = (Info->SectorSize * Info->SectorCount) >> 20; // / (1024 * 1024); 
    if (MBytes < 10240)
        return (ULONG)MBytes;
    return (ULONG)(MBytes >> 10); // / 1024
}
static FORCEINLINE PCHAR
__Units(
    __in  PXENVBD_DISKINFO          Info
    )
{
    ULONG64 MBytes = (Info->SectorSize * Info->SectorCount) >> 20; // / (1024 * 1024); 
    if (MBytes < 10240)
        return "MB";
    return "GB";
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
__ReadDiskInfo(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    BOOLEAN Changed = FALSE;

    Changed |= FrontendReadValue32(Frontend,
                                  "info",
                                  FALSE,
                                  &Frontend->DiskInfo.DiskInfo);
    Changed |= FrontendReadValue32(Frontend,
                                  "sector-size",
                                  FALSE,
                                  &Frontend->DiskInfo.SectorSize);
    Changed |= FrontendReadValue32(Frontend,
                                  "physical-sector-size",
                                  FALSE,
                                  &Frontend->DiskInfo.PhysSectorSize);
    Changed |= FrontendReadValue64(Frontend,
                                  "sectors",
                                  &Frontend->DiskInfo.SectorCount);

    if (!Changed)
        return;

    Frontend->Caps.SurpriseRemovable = !!(Frontend->DiskInfo.DiskInfo & VDISK_REMOVABLE);
    if (Frontend->DiskInfo.DiskInfo & VDISK_READONLY) {
        Warning("Target[%d] : DiskInfo contains VDISK_READONLY flag!\n", Frontend->TargetId);
    }
    if (Frontend->DiskInfo.DiskInfo & VDISK_CDROM) {
        Warning("Target[%d] : DiskInfo contains VDISK_CDROM flag!\n", Frontend->TargetId);
    }
    if (Frontend->DiskInfo.SectorSize == 0) {
        Error("Target[%d] : Invalid SectorSize!\n", Frontend->TargetId);
    }
    if (Frontend->DiskInfo.SectorCount == 0) {
        Error("Target[%d] : Invalid SectorCount!\n", Frontend->TargetId);
    }
    if (Frontend->DiskInfo.PhysSectorSize == 0) {
        Frontend->DiskInfo.PhysSectorSize = Frontend->DiskInfo.SectorSize;
    }

    // dump actual values
    Verbose("Target[%d] : %lld sectors of %d bytes (%d)\n", Frontend->TargetId,
                Frontend->DiskInfo.SectorCount, Frontend->DiskInfo.SectorSize,
                Frontend->DiskInfo.PhysSectorSize);
    Verbose("Target[%d] : %d %s (%08x) %s\n", Frontend->TargetId,
                __Size(&Frontend->DiskInfo), __Units(&Frontend->DiskInfo),
                Frontend->DiskInfo.DiskInfo,
                Frontend->Caps.SurpriseRemovable ? "SURPRISE_REMOVABLE" : "");
}

static FORCEINLINE VOID
FrontendReadFeatures(
    IN  PXENVBD_FRONTEND            Frontend
    )
{
    BOOLEAN Changed = FALSE;

    Changed |= FrontendReadFeature(Frontend,
                                   "removable",
                                   &Frontend->Caps.Removable);
    Changed |= FrontendReadValue32(Frontend,
                                   "feature-max-indirect-segments",
                                   TRUE,
                                   &Frontend->Features.Indirect);
    Changed |= FrontendReadFeature(Frontend,
                                   "feature-persistent",
                                   &Frontend->Features.Persistent);

    if (!Changed)
        return;

    Verbose("Target[%d] : Features: %s%s%s\n",
                Frontend->TargetId,
                Frontend->Features.Persistent ? "PERSISTENT " : "",
                Frontend->Features.Indirect ? "INDIRECT " : "",
                Frontend->Caps.Removable ? "REMOVABLE" : "");
    if (Frontend->Features.Indirect) {
        Verbose("Target[%d] : INDIRECT %x\n",
                    Frontend->TargetId,
                    Frontend->Features.Indirect);
    }
}

static FORCEINLINE VOID
FrontendReadDiskInfo(
    IN  PXENVBD_FRONTEND            Frontend
    )
{
    BOOLEAN Changed = FALSE;
    BOOLEAN Discard;
    BOOLEAN DiscardFeature = FALSE;
    BOOLEAN DiscardEnable = TRUE;

    Changed |= FrontendReadFeature(Frontend,
                                   "feature-barrier",
                                   &Frontend->DiskInfo.Barrier);
    Changed |= FrontendReadFeature(Frontend,
                                   "feature-flush-cache",
                                   &Frontend->DiskInfo.FlushCache);

    // discard related
    FrontendReadFeature(Frontend,
                        "feature-discard",
                        &DiscardFeature);
    FrontendReadFeature(Frontend,
                        "discard-enable",
                        &DiscardEnable);
    Discard = DiscardFeature && DiscardEnable;
    Changed |= (Discard != Frontend->DiskInfo.Discard);
    Frontend->DiskInfo.Discard = Discard;
    Changed |= FrontendReadFeature(Frontend,
                                   "discard-secure",
                                   &Frontend->DiskInfo.DiscardSecure);
    Changed |= FrontendReadValue32(Frontend,
                                   "discard-alignment",
                                   TRUE,
                                   &Frontend->DiskInfo.DiscardAlignment);
    Changed |= FrontendReadValue32(Frontend,
                                   "discard-granularity",
                                   TRUE,
                                   &Frontend->DiskInfo.DiscardGranularity);

    if (!Changed)
        return;

    Verbose("Target[%d] : Features: %s%s%s\n",
                Frontend->TargetId,
                Frontend->DiskInfo.Barrier ? "BARRIER " : "",
                Frontend->DiskInfo.FlushCache ?  "FLUSH " : "",
                Frontend->DiskInfo.Discard ? "DISCARD " : "");
    if (Frontend->DiskInfo.Discard) {
        Verbose("Target[%d] : DISCARD %s%x/%x\n",
                    Frontend->TargetId,
                    Frontend->DiskInfo.DiscardSecure ? "SECURE " : "",
                    Frontend->DiskInfo.DiscardAlignment,
                    Frontend->DiskInfo.DiscardGranularity);
    }
}

//=============================================================================
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
FrontendClose(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XenbusState     BackendState;

    // unwatch backend (null check for initial close operation)
    if (Frontend->BackendWatch)
        XENBUS_STORE(WatchRemove,
                     Frontend->Store,
                     Frontend->BackendWatch);
    Frontend->BackendWatch = NULL;
    
    Frontend->BackendId = DOMID_INVALID;

    // get/update backend path
    Status = __UpdateBackendPath(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // Backend : -> !INITIALIZING
    BackendState = XenbusStateUnknown;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail2;
    } while (BackendState == XenbusStateInitialising);

    // Frontend: -> CLOSING 
    // Backend : -> CLOSING 
    while (BackendState != XenbusStateClosing &&
           BackendState != XenbusStateClosed) {
        Status = ___SetState(Frontend, XenbusStateClosing);
        if (!NT_SUCCESS(Status))
            goto fail3;
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail4;
    }

    // Frontend: -> CLOSED
    // Backend : -> CLOSED
    while (BackendState != XenbusStateClosed) {
        Status = ___SetState(Frontend, XenbusStateClosed);
        if (!NT_SUCCESS(Status))
            goto fail5;
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail6;
    }

    return STATUS_SUCCESS;

fail6:
fail5:
fail4:
fail3:
fail2:
fail1:
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
FrontendPrepare(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XenbusState     BackendState;

    // get/update backend path
    Status = __UpdateBackendPath(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // watch backend (4 paths needed)
    Status = XENBUS_STORE(WatchAdd,
                          Frontend->Store,
                          NULL,
                          Frontend->BackendPath,
                          ThreadGetEvent(Frontend->BackendThread),
                          &Frontend->BackendWatch);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // write targetpath
    Status = FrontendWriteUsage(Frontend);
    if (!NT_SUCCESS(Status))
        goto fail3;

    Status = XENBUS_STORE(Printf,
                          Frontend->Store,
                          NULL,
                          Frontend->TargetPath, 
                          "frontend",
                          "%s",
                          Frontend->FrontendPath);
    if (!NT_SUCCESS(Status))
        goto fail4;

    Status = XENBUS_STORE(Printf,
                          Frontend->Store,
                          NULL,
                          Frontend->TargetPath, 
                          "device",
                          "%u",
                          Frontend->DeviceId);
    if (!NT_SUCCESS(Status))
        goto fail5;

    // Frontend: -> INITIALIZING
    Status = ___SetState(Frontend, XenbusStateInitialising);
    if (!NT_SUCCESS(Status))
        goto fail6;

    // Backend : -> INITWAIT
    BackendState = XenbusStateUnknown;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail7;
    } while (BackendState == XenbusStateClosed || 
             BackendState == XenbusStateInitialising);
    Status = STATUS_UNSUCCESSFUL;
    if (BackendState != XenbusStateInitWait)
        goto fail8;

    // read inquiry data
    if (Frontend->Inquiry == NULL)
        PdoReadInquiryData(Frontend, &Frontend->Inquiry);
    PdoUpdateInquiryData(Frontend, Frontend->Inquiry);

    // read features and caps (removable, ring-order, ...)
    Verbose("Target[%d] : BackendId %d (%s)\n",
            Frontend->TargetId,
            Frontend->BackendId,
            Frontend->BackendPath);

    FrontendReadFeatures(Frontend);
    
    return STATUS_SUCCESS;

fail8:
    Error("Fail8\n");
fail7:
    Error("Fail7\n");
fail6:
    Error("Fail6\n");
fail5:
    Error("Fail5\n");
fail4:
    Error("Fail4\n");
fail3:
    Error("Fail3\n");
    (VOID) XENBUS_STORE(WatchRemove,
                        Frontend->Store,
                        Frontend->BackendWatch);
    Frontend->BackendWatch = NULL;
fail2:
    Error("Fail2\n");
fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static NTSTATUS
FrontendConnect(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS        Status;
    XenbusState     BackendState;

    // Alloc Ring, Create Evtchn, Gnttab map
    Status = GranterConnect(Frontend->Granter, Frontend->BackendId);
    if (!NT_SUCCESS(Status))
        goto fail1;

    Status = BlockRingConnect(Frontend->BlockRing);
    if (!NT_SUCCESS(Status))
        goto fail2;

    Status = NotifierConnect(Frontend->Notifier, Frontend->BackendId);
    if (!NT_SUCCESS(Status))
        goto fail3;

    // write evtchn/gnttab details in xenstore
    for (;;) {
        PXENBUS_STORE_TRANSACTION   Transaction;
        
        Status = XENBUS_STORE(TransactionStart,
                              Frontend->Store,
                              &Transaction);
        if (!NT_SUCCESS(Status))
            break;

        Status = NotifierStoreWrite(Frontend->Notifier, Transaction, Frontend->FrontendPath);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = BlockRingStoreWrite(Frontend->BlockRing, Transaction, Frontend->FrontendPath);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = GranterStoreWrite(Frontend->Granter, Transaction, Frontend->FrontendPath);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = XENBUS_STORE(Printf,
                              Frontend->Store,
                              Transaction,
                              Frontend->FrontendPath,
                              "target-id",
                              "%u",
                              Frontend->TargetId);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = XENBUS_STORE(Printf,
                              Frontend->Store,
                              Transaction,
                              Frontend->FrontendPath,
                              "feature-surprise-remove",
                              "%u",
                              1);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = XENBUS_STORE(Printf,
                              Frontend->Store,
                              Transaction,
                              Frontend->FrontendPath,
                              "feature-online-resize",
                              "%u",
                              1);
        if (!NT_SUCCESS(Status))
            goto abort;

        Status = XENBUS_STORE(TransactionEnd,
                              Frontend->Store,
                              Transaction,
                              TRUE);
        if (Status == STATUS_RETRY)
            continue;

        break;

abort:
        (VOID) XENBUS_STORE(TransactionEnd,
                            Frontend->Store,
                            Transaction,
                            FALSE);
        break;
    }
    if (!NT_SUCCESS(Status))
        goto fail4;

    // Frontend: -> INITIALIZED
    Status = ___SetState(Frontend, XenbusStateInitialised);
    if (!NT_SUCCESS(Status))
        goto fail5;

    // Backend : -> CONNECTED
    BackendState = XenbusStateUnknown;
    do {
        Status = __WaitState(Frontend, &BackendState);
        if (!NT_SUCCESS(Status))
            goto fail6;
    } while (BackendState == XenbusStateInitWait ||
             BackendState == XenbusStateInitialising ||
             BackendState == XenbusStateInitialised);
    Status = STATUS_UNSUCCESSFUL;
    if (BackendState != XenbusStateConnected)
        goto fail7;

    // read disk info
    __ReadDiskInfo(Frontend);
    FrontendReadDiskInfo(Frontend);

    // blkback doesnt write features before InitWait, blkback writes features before Connected!
    FrontendReadFeatures(Frontend);

    // Frontend: -> CONNECTED
    Status = ___SetState(Frontend, XenbusStateConnected);
    if (!NT_SUCCESS(Status))
        goto fail8;

    return STATUS_SUCCESS;

fail8:
    Error("Fail8\n");
fail7:
    Error("Fail7\n");
fail6:
    Error("Fail6\n");
fail5:
    Error("Fail5\n");
fail4:
    Error("Fail4\n");
    NotifierDisconnect(Frontend->Notifier);
fail3:
    Error("Fail3\n");
    BlockRingDisconnect(Frontend->BlockRing);
fail2:
    Error("Fail2\n");
    GranterDisconnect(Frontend->Granter);
fail1:
    Error("Fail1 (%08x)\n", Status);
    return Status;
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
FrontendDisconnect(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NotifierDisconnect(Frontend->Notifier);
    BlockRingDisconnect(Frontend->BlockRing);
    GranterDisconnect(Frontend->Granter);
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
FrontendEnable(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    Frontend->Caps.Connected = TRUE;
    KeMemoryBarrier();

    GranterEnable(Frontend->Granter);
    BlockRingEnable(Frontend->BlockRing);
    NotifierEnable(Frontend->Notifier);
}
__drv_requiresIRQL(DISPATCH_LEVEL)
static FORCEINLINE VOID
FrontendDisable(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    Frontend->Caps.Connected = FALSE;

    NotifierDisable(Frontend->Notifier);
    BlockRingDisable(Frontend->BlockRing);
    GranterDisable(Frontend->Granter);
}

//=============================================================================
// Init/Term
static DECLSPEC_NOINLINE NTSTATUS
__FrontendSetState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  XENVBD_STATE            State
    )
{
    NTSTATUS    Status;
    const ULONG TargetId = Frontend->TargetId;
    BOOLEAN     Failed = FALSE;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());
    Verbose("Target[%d] : %s ----> %s\n", 
                TargetId, 
                __XenvbdStateName(Frontend->State), 
                __XenvbdStateName(State));
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    
    while (!Failed && Frontend->State != State) {
        switch (Frontend->State) {
        case XENVBD_INITIALIZED:
            switch (State) {
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                Status = FrontendClose(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_CLOSED;
                } else {
                    Failed = TRUE;
                }
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        case XENVBD_CLOSED:
            switch (State) {
            case XENVBD_INITIALIZED:
                // ONLY Closed->Initialized is valid, which can occur with a very early resume from suspend
                // i.e. VM was suspended before the Initianized->Closed transition, and each resume needs
                //      the Close transition to properly close the frontend and backend devices.
                Frontend->State = XENVBD_INITIALIZED;
                break;
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                Status = FrontendPrepare(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_PREPARED;
                } else {
                    Status = FrontendClose(Frontend);
                    if (NT_SUCCESS(Status))
                        Frontend->State = XENVBD_CLOSED;
                    else
                        Frontend->State = XENVBD_STATE_INVALID;
                    Failed = TRUE;
                }
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        case XENVBD_PREPARED:
            switch (State) {
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                Status = FrontendConnect(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_CONNECTED;
                } else {
                    Status = FrontendClose(Frontend);
                    if (NT_SUCCESS(Status))
                        Frontend->State = XENVBD_CLOSED;
                    else
                        Frontend->State = XENVBD_STATE_INVALID;
                    Failed = TRUE;
                }
                break;
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
                Status = FrontendClose(Frontend);
                if (NT_SUCCESS(Status)) {
                    Frontend->State = XENVBD_CLOSED;
                } else {
                    Frontend->State = XENVBD_STATE_INVALID;
                    Failed = TRUE;
                }
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;
            
        case XENVBD_CONNECTED:
            switch (State) {
            case XENVBD_ENABLED:
                FrontendEnable(Frontend);
                Frontend->State = XENVBD_ENABLED;
                break;
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
                Status = FrontendClose(Frontend);
                Frontend->State = XENVBD_CLOSING;
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        case XENVBD_CLOSING:
            switch (State) {
            case XENVBD_INITIALIZED:
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                FrontendDisconnect(Frontend);
                Frontend->State = XENVBD_CLOSED;
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        case XENVBD_ENABLED:
            switch (State) {
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
                FrontendDisable(Frontend);
                Frontend->State = XENVBD_CONNECTED;
                break;
            default:
                Failed = TRUE;
                break;
            }
            break;

        default:
            Failed = TRUE;
            break;
        }
        Verbose("Target[%d] : in state %s\n", TargetId, __XenvbdStateName(Frontend->State));
    }
    Trace("Target[%d] @ (%d) <===== (%s)\n", TargetId, KeGetCurrentIrql(), Failed ? "FAILED" : "SUCCEEDED");
    return Failed ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static DECLSPEC_NOINLINE VOID
FrontendSuspendLateCallback(
    __in  PVOID                   Argument
    )
{
    NTSTATUS            Status;
    XENVBD_STATE        State;
    PXENVBD_FRONTEND    Frontend = (PXENVBD_FRONTEND)Argument;

    Verbose("Target[%d] : ===> from %s\n", Frontend->TargetId, __XenvbdStateName(Frontend->State));
    State = Frontend->State;

    TargetPreResume(Frontend->Target);

    // dont acquire state lock - called at DISPATCH on 1 vCPU with interrupts enabled
    Status = __FrontendSetState(Frontend, XENVBD_CLOSED);
    if (!NT_SUCCESS(Status)) {
        Error("Target[%d] : SetState CLOSED (%08x)\n", Frontend->TargetId, Status);
        ASSERT(FALSE);
    }

    // dont acquire state lock - called at DISPATCH on 1 vCPU with interrupts enabled
    Status = __FrontendSetState(Frontend, State);
    if (!NT_SUCCESS(Status)) {
        Error("Target[%d] : SetState %s (%08x)\n", Frontend->TargetId, __XenvbdStateName(State), Status);
        ASSERT(FALSE);
    }

    TargetPostResume(Frontend->Target);
    NotifierTrigger(Frontend->Notifier);

    Verbose("Target[%d] : <=== restored %s\n", Frontend->TargetId, __XenvbdStateName(Frontend->State));
}

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
NTSTATUS
FrontendD3ToD0(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    NTSTATUS    Status;
    KIRQL       Irql;

    KeAcquireSpinLock(&Frontend->StateLock, &Irql);

    // acquire interfaces
    Frontend->Store   = AdapterAcquireStore(TargetGetAdapter(Frontend->Target));

    Status = STATUS_UNSUCCESSFUL;
    if (Frontend->Store == NULL)
        goto fail1;

    Frontend->Suspend = AdapterAcquireSuspend(TargetGetAdapter(Frontend->Target));

    Status = STATUS_UNSUCCESSFUL;
    if (Frontend->Suspend == NULL)
        goto fail2;

    // register suspend callback
    ASSERT3P(Frontend->SuspendLateCallback, ==, NULL);
    Status = XENBUS_SUSPEND(Register,
                            Frontend->Suspend,
                            SUSPEND_CALLBACK_LATE,
                            FrontendSuspendLateCallback,
                            Frontend,
                            &Frontend->SuspendLateCallback);
    if (!NT_SUCCESS(Status))
        goto fail3;

    // update state
    Frontend->Active = TRUE;

    KeReleaseSpinLock(&Frontend->StateLock, Irql);
    return STATUS_SUCCESS;

fail3:
    Error("Fail3\n");

    XENBUS_SUSPEND(Release, Frontend->Suspend);
    Frontend->Suspend = NULL;

fail2:
    Error("Fail2\n");

    XENBUS_STORE(Release, Frontend->Store);
    Frontend->Store = NULL;

fail1:
    Error("Fail1 (%08x)\n", Status);

    KeReleaseSpinLock(&Frontend->StateLock, Irql);
    return Status;
}

__drv_maxIRQL(DISPATCH_LEVEL)
VOID
FrontendD0ToD3(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    KIRQL       Irql;

    KeAcquireSpinLock(&Frontend->StateLock, &Irql);

    // update state
    Frontend->Active = FALSE;

    // deregister suspend callback
    if (Frontend->SuspendLateCallback != NULL) {
        XENBUS_SUSPEND(Deregister,
                       Frontend->Suspend,
                       Frontend->SuspendLateCallback);
        Frontend->SuspendLateCallback = NULL;
    }
    // Free backend path before dropping store interface
    if (Frontend->BackendPath) {
        __FrontendFree(Frontend->BackendPath);
        Frontend->BackendPath = NULL;
    }

    // release interfaces
    XENBUS_SUSPEND(Release, Frontend->Suspend);
    Frontend->Suspend = NULL;
    
    XENBUS_STORE(Release, Frontend->Store);
    Frontend->Store = NULL;

    KeReleaseSpinLock(&Frontend->StateLock, Irql);
}

__checkReturn
NTSTATUS
FrontendSetState(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  XENVBD_STATE            State
    )
{
    NTSTATUS    Status;
    KIRQL       Irql;

    KeAcquireSpinLock(&Frontend->StateLock, &Irql);

    Status = __FrontendSetState(Frontend, State);

    KeReleaseSpinLock(&Frontend->StateLock, Irql);
    return Status;
}

__checkReturn
static DECLSPEC_NOINLINE NTSTATUS
FrontendBackend(
    __in PXENVBD_THREAD              Thread,
    __in PVOID                       Context
    )
{
    PXENVBD_FRONTEND                Frontend = Context;

    for (;;) {
        KIRQL       Irql;

        if (!ThreadWait(Thread))
            break;

        KeAcquireSpinLock(&Frontend->StateLock, &Irql);
        // Only attempt this if Active, Active is set/cleared on D3->D0/D0->D3
        if (Frontend->Active) {
            __ReadDiskInfo(Frontend);
            __CheckBackendForEject(Frontend);
        }
        KeReleaseSpinLock(&Frontend->StateLock, Irql);
    }

    return STATUS_SUCCESS;

}

__checkReturn
NTSTATUS
FrontendCreate(
    __in  PXENVBD_TARGET             Target,
    __in  PCHAR                   DeviceId, 
    __in  ULONG                   TargetId, 
    __out PXENVBD_FRONTEND*       _Frontend
    )
{
    NTSTATUS            Status;
    PXENVBD_FRONTEND    Frontend;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());

    Frontend = __FrontendAlloc(sizeof(XENVBD_FRONTEND));

    Status = STATUS_NO_MEMORY;
    if (Frontend == NULL)
        goto fail1;

    // populate members
    Frontend->Target = Target;
    Frontend->TargetId = TargetId;
    Frontend->DeviceId = strtoul(DeviceId, NULL, 10);
    Frontend->State = XENVBD_INITIALIZED;
    Frontend->DiskInfo.SectorSize = 512; // default sector size
    Frontend->BackendId = DOMID_INVALID;
    
    Status = STATUS_INSUFFICIENT_RESOURCES;
    Frontend->FrontendPath = DriverFormat("device/%s/%s", AdapterEnum(TargetGetAdapter(Target)), DeviceId);
    if (Frontend->FrontendPath == NULL) 
        goto fail2;

    Frontend->TargetPath = DriverFormat("data/scsi/target/%d", TargetId);
    if (Frontend->TargetPath == NULL)
        goto fail3;

    Status = NotifierCreate(Frontend, &Frontend->Notifier);
    if (!NT_SUCCESS(Status))
        goto fail4;

    Status = BlockRingCreate(Frontend, Frontend->DeviceId, &Frontend->BlockRing);
    if (!NT_SUCCESS(Status))
        goto fail5;

    Status = GranterCreate(Frontend, &Frontend->Granter);
    if (!NT_SUCCESS(Status))
        goto fail6;

    Status = ThreadCreate(FrontendBackend, Frontend, &Frontend->BackendThread);
    if (!NT_SUCCESS(Status))
        goto fail7;

    // kernel objects
    KeInitializeSpinLock(&Frontend->StateLock);
    
    Trace("Target[%d] @ (%d) <===== (STATUS_SUCCESS)\n", Frontend->TargetId, KeGetCurrentIrql());
    *_Frontend = Frontend;
    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");
    GranterDestroy(Frontend->Granter);
    Frontend->Granter = NULL;
fail6:
    Error("fail6\n");
    BlockRingDestroy(Frontend->BlockRing);
    Frontend->BlockRing = NULL;
fail5:
    Error("fail5\n");
    NotifierDestroy(Frontend->Notifier);
    Frontend->Notifier = NULL;
fail4:
    Error("fail4\n");
    DriverFormatFree(Frontend->TargetPath);
    Frontend->TargetPath = NULL;
fail3:
    Error("fail3\n");
    DriverFormatFree(Frontend->FrontendPath);
    Frontend->FrontendPath = NULL;
fail2:
    Error("Fail2\n");
    __FrontendFree(Frontend);
fail1:
    Error("Fail1 (%08x)\n", Status);
    *_Frontend = NULL;
    return Status;
}

VOID
FrontendDestroy(
    __in  PXENVBD_FRONTEND        Frontend
    )
{
    const ULONG TargetId = Frontend->TargetId;

    Trace("Target[%d] @ (%d) =====>\n", TargetId, KeGetCurrentIrql());

    PdoFreeInquiryData(Frontend->Inquiry);
    Frontend->Inquiry = NULL;

    ThreadAlert(Frontend->BackendThread);
    ThreadJoin(Frontend->BackendThread);
    Frontend->BackendThread = NULL;

    GranterDestroy(Frontend->Granter);
    Frontend->Granter = NULL;

    BlockRingDestroy(Frontend->BlockRing);
    Frontend->BlockRing = NULL;

    NotifierDestroy(Frontend->Notifier);
    Frontend->Notifier = NULL;

    DriverFormatFree(Frontend->TargetPath);
    Frontend->TargetPath = NULL;

    DriverFormatFree(Frontend->FrontendPath);
    Frontend->FrontendPath = NULL;

    ASSERT3P(Frontend->BackendPath, ==, NULL);
    ASSERT3P(Frontend->Inquiry, ==, NULL);
    ASSERT3P(Frontend->SuspendLateCallback, ==, NULL);
    ASSERT3P(Frontend->BackendWatch, ==, NULL);

    __FrontendFree(Frontend);
    Trace("Target[%d] @ (%d) <=====\n", TargetId, KeGetCurrentIrql());
}

//=============================================================================
// Debug
VOID
FrontendDebugCallback(
    __in  PXENVBD_FRONTEND        Frontend,
    __in  PXENBUS_DEBUG_INTERFACE Debug
    )
{
    XENBUS_DEBUG(Printf, Debug,
                 "FRONTEND: TargetId=%d DeviceId=%d BackendId=%d\n",
                 Frontend->TargetId,
                 Frontend->DeviceId,
                 Frontend->BackendId);
    XENBUS_DEBUG(Printf, Debug,
                 "FRONTEND: FrontendPath %s\n",
                 Frontend->FrontendPath);
    XENBUS_DEBUG(Printf, Debug,
                 "FRONTEND: BackendPath  %s\n",
                 Frontend->BackendPath ? Frontend->BackendPath : "NULL");
    XENBUS_DEBUG(Printf, Debug,
                 "FRONTEND: TargetPath   %s\n",
                 Frontend->TargetPath);
    XENBUS_DEBUG(Printf, Debug,
                 "FRONTEND: State   : %s\n",
                 __XenvbdStateName(Frontend->State));

    XENBUS_DEBUG(Printf, Debug,
                 "FRONTEND: Caps    : %s%s%s%s%s%s\n",
                 Frontend->Caps.Connected ? "CONNECTED " : "",
                 Frontend->Caps.Removable ? "REMOVABLE " : "",
                 Frontend->Caps.SurpriseRemovable ? "SURPRISE " : "",
                 Frontend->Caps.Paging ? "PAGING " : "",
                 Frontend->Caps.Hibernation ? "HIBER " : "",
                 Frontend->Caps.DumpFile ? "DUMP " : "");

    XENBUS_DEBUG(Printf, Debug,
                 "FRONTEND: Features: %s%s%s%s%s\n",
                 Frontend->Features.Persistent ? "PERSISTENT " : "",
                 Frontend->Features.Indirect > 0 ? "INDIRECT " : "",
                 Frontend->DiskInfo.Barrier ? "BARRIER " : "",
                 Frontend->DiskInfo.FlushCache ? "FLUSH " : "",
                 Frontend->DiskInfo.Discard ? "DISCARD " : "");

    if (Frontend->Features.Indirect > 0) {
        XENBUS_DEBUG(Printf, Debug,
                     "FRONTEND: INDIRECT %x\n",
                     Frontend->Features.Indirect);
    }
    if (Frontend->DiskInfo.Discard) {
        XENBUS_DEBUG(Printf, Debug,
                     "FRONTEND: DISCARD %s%x/%x\n",
                     Frontend->DiskInfo.DiscardSecure ? "SECURE " : "",
                     Frontend->DiskInfo.DiscardAlignment,
                     Frontend->DiskInfo.DiscardGranularity);
    }

    XENBUS_DEBUG(Printf, Debug,
                 "FRONTEND: DiskInfo: %llu @ %u (%u) %08x\n",
                 Frontend->DiskInfo.SectorCount,
                 Frontend->DiskInfo.SectorSize,
                 Frontend->DiskInfo.PhysSectorSize,
                 Frontend->DiskInfo.DiskInfo);

    GranterDebugCallback(Frontend->Granter, Debug);
    BlockRingDebugCallback(Frontend->BlockRing, Debug);
    NotifierDebugCallback(Frontend->Notifier, Debug);
}

