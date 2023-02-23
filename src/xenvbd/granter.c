/* Copyright (c) Xen Project.
 * Copyright (c) Cloud Software Group, Inc.
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
#include <ntstrsafe.h>

#include <debug_interface.h>
#include <gnttab_interface.h>

#include "granter.h"
#include "frontend.h"
#include "target.h"
#include "adapter.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

struct _XENVBD_GRANTER {
    PXENVBD_FRONTEND                Frontend;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;

    XENBUS_DEBUG_INTERFACE          DebugInterface;
    XENBUS_GNTTAB_INTERFACE         GnttabInterface;
    PXENBUS_DEBUG_CALLBACK          DebugCallback;
    PXENBUS_GNTTAB_CACHE            Cache;
    KSPIN_LOCK                      Lock;

    LONG                            Current;
    LONG                            Maximum;
};
#define GRANTER_POOL_TAG            'tnGX'

static FORCEINLINE PVOID
__GranterAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, GRANTER_POOL_TAG);
}

static FORCEINLINE VOID
__GranterFree(
    IN  PVOID   Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, GRANTER_POOL_TAG);
}

NTSTATUS
GranterCreate(
    IN  PXENVBD_FRONTEND    Frontend,
    OUT PXENVBD_GRANTER     *Granter
    )
{
    NTSTATUS                status;

    status = STATUS_NO_MEMORY;
    *Granter = __GranterAllocate(sizeof(XENVBD_GRANTER));
    if (*Granter == NULL)
        goto fail1;

    (*Granter)->Frontend = Frontend;
    KeInitializeSpinLock(&(*Granter)->Lock);

    return STATUS_SUCCESS;

fail1:
    return status;
}

VOID
GranterDestroy(
    IN  PXENVBD_GRANTER Granter
    )
{
    Granter->Frontend = NULL;
    RtlZeroMemory(&Granter->Lock, sizeof(KSPIN_LOCK));

    ASSERT(IsZeroMemory(Granter, sizeof(XENVBD_GRANTER)));
    
    __GranterFree(Granter);
}

static VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
GranterAcquireLock(
    IN  PVOID       Argument
    )
{
    PXENVBD_GRANTER Granter = Argument;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Granter->Lock);
}

static VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
GranterReleaseLock(
    IN  PVOID       Argument
    )
{
    PXENVBD_GRANTER Granter = Argument;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

#pragma prefast(disable:26110)
    KeReleaseSpinLockFromDpcLevel(&Granter->Lock);
}

static DECLSPEC_NOINLINE VOID
GranterDebugCallback(
    IN  PVOID       Argument,
    IN  BOOLEAN     Crashing
    )
{
    PXENVBD_GRANTER Granter = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Granter->DebugInterface,
                 "%s %s\n",
                 Granter->Connected ? "CONNECTED" : "DISCONNECTED",
                 Granter->Enabled ? "ENABLED" : "DISABLED");
    XENBUS_DEBUG(Printf,
                 &Granter->DebugInterface,
                 "%d / %d\n",
                 Granter->Current,
                 Granter->Maximum);

    Granter->Maximum = Granter->Current;
}

#define MAXNAMELEN  32

NTSTATUS
GranterConnect(
    IN  PXENVBD_GRANTER Granter
    )
{
    PXENVBD_ADAPTER     Adapter = TargetGetAdapter(FrontendGetTarget(Granter->Frontend));
    CHAR                Name[MAXNAMELEN];
    NTSTATUS            status;

    ASSERT(Granter->Connected == FALSE);

    AdapterGetGnttabInterface(Adapter, &Granter->GnttabInterface);
    AdapterGetDebugInterface(Adapter, &Granter->DebugInterface);

    status = XENBUS_GNTTAB(Acquire, &Granter->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Acquire, &Granter->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "disk_%u",
                                FrontendGetTargetId(Granter->Frontend));
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_GNTTAB(CreateCache,
                           &Granter->GnttabInterface,
                           Name,
                           0,
                           0,
                           GranterAcquireLock,
                           GranterReleaseLock,
                           Granter,
                           &Granter->Cache);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_DEBUG(Register,
                          &Granter->DebugInterface,
                          __MODULE__"|GRANTER",
                          GranterDebugCallback,
                          Granter,
                          &Granter->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail5;

    Granter->Connected = TRUE;
    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");
    XENBUS_GNTTAB(DestroyCache,
                  &Granter->GnttabInterface,
                  Granter->Cache);
    Granter->Cache = NULL;
fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
    XENBUS_DEBUG(Release, &Granter->DebugInterface);
fail2:
    Error("fail2\n");
    XENBUS_GNTTAB(Release, &Granter->GnttabInterface);
fail1:
    Error("fail1 %08x\n", status);

    RtlZeroMemory(&Granter->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Granter->GnttabInterface, sizeof(XENBUS_GNTTAB_INTERFACE));

    return status;
}

NTSTATUS
GranterStoreWrite(
    IN  PXENVBD_GRANTER Granter,
    IN  PVOID           Transaction
    )
{
    UNREFERENCED_PARAMETER(Granter);
    UNREFERENCED_PARAMETER(Transaction);

    return STATUS_SUCCESS;
}

VOID
GranterEnable(
    IN  PXENVBD_GRANTER Granter
    )
{
    ASSERT(Granter->Enabled == FALSE);

    Granter->Enabled = TRUE;
}

VOID
GranterDisable(
    IN  PXENVBD_GRANTER Granter
    )
{
    ASSERT(Granter->Enabled == TRUE);

    Granter->Enabled = FALSE;
}

VOID
GranterDisconnect(
    IN  PXENVBD_GRANTER Granter
    )
{
    ASSERT(Granter->Connected == TRUE);

    ASSERT3S(Granter->Current, ==, 0);
    Granter->Maximum = 0;

    XENBUS_DEBUG(Deregister,
                 &Granter->DebugInterface,
                 Granter->DebugCallback);
    Granter->DebugCallback = NULL;

    XENBUS_GNTTAB(DestroyCache,
                  &Granter->GnttabInterface,
                  Granter->Cache);
    Granter->Cache = NULL;

    XENBUS_DEBUG(Release, &Granter->DebugInterface);
    XENBUS_GNTTAB(Release, &Granter->GnttabInterface);

    RtlZeroMemory(&Granter->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Granter->GnttabInterface, sizeof(XENBUS_GNTTAB_INTERFACE));

    Granter->Connected = FALSE;
}

NTSTATUS
GranterGet(
    IN  PXENVBD_GRANTER     Granter,
    IN  PFN_NUMBER          Pfn,
    IN  BOOLEAN             ReadOnly,
    OUT PVOID               *Handle
    )
{
    PXENBUS_GNTTAB_ENTRY    Entry;
    NTSTATUS                status;
    LONG                    Value;

    status = STATUS_DEVICE_NOT_READY;
    if (Granter->Connected == FALSE)
        goto fail1;

    status = XENBUS_GNTTAB(PermitForeignAccess, 
                           &Granter->GnttabInterface,
                           Granter->Cache,
                           FALSE,
                           (USHORT)FrontendGetBackendDomain(Granter->Frontend),
                           Pfn,
                           ReadOnly,
                           &Entry);
    if (!NT_SUCCESS(status))
        goto fail2;
    
    Value = InterlockedIncrement(&Granter->Current);
    if (Value > Granter->Maximum)
        Granter->Maximum = Value;

    *Handle = Entry;
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

VOID
GranterPut(
    IN  PXENVBD_GRANTER     Granter,
    IN  PVOID               Handle
    )
{
    PXENBUS_GNTTAB_ENTRY    Entry = Handle;
    NTSTATUS                status;

    if (Granter->Connected == FALSE)
        return;

    status = XENBUS_GNTTAB(RevokeForeignAccess,
                           &Granter->GnttabInterface,
                           Granter->Cache,
                           FALSE,
                           Entry);
    ASSERT(NT_SUCCESS(status));

    InterlockedDecrement(&Granter->Current);
}

ULONG
GranterReference(
    IN  PXENVBD_GRANTER     Granter,
    IN  PVOID               Handle
    )
{
    PXENBUS_GNTTAB_ENTRY    Entry = Handle;

    if (Granter->Connected == FALSE)
        return 0;

    return XENBUS_GNTTAB(GetReference,
                         &Granter->GnttabInterface,
                         Entry);
}
