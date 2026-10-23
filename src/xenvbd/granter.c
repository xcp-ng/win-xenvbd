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
    _In_ ULONG  Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, GRANTER_POOL_TAG);
}

static FORCEINLINE VOID
__GranterFree(
    _In_ PVOID  Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, GRANTER_POOL_TAG);
}

NTSTATUS
GranterCreate(
    _In_ PXENVBD_FRONTEND       Frontend,
    _Outptr_ PXENVBD_GRANTER    *Granter
    )
{
    NTSTATUS                    status;

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

static VOID
__GranterDestroyCache(
    _Inout_ PXENVBD_GRANTER Granter
    );

VOID
GranterDestroy(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    BUG_ON(Granter->Current != 0);
    ASSERT3P(Granter->Cache, ==, NULL);

    Granter->Frontend = NULL;
    RtlZeroMemory(&Granter->Lock, sizeof(KSPIN_LOCK));

    ASSERT(IsZeroMemory(Granter, sizeof(XENVBD_GRANTER)));
    
    __GranterFree(Granter);
}

static VOID
_IRQL_requires_(DISPATCH_LEVEL)
GranterAcquireLock(
    _In_ PVOID      Argument
    )
{
    PXENVBD_GRANTER Granter = Argument;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Granter->Lock);
}

static VOID
_IRQL_requires_(DISPATCH_LEVEL)
GranterReleaseLock(
    _In_ PVOID      Argument
    )
{
    PXENVBD_GRANTER Granter = Argument;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

#pragma prefast(disable:26110)
    KeReleaseSpinLockFromDpcLevel(&Granter->Lock);
}

static DECLSPEC_NOINLINE VOID
GranterDebugCallback(
    _In_ PVOID      Argument,
    _In_ BOOLEAN    Crashing
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

static NTSTATUS
__GranterCreateCache(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    PXENVBD_ADAPTER         Adapter = TargetGetAdapter(FrontendGetTarget(Granter->Frontend));
    CHAR                    Name[MAXNAMELEN];
    NTSTATUS                status;

    ASSERT3P(Granter->Cache, ==, NULL);

    AdapterGetGnttabInterface(Adapter, &Granter->GnttabInterface);

    status = XENBUS_GNTTAB(Acquire, &Granter->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "disk_%u",
                                FrontendGetTargetId(Granter->Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

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
        goto fail3;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    XENBUS_GNTTAB(Release, &Granter->GnttabInterface);

fail1:
    Error("fail1 %08x\n", status);

    RtlZeroMemory(&Granter->GnttabInterface, sizeof(XENBUS_GNTTAB_INTERFACE));

    return status;
}

static VOID
__GranterDestroyCache(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    ASSERT3S(Granter->Current, ==, 0);

    XENBUS_GNTTAB(DestroyCache,
                  &Granter->GnttabInterface,
                  Granter->Cache);
    Granter->Cache = NULL;

    XENBUS_GNTTAB(Release, &Granter->GnttabInterface);

    RtlZeroMemory(&Granter->GnttabInterface, sizeof(XENBUS_GNTTAB_INTERFACE));
}

NTSTATUS
GranterConnect(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    PXENVBD_ADAPTER         Adapter = TargetGetAdapter(FrontendGetTarget(Granter->Frontend));
    NTSTATUS                status;

    ASSERT(Granter->Connected == FALSE);

    if (Granter->Cache == NULL) {
        status = __GranterCreateCache(Granter);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    AdapterGetDebugInterface(Adapter, &Granter->DebugInterface);

    status = XENBUS_DEBUG(Acquire, &Granter->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_DEBUG(Register,
                          &Granter->DebugInterface,
                          __MODULE__"|GRANTER",
                          GranterDebugCallback,
                          Granter,
                          &Granter->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail3;

    Granter->Connected = TRUE;
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    XENBUS_DEBUG(Release, &Granter->DebugInterface);

fail2:
    Error("fail2\n");

    RtlZeroMemory(&Granter->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));

    if (Granter->Current == 0)
        __GranterDestroyCache(Granter);

fail1:
    Error("fail1 %08x\n", status);

    return status;
}

NTSTATUS
GranterStoreWrite(
    _In_ PXENVBD_GRANTER    Granter,
    _In_ PVOID              Transaction
    )
{
    UNREFERENCED_PARAMETER(Granter);
    UNREFERENCED_PARAMETER(Transaction);

    return STATUS_SUCCESS;
}

VOID
GranterEnable(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    ASSERT(Granter->Enabled == FALSE);

    Granter->Enabled = TRUE;
}

VOID
GranterDisable(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    ASSERT(Granter->Enabled == TRUE);

    Granter->Enabled = FALSE;
}

VOID
GranterDisconnect(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    ASSERT(Granter->Connected == TRUE);

    Granter->Maximum = 0;

    XENBUS_DEBUG(Deregister,
                 &Granter->DebugInterface,
                 Granter->DebugCallback);
    Granter->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Granter->DebugInterface);

    RtlZeroMemory(&Granter->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));

    Granter->Connected = FALSE;

    if (Granter->Current != 0) {
        Warning("Target[%u] : %ld grants outstanding\n",
                FrontendGetTargetId(Granter->Frontend),
                Granter->Current);
        return;
    }

    __GranterDestroyCache(Granter);
}

VOID
GranterD3ToD0(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    ASSERT3P(Granter->Cache, ==, NULL);
    ASSERT3S(Granter->Current, ==, 0);
}

VOID
GranterD0ToD3(
    _Inout_ PXENVBD_GRANTER Granter
    )
{
    KIRQL                   Irql;

    ASSERT(!Granter->Connected);

    // All grants must be revoked before transitioning to S3.

    BUG_ON(Granter->Current != 0);

    if (Granter->Cache == NULL)
        return;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __GranterDestroyCache(Granter);
    KeLowerIrql(Irql);
}

NTSTATUS
GranterGet(
    _Inout_ PXENVBD_GRANTER Granter,
    _In_ PFN_NUMBER         Pfn,
    _In_ BOOLEAN            ReadOnly,
    _Outptr_ PVOID          *Handle
    )
{
    PXENBUS_GNTTAB_ENTRY    Entry;
    NTSTATUS                status;
    LONG                    Value;

    status = STATUS_DEVICE_NOT_READY;
    if (Granter->Connected == FALSE)
        goto fail1;

    Value = InterlockedIncrement(&Granter->Current);

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

    if (Value > Granter->Maximum)
        Granter->Maximum = Value;

    *Handle = Entry;
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");
    InterlockedDecrement(&Granter->Current);
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

_Check_return_
NTSTATUS
GranterTryPut(
    _Inout_ PXENVBD_GRANTER Granter,
    _In_ PVOID              Handle
    )
{
    PXENBUS_GNTTAB_ENTRY    Entry = Handle;
    NTSTATUS                status;

    ASSERT3P(Granter->Cache, !=, NULL);

    status = XENBUS_GNTTAB(RevokeForeignAccess,
                           &Granter->GnttabInterface,
                           Granter->Cache,
                           FALSE,
                           Entry);
    if (!NT_SUCCESS(status))
        goto fail1;

    InterlockedDecrement(&Granter->Current);

    return STATUS_SUCCESS;

fail1:
    return status;
}

ULONG
GranterReference(
    _In_ PXENVBD_GRANTER    Granter,
    _In_ PVOID              Handle
    )
{
    PXENBUS_GNTTAB_ENTRY    Entry = Handle;

    if (Granter->Connected == FALSE)
        return 0;

    return XENBUS_GNTTAB(GetReference,
                         &Granter->GnttabInterface,
                         Entry);
}
