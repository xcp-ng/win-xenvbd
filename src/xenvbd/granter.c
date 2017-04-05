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
#include "target.h"
#include "adapter.h"
#include "util.h"
#include "debug.h"
#include "thread.h"
#include <gnttab_interface.h>

struct _XENVBD_GRANTER {
    PXENVBD_FRONTEND                Frontend;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;

    PXENBUS_GNTTAB_INTERFACE        GnttabInterface;
    PXENBUS_GNTTAB_CACHE            Cache;
    KSPIN_LOCK                      Lock;

    USHORT                          BackendDomain;
    LONG                            Current;
    LONG                            Maximum;
};
#define GRANTER_POOL_TAG            'tnGX'

static FORCEINLINE PVOID
__GranterAllocate(
    IN  ULONG                       Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, GRANTER_POOL_TAG);
}

static FORCEINLINE VOID
__GranterFree(
    IN  PVOID                       Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, GRANTER_POOL_TAG);
}

NTSTATUS
GranterCreate(
    IN  PXENVBD_FRONTEND            Frontend,
    OUT PXENVBD_GRANTER*            Granter
    )
{
    NTSTATUS    status;

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
    IN  PXENVBD_GRANTER             Granter
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
    IN  PVOID               Argument
    )
{
    PXENVBD_GRANTER         Granter = Argument;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Granter->Lock);
}

static VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
GranterReleaseLock(
    IN  PVOID               Argument
    )
{
    PXENVBD_GRANTER         Granter = Argument;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

#pragma prefast(disable:26110)
    KeReleaseSpinLockFromDpcLevel(&Granter->Lock);
}

#define MAXNAMELEN  32

NTSTATUS
GranterConnect(
    IN  PXENVBD_GRANTER             Granter,
    IN  USHORT                      BackendDomain
    )
{
    PXENVBD_ADAPTER Adapter = TargetGetAdapter(FrontendGetTarget(Granter->Frontend));
    CHAR        Name[MAXNAMELEN];
    NTSTATUS    status;

    ASSERT(Granter->Connected == FALSE);

    Granter->GnttabInterface = AdapterAcquireGnttab(Adapter);

    status = STATUS_UNSUCCESSFUL;
    if (Granter->GnttabInterface == NULL)
        goto fail1;

    Granter->BackendDomain = BackendDomain;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "disk_%u",
                                FrontendGetTargetId(Granter->Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_GNTTAB(CreateCache,
                           Granter->GnttabInterface,
                           Name,
                           0,
                           GranterAcquireLock,
                           GranterReleaseLock,
                           Granter,
                           &Granter->Cache);
    if (!NT_SUCCESS(status))
        goto fail3;

    Granter->Connected = TRUE;
    return STATUS_SUCCESS;

fail3:
fail2:
    Granter->BackendDomain = 0;
    XENBUS_GNTTAB(Release, Granter->GnttabInterface);
    Granter->GnttabInterface = NULL;
fail1:
    return status;
}

NTSTATUS
GranterStoreWrite(
    IN  PXENVBD_GRANTER             Granter,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  PCHAR                       FrontendPath
    )
{
    UNREFERENCED_PARAMETER(Granter);
    UNREFERENCED_PARAMETER(Transaction);
    UNREFERENCED_PARAMETER(FrontendPath);

    return STATUS_SUCCESS;
}

VOID
GranterEnable(
    IN  PXENVBD_GRANTER             Granter
    )
{
    ASSERT(Granter->Enabled == FALSE);

    Granter->Enabled = TRUE;
}

VOID
GranterDisable(
    IN  PXENVBD_GRANTER             Granter
    )
{
    ASSERT(Granter->Enabled == TRUE);

    Granter->Enabled = FALSE;
}

VOID
GranterDisconnect(
    IN  PXENVBD_GRANTER             Granter
    )
{
    ASSERT(Granter->Connected == TRUE);

    ASSERT3S(Granter->Current, ==, 0);
    Granter->Maximum = 0;

    XENBUS_GNTTAB(DestroyCache,
                  Granter->GnttabInterface,
                  Granter->Cache);
    Granter->Cache = NULL;

    XENBUS_GNTTAB(Release, Granter->GnttabInterface);
    Granter->GnttabInterface = NULL;

    Granter->BackendDomain = 0;
    Granter->Connected = FALSE;
}

VOID
GranterDebugCallback(
    IN  PXENVBD_GRANTER             Granter,
    IN  PXENBUS_DEBUG_INTERFACE     Debug
    )
{
    XENBUS_DEBUG(Printf, Debug,
                 "GRANTER: %s %s\n", 
                 Granter->Connected ? "CONNECTED" : "DISCONNECTED",
                 Granter->Enabled ? "ENABLED" : "DISABLED");
    XENBUS_DEBUG(Printf, Debug,
                 "GRANTER: %d / %d\n",
                 Granter->Current,
                 Granter->Maximum);
    Granter->Maximum = Granter->Current;
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
                           Granter->GnttabInterface, 
                           Granter->Cache,
                           FALSE,
                           Granter->BackendDomain,
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
fail1:
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
                           Granter->GnttabInterface,
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
                         Granter->GnttabInterface,
                         Entry);
}
