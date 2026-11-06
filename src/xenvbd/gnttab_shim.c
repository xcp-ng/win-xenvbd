/* Copyright (c) Vates.
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

#include <gnttab_interface.h>

#include "gnttab_shim.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

struct _XENVBD_GNTTAB_SHIM {
    struct _XENBUS_GNTTAB_INTERFACE_V4  Source;
};

#define GNTTAB_SHIM_POOL_TAG    'STGV'

static FORCEINLINE PXENVBD_GNTTAB_SHIM
__GnttabShim(
    _In_ PINTERFACE Interface
    )
{
    return Interface->Context;
}

static NTSTATUS
GnttabShimAcquire(
    _In_ PINTERFACE Interface
    )
{
    PXENVBD_GNTTAB_SHIM Shim = __GnttabShim(Interface);

    return XENBUS_GNTTAB(Acquire, &Shim->Source);
}

static VOID
GnttabShimRelease(
    _In_ PINTERFACE Interface
    )
{
    PXENVBD_GNTTAB_SHIM Shim = __GnttabShim(Interface);

    XENBUS_GNTTAB(Release, &Shim->Source);
}

static NTSTATUS
GnttabShimCreateCache(
    _In_ PINTERFACE                 Interface,
    _In_ PCSTR                      Name,
    _In_ ULONG                      Reservation,
    _In_ ULONG                      Cap,
    _In_ XENBUS_CACHE_ACQUIRE_LOCK  AcquireLock,
    _In_ XENBUS_CACHE_RELEASE_LOCK  ReleaseLock,
    _In_opt_ PVOID                  Argument,
    _Outptr_ PXENBUS_GNTTAB_CACHE   *Cache
    )
{
    PXENVBD_GNTTAB_SHIM             Shim = __GnttabShim(Interface);

    return XENBUS_GNTTAB(CreateCache,
                         &Shim->Source,
                         Name,
                         Reservation,
                         Cap,
                         AcquireLock,
                         ReleaseLock,
                         Argument,
                         Cache);
}

static NTSTATUS
GnttabShimPermitForeignAccess(
    _In_ PINTERFACE                 Interface,
    _In_ PXENBUS_GNTTAB_CACHE       Cache,
    _In_ BOOLEAN                    Locked,
    _In_ USHORT                     Domain,
    _In_ PFN_NUMBER                 Pfn,
    _In_ BOOLEAN                    ReadOnly,
    _Outptr_ PXENBUS_GNTTAB_ENTRY   *Entry
    )
{
    PXENVBD_GNTTAB_SHIM             Shim = __GnttabShim(Interface);

    return XENBUS_GNTTAB(PermitForeignAccess,
                         &Shim->Source,
                         Cache,
                         Locked,
                         Domain,
                         Pfn,
                         ReadOnly,
                         Entry);
}

static NTSTATUS
GnttabShimTryRevokeForeignAccess(
    _In_ PINTERFACE             Interface,
    _In_ PXENBUS_GNTTAB_CACHE   Cache,
    _In_ BOOLEAN                Locked,
    _In_ PXENBUS_GNTTAB_ENTRY   Entry
    )
{
    PXENVBD_GNTTAB_SHIM         Shim = __GnttabShim(Interface);
    NTSTATUS                    status;

    status = XENBUS_GNTTAB(RevokeForeignAccessVersion2,
                           &Shim->Source,
                           Cache,
                           Locked,
                           Entry);
    if (!NT_SUCCESS(status))
        return STATUS_DEVICE_BUSY;

    return STATUS_SUCCESS;
}

static ULONG
GnttabShimGetReference(
    _In_ PINTERFACE             Interface,
    _In_ PXENBUS_GNTTAB_ENTRY   Entry
    )
{
    PXENVBD_GNTTAB_SHIM         Shim = __GnttabShim(Interface);

    return XENBUS_GNTTAB(GetReference, &Shim->Source, Entry);
}

static NTSTATUS
GnttabShimQueryReference(
    _In_ PINTERFACE         Interface,
    _In_ ULONG              Reference,
    _Out_opt_ PPFN_NUMBER   Pfn,
    _Out_opt_ PBOOLEAN      ReadOnly
    )
{
    PXENVBD_GNTTAB_SHIM     Shim = __GnttabShim(Interface);

    return XENBUS_GNTTAB(QueryReference, &Shim->Source, Reference, Pfn, ReadOnly);
}

static VOID
GnttabShimDestroyCache(
    _In_ PINTERFACE             Interface,
    _In_ PXENBUS_GNTTAB_CACHE   Cache
    )
{
    PXENVBD_GNTTAB_SHIM         Shim = __GnttabShim(Interface);

    XENBUS_GNTTAB(DestroyCache, &Shim->Source, Cache);
}

static NTSTATUS
GnttabShimMapForeignPages(
    _In_ PINTERFACE             Interface,
    _In_ USHORT                 Domain,
    _In_ ULONG                  NumberPages,
    _In_ PULONG                 References,
    _In_ BOOLEAN                ReadOnly,
    _Out_ PHYSICAL_ADDRESS      *Address
    )
{
    PXENVBD_GNTTAB_SHIM         Shim = __GnttabShim(Interface);

    return XENBUS_GNTTAB(MapForeignPages,
                         &Shim->Source,
                         Domain,
                         NumberPages,
                         References,
                         ReadOnly,
                         Address);
}

static NTSTATUS
GnttabShimUnmapForeignPages(
    _In_ PINTERFACE             Interface,
    _In_ PHYSICAL_ADDRESS       Address
    )
{
    PXENVBD_GNTTAB_SHIM         Shim = __GnttabShim(Interface);

    return XENBUS_GNTTAB(UnmapForeignPages, &Shim->Source, Address);
}

NTSTATUS
GnttabShimCreate(
    _In_ const struct _XENBUS_GNTTAB_INTERFACE_V4   *Source,
    _Out_ PXENBUS_GNTTAB_INTERFACE                  Interface,
    _Outptr_ PXENVBD_GNTTAB_SHIM                    *Shim
    )
{
    NTSTATUS                                        status;

    status = STATUS_NO_MEMORY;
    *Shim = __AllocatePoolWithTag(NonPagedPool,
                                  sizeof(XENVBD_GNTTAB_SHIM),
                                  GNTTAB_SHIM_POOL_TAG);
    if (*Shim == NULL)
        goto fail1;

    (*Shim)->Source = *Source;

    RtlZeroMemory(Interface, sizeof(XENBUS_GNTTAB_INTERFACE));
    Interface->Interface.Size = sizeof(XENBUS_GNTTAB_INTERFACE);
    Interface->Interface.Version = 5;
    Interface->Interface.Context = *Shim;
    Interface->GnttabAcquire = GnttabShimAcquire;
    Interface->GnttabRelease = GnttabShimRelease;
    Interface->GnttabCreateCache = GnttabShimCreateCache;
    Interface->GnttabPermitForeignAccess = GnttabShimPermitForeignAccess;
    Interface->GnttabTryRevokeForeignAccess = GnttabShimTryRevokeForeignAccess;
    Interface->GnttabGetReference = GnttabShimGetReference;
    Interface->GnttabQueryReference = GnttabShimQueryReference;
    Interface->GnttabDestroyCache = GnttabShimDestroyCache;
    Interface->GnttabMapForeignPages = GnttabShimMapForeignPages;
    Interface->GnttabUnmapForeignPages = GnttabShimUnmapForeignPages;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 %08x\n", status);
    return status;
}

VOID
GnttabShimDestroy(
    _In_ _Post_ptr_invalid_ PXENVBD_GNTTAB_SHIM Shim
    )
{
    RtlZeroMemory(Shim, sizeof(XENVBD_GNTTAB_SHIM));
    __FreePoolWithTag(Shim, GNTTAB_SHIM_POOL_TAG);
}
