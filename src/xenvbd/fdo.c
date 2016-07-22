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

#define INITGUID 1

#include "fdo.h"
#include "driver.h"
#include "registry.h"
#include "pdo.h"
#include "srbext.h"
#include "thread.h"
#include "buffer.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include <version.h>
#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <emulated_interface.h>

#include <stdlib.h>

#define MAXNAMELEN  128

#define FDO_SIGNATURE   'odfX'

struct _XENVBD_FDO {
    ULONG                       Signature;
    KEVENT                      RemoveEvent;
    LONG                        ReferenceCount;
    PDEVICE_OBJECT              DeviceObject;
    PDEVICE_OBJECT              LowerDeviceObject;
    PDEVICE_OBJECT              PhysicalDeviceObject;
    KSPIN_LOCK                  Lock;
    DEVICE_POWER_STATE          DevicePower;
    ANSI_STRING                 Enumerator;

    // Power
    PXENVBD_THREAD              DevicePowerThread;
    PIRP                        DevicePowerIrp;

    // Interfaces to XenBus
    XENBUS_EVTCHN_INTERFACE     Evtchn;
    XENBUS_STORE_INTERFACE      Store;
    XENBUS_GNTTAB_INTERFACE     Gnttab;
    XENBUS_DEBUG_INTERFACE      Debug;
    XENBUS_SUSPEND_INTERFACE    Suspend;
    XENBUS_UNPLUG_INTERFACE     Unplug;
    XENFILT_EMULATED_INTERFACE  Emulated;
    
    // Debug Callback
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallback;

    // Targets
    KSPIN_LOCK                  TargetLock;
    PXENVBD_PDO                 Targets[XENVBD_MAX_TARGETS];

    // Target Enumeration
    PXENVBD_THREAD              ScanThread;
    KEVENT                      ScanEvent;
    PXENBUS_STORE_WATCH         ScanWatch;

    // Statistics
    LONG                        CurrentSrbs;
    LONG                        MaximumSrbs;
    LONG                        TotalSrbs;
};

//=============================================================================
static FORCEINLINE BOOLEAN
__FdoSetDevicePowerState(
    __in PXENVBD_FDO                 Fdo,
    __in DEVICE_POWER_STATE          State
    )
{
    KIRQL       Irql;
    BOOLEAN     Changed = FALSE;

    KeAcquireSpinLock(&Fdo->Lock, &Irql);

    if (Fdo->DevicePower != State) {
        Verbose("POWER %s to %s\n", PowerDeviceStateName(Fdo->DevicePower), PowerDeviceStateName(State));
        Changed = TRUE;
        Fdo->DevicePower = State;
    }

    KeReleaseSpinLock(&Fdo->Lock, Irql);

    return Changed;
}

static FORCEINLINE DEVICE_POWER_STATE
__FdoGetDevicePowerState(
    __in PXENVBD_FDO                Fdo
    )
{
    KIRQL               Irql;
    DEVICE_POWER_STATE  State;

    KeAcquireSpinLock(&Fdo->Lock, &Irql);
    State = Fdo->DevicePower;
    KeReleaseSpinLock(&Fdo->Lock, Irql);

    return State;
}

__checkReturn
static FORCEINLINE PXENVBD_PDO
__FdoGetPdoAlways(
    __in PXENVBD_FDO                 Fdo,
    __in ULONG                       TargetId,
    __in PCHAR                       Caller
    )
{
    PXENVBD_PDO Pdo;
    KIRQL       Irql;

    ASSERT3U(TargetId, <, XENVBD_MAX_TARGETS);

    KeAcquireSpinLock(&Fdo->TargetLock, &Irql);
    Pdo = Fdo->Targets[TargetId];
    if (Pdo) {
        __PdoReference(Pdo, Caller);
    }
    KeReleaseSpinLock(&Fdo->TargetLock, Irql);
    
    return Pdo;
}

__checkReturn
static FORCEINLINE PXENVBD_PDO
___FdoGetPdo(
    __in PXENVBD_FDO                 Fdo,
    __in ULONG                       TargetId,
    __in PCHAR                       Caller
    )
{
    PXENVBD_PDO Pdo = NULL;
    KIRQL       Irql;

    ASSERT3U(TargetId, <, XENVBD_MAX_TARGETS);

    KeAcquireSpinLock(&Fdo->TargetLock, &Irql);
    if (Fdo->Targets[TargetId] && 
        __PdoReference(Fdo->Targets[TargetId], Caller) > 0) {
        Pdo = Fdo->Targets[TargetId];
    }
    KeReleaseSpinLock(&Fdo->TargetLock, Irql);
    
    return Pdo;
}
#define __FdoGetPdo(f, t) ___FdoGetPdo(f, t, __FUNCTION__)

// Reference Counting
LONG
__FdoReference(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       Caller
    )
{
    LONG Result;
    
    ASSERT3P(Fdo, !=, NULL);
    Result = InterlockedIncrement(&Fdo->ReferenceCount);
    ASSERTREFCOUNT(Result, >, 0, Caller);

    if (Result == 1) {
        Result = InterlockedDecrement(&Fdo->ReferenceCount);
        Error("%s: Attempting to take reference of removed FDO from %d\n", Caller, Result);
        return 0;
    } else {
        ASSERTREFCOUNT(Result, >, 1, Caller);
        return Result;
    }
}
FORCEINLINE LONG
__FdoDereference(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       Caller
    )
{
    LONG    Result;
    
    ASSERT3P(Fdo, !=, NULL);
    Result = InterlockedDecrement(&Fdo->ReferenceCount);
    ASSERTREFCOUNT(Result, >=, 0, Caller);
    
    if (Result == 0) {
        Verbose("Final ReferenceCount dropped, 0x%p able to be removed\n", Fdo);
        KeSetEvent(&Fdo->RemoveEvent, IO_NO_INCREMENT, FALSE);
    }
    return Result;
}
BOOLEAN
FdoLinkPdo(
    __in PXENVBD_FDO                 Fdo,
    __in PXENVBD_PDO                 Pdo
    )
{
    KIRQL       Irql;
    PXENVBD_PDO Current;
    BOOLEAN     Result = FALSE;
    ULONG       TargetId = PdoGetTargetId(Pdo);

    KeAcquireSpinLock(&Fdo->TargetLock, &Irql);
    Current = Fdo->Targets[TargetId];
    if (Fdo->Targets[TargetId] == NULL) {
        Fdo->Targets[TargetId] = Pdo;
        Result = TRUE;
    }
    KeReleaseSpinLock(&Fdo->TargetLock, Irql);

    if (!Result) {
        Warning("Target[%d] : Current 0x%p, New 0x%p\n", TargetId, Current, Pdo);
    }
    return Result;
}
BOOLEAN
FdoUnlinkPdo(
    __in PXENVBD_FDO                 Fdo,
    __in PXENVBD_PDO                 Pdo
    )
{
    KIRQL       Irql;
    PXENVBD_PDO Current;
    BOOLEAN     Result = FALSE;
    ULONG       TargetId = PdoGetTargetId(Pdo);

    KeAcquireSpinLock(&Fdo->TargetLock, &Irql);
    Current = Fdo->Targets[TargetId];
    if (Fdo->Targets[TargetId] == Pdo) {
        Fdo->Targets[TargetId] = NULL;
        Result = TRUE;
    }
    KeReleaseSpinLock(&Fdo->TargetLock, Irql);

    if (!Result) {
        Warning("Target[%d] : Current 0x%p, Expected 0x%p\n", TargetId, Current, Pdo);
    }
    return Result;
}

//=============================================================================
// QueryInterface

static NTSTATUS
FdoQueryInterface(
    IN  PXENVBD_FDO     Fdo,
    IN  const GUID      *Guid,
    IN  ULONG           Version,
    OUT PINTERFACE      Interface,
    IN  ULONG           Size,
    IN  BOOLEAN         Optional
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = Guid;
    StackLocation->Parameters.QueryInterface.Size = (USHORT)Size;
    StackLocation->Parameters.QueryInterface.Version = (USHORT)Version;
    StackLocation->Parameters.QueryInterface.Interface = Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status)) {
        if (status == STATUS_NOT_SUPPORTED && Optional)
            goto done;

        goto fail2;
    }

done:
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

#define QUERY_INTERFACE(                                                            \
    _Fdo,                                                                               \
    _ProviderName,                                                                      \
    _InterfaceName,                                                                     \
    _Interface,                                                                         \
    _Size,                                                                              \
    _Optional)                                                                          \
    FdoQueryInterface((_Fdo),                                                           \
                      &GUID_ ## _ProviderName ## _ ## _InterfaceName ## _INTERFACE,     \
                      _ProviderName ## _ ## _InterfaceName ## _INTERFACE_VERSION_MAX,   \
                      (_Interface),                                                     \
                      (_Size),                                                          \
                      (_Optional))

//=============================================================================
// Debug

static DECLSPEC_NOINLINE VOID
FdoDebugCallback(
    __in PVOID                       Context,
    __in BOOLEAN                     Crashing
    )
{
    PXENVBD_FDO     Fdo = Context;
    ULONG           TargetId;

    if (Fdo == NULL || Fdo->DebugCallback == NULL)
        return;

    XENBUS_DEBUG(Printf, &Fdo->Debug,
                 "FDO: Version: %d.%d.%d.%d (%d/%d/%d)\n",
                 MAJOR_VERSION, MINOR_VERSION, MICRO_VERSION, BUILD_NUMBER,
                 DAY, MONTH, YEAR); 
    XENBUS_DEBUG(Printf, &Fdo->Debug,
                 "FDO: Fdo: 0x%p (ref-count %d) %s\n",
                 Context,
                 Fdo->ReferenceCount,
                 Crashing ? "CRASHING" : "");
    XENBUS_DEBUG(Printf, &Fdo->Debug,
                 "FDO: DevObj 0x%p LowerDevObj 0x%p PhysDevObj 0x%p\n",
                 Fdo->DeviceObject,
                 Fdo->LowerDeviceObject,
                 Fdo->PhysicalDeviceObject);
    XENBUS_DEBUG(Printf, &Fdo->Debug,
                 "FDO: DevicePowerState: %s\n",
                 PowerDeviceStateName(Fdo->DevicePower));
    XENBUS_DEBUG(Printf, &Fdo->Debug,
                 "FDO: Enumerator      : %s (0x%p)\n",
                 FdoEnum(Fdo), Fdo->Enumerator.Buffer);
    XENBUS_DEBUG(Printf, &Fdo->Debug,
                 "FDO: Srbs            : %d / %d (%d Total)\n",
                 Fdo->CurrentSrbs, Fdo->MaximumSrbs, Fdo->TotalSrbs);

    BufferDebugCallback(&Fdo->Debug);
    
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        // no need to use __FdoGetPdo (which is locked at DISPATCH) as called at HIGH_LEVEL
        PXENVBD_PDO Pdo = Fdo->Targets[TargetId];
        if (Pdo == NULL)
            continue;

        XENBUS_DEBUG(Printf, &Fdo->Debug,
                     "FDO: ====> Target[%-3d]    : 0x%p\n",                  
                     TargetId, Pdo);

        // call Target's debug callback directly
        PdoDebugCallback(Pdo, &Fdo->Debug);

        XENBUS_DEBUG(Printf, &Fdo->Debug,
                     "FDO: <==== Target[%-3d]    : 0x%p\n",                  
                     TargetId, Pdo);
    }

    Fdo->MaximumSrbs = Fdo->CurrentSrbs;
    Fdo->TotalSrbs = 0;
}

//=============================================================================
// Enumeration
static FORCEINLINE ULONG
__ParseVbd(
    __in PCHAR                       DeviceIdStr
    )
{
    ULONG   DeviceId = strtoul(DeviceIdStr, NULL, 10);
    
    ASSERT3U((DeviceId & ~((1 << 29) - 1)), ==, 0);

    if (DeviceId & (1 << 28)) { 
        return (DeviceId & ((1 << 20) - 1)) >> 8;           /* xvd    */
    } else {
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
        default:    break;
        }
    }
    Error("Invalid DeviceId %s (%08x)\n", DeviceIdStr, DeviceId);
    return 0xFFFFFFFF; // OBVIOUS ERROR VALUE
}
static FORCEINLINE XENVBD_DEVICE_TYPE
__DeviceType(
    __in PCHAR                      Type
    )
{
    if (strcmp(Type, "disk") == 0)
        return XENVBD_DEVICE_TYPE_DISK;
    if (strcmp(Type, "cdrom") == 0)
        return XENVBD_DEVICE_TYPE_CDROM;
    return XENVBD_DEVICE_TYPE_UNKNOWN;
}
__checkReturn
static FORCEINLINE BOOLEAN
__FdoHiddenTarget(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       DeviceId,
    __out PXENVBD_DEVICE_TYPE        DeviceType
    )
{
    NTSTATUS    Status;
    PCHAR       FrontendPath;
    PCHAR       Buffer;
    ULONG       Value;
    
    *DeviceType = XENVBD_DEVICE_TYPE_UNKNOWN;
    FrontendPath = DriverFormat("device/%s/%s", FdoEnum(Fdo), DeviceId);
    if (!FrontendPath)
        goto fail;

    // Ejected?
    Status = XENBUS_STORE(Read, &Fdo->Store, NULL, FrontendPath, "ejected", &Buffer);
    if (NT_SUCCESS(Status)) {
        Value = strtoul(Buffer, NULL, 10);
        XENBUS_STORE(Free, &Fdo->Store, Buffer);

        if (Value)
            goto ignore;
    }

    // Not Disk?
    Status = XENBUS_STORE(Read, &Fdo->Store, NULL, FrontendPath, "device-type", &Buffer);
    if (!NT_SUCCESS(Status))
        goto ignore;
    *DeviceType = __DeviceType(Buffer);
    XENBUS_STORE(Free, &Fdo->Store, Buffer);
    
    switch (*DeviceType) {
    case XENVBD_DEVICE_TYPE_DISK:   
        break;
    case XENVBD_DEVICE_TYPE_CDROM:  
        if (DriverParameters.PVCDRom)   
            break;
        // intentional fall-through
    default:                        
        goto ignore;
    }

    // Try to Create
    DriverFormatFree(FrontendPath);
    return FALSE;

fail:
    Error("Fail\n");
    return TRUE;

ignore:
    DriverFormatFree(FrontendPath);
    return TRUE;
}
__checkReturn
static FORCEINLINE BOOLEAN
__FdoIsPdoUnplugged(
    __in PXENVBD_FDO                 Fdo,
    __in PCHAR                       Enumerator,
    __in PCHAR                       Device,
    __in ULONG                       Target
    )
{
    // Only check targets that could be emulated
    if (Target > 3) {
        Verbose("Target[%d] : (%s/%s) Emulated NOT_APPLICABLE (non-IDE device)\n", 
                            Target, Enumerator, Device);
        return TRUE;
    }
     
    // Check presense of Emulated interface. Absence indicates emulated cannot be unplugged
    if (Fdo->Emulated.Interface.Context == NULL) {
        Warning("Target[%d] : (%s/%s) Emulated NOT_KNOWN (assumed PRESENT)\n", 
                            Target, Enumerator, Device);
        return FALSE;
    }

    // Ask XenFilt if Ctrlr(0), Target(Target), Lun(0) is present
    if (XENFILT_EMULATED(IsDiskPresent, &Fdo->Emulated, 0, Target, 0)) {
        Verbose("Target[%d] : (%s/%s) Emulated PRESENT\n", 
                            Target, Enumerator, Device);
        return FALSE;
    } else {
        Verbose("Target[%d] : (%s/%s) Emulated NOT_PRESENT\n", 
                            Target, Enumerator, Device);
        return TRUE;
    }
}

static FORCEINLINE VOID
__FdoEnumerate(
    __in    PXENVBD_FDO     Fdo,
    __in    PANSI_STRING    Devices,
    __out   PBOOLEAN        NeedInvalidate,
    __out   PBOOLEAN        NeedReboot
    )
{
    ULONG               TargetId;
    PANSI_STRING        Device;
    ULONG               Index;
    PXENVBD_PDO         Pdo;

    *NeedInvalidate = FALSE;
    *NeedReboot = FALSE;

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        BOOLEAN     Missing = TRUE;

        Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo == NULL)
            continue;

        for (Index = 0; Devices[Index].Buffer != NULL; ++Index) {
            ULONG DeviceTargetId;
            Device = &Devices[Index];
            DeviceTargetId = __ParseVbd(Device->Buffer);
            if (TargetId == DeviceTargetId) {
                Missing = FALSE;
                break;
            }
        }

        if (Missing && !PdoIsMissing(Pdo)) {
            PdoSetMissing(Pdo, "Device Disappeared");
            if (PdoGetDevicePnpState(Pdo) == Present)
                PdoSetDevicePnpState(Pdo, Deleted);
            else
                *NeedInvalidate = TRUE;
        }

        if (PdoGetDevicePnpState(Pdo) == Deleted) {
            PdoDereference(Pdo);
            PdoDestroy(Pdo);
        } else {
            PdoDereference(Pdo);
        }
    }

    // add new targets
    for (Index = 0; Devices[Index].Buffer != NULL; ++Index) {
        XENVBD_DEVICE_TYPE  DeviceType;

        Device = &Devices[Index];

        TargetId = __ParseVbd(Device->Buffer);
        if (TargetId == 0xFFFFFFFF) {
            continue;
        }

        Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            PdoDereference(Pdo);
            continue;
        }

        if (__FdoHiddenTarget(Fdo, Device->Buffer, &DeviceType)) {
            continue;
        }

        if (!__FdoIsPdoUnplugged(Fdo,
                                FdoEnum(Fdo),
                                Device->Buffer,
                                TargetId)) {
            *NeedReboot = TRUE;
            continue;
        }

        if (PdoCreate(Fdo,
                      Device->Buffer,
                      TargetId,
                      DeviceType)) {
            *NeedInvalidate = TRUE;
        }
    }
}

static FORCEINLINE PANSI_STRING
__FdoMultiSzToAnsi(
    IN  PCHAR       Buffer
    )
{
    PANSI_STRING    Ansi;
    LONG            Index;
    LONG            Count;
    NTSTATUS        status;

    Index = 0;
    Count = 0;
    for (;;) {
        if (Buffer[Index] == '\0') {
            Count++;
            Index++;

            // Check for double NUL
            if (Buffer[Index] == '\0')
                break;
        } else {
            Index++;
        }
    }

    Ansi = __AllocateNonPagedPoolWithTag(__FUNCTION__,
                                         __LINE__,
                                         sizeof (ANSI_STRING) * (Count + 1),
                                         FDO_SIGNATURE);

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __AllocateNonPagedPoolWithTag(__FUNCTION__,
                                                           __LINE__,
                                                           Ansi[Index].MaximumLength,
                                                           FDO_SIGNATURE);

        status = STATUS_NO_MEMORY;
        if (Ansi[Index].Buffer == NULL)
            goto fail2;

        RtlCopyMemory(Ansi[Index].Buffer, Buffer, Length);
        Ansi[Index].Length = (USHORT)Length;

        Buffer += Length + 1;
    }

    return Ansi;

fail2:
    Error("fail2\n");

    while (--Index >= 0)
            __FreePoolWithTag(Ansi[Index].Buffer, FDO_SIGNATURE);

    __FreePoolWithTag(Ansi, FDO_SIGNATURE);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static FORCEINLINE PANSI_STRING
__FdoMultiSzToUpcaseAnsi(
    IN  PCHAR       Buffer
    )
{
    PANSI_STRING    Ansi;
    LONG            Index;
    LONG            Count;
    NTSTATUS        status;

    Index = 0;
    Count = 0;
    for (;;) {
        if (Buffer[Index] == '\0') {
            Count++;
            Index++;

            // Check for double NUL
            if (Buffer[Index] == '\0')
                break;
        } else {
            Buffer[Index] = __toupper(Buffer[Index]);
            Index++;
        }
    }

    Ansi = __AllocateNonPagedPoolWithTag(__FUNCTION__,
                                         __LINE__,
                                         sizeof (ANSI_STRING) * (Count + 1),
                                         FDO_SIGNATURE);

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __AllocateNonPagedPoolWithTag(__FUNCTION__,
                                                           __LINE__,
                                                           Ansi[Index].MaximumLength,
                                                           FDO_SIGNATURE);

        status = STATUS_NO_MEMORY;
        if (Ansi[Index].Buffer == NULL)
            goto fail2;

        RtlCopyMemory(Ansi[Index].Buffer, Buffer, Length);
        Ansi[Index].Length = (USHORT)Length;

        Buffer += Length + 1;
    }

    return Ansi;

fail2:
    Error("fail2\n");

    while (--Index >= 0)
            __FreePoolWithTag(Ansi[Index].Buffer, FDO_SIGNATURE);

    __FreePoolWithTag(Ansi, FDO_SIGNATURE);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static FORCEINLINE VOID
__FdoFreeAnsi(
    IN  PANSI_STRING    Ansi
    )
{
    ULONG               Index;

    for (Index = 0; Ansi[Index].Buffer != NULL; Index++)
            __FreePoolWithTag(Ansi[Index].Buffer, FDO_SIGNATURE);

    __FreePoolWithTag(Ansi, FDO_SIGNATURE);
}

static DECLSPEC_NOINLINE VOID
FdoScanTargets(
    __in    PXENVBD_FDO Fdo
    )
{
    NTSTATUS        Status;
    PCHAR           Buffer;
    PANSI_STRING    Devices;
    BOOLEAN         NeedInvalidate;
    BOOLEAN         NeedReboot;

    Status = XENBUS_STORE(Directory, &Fdo->Store, NULL, "device", FdoEnum(Fdo), &Buffer);
    if (!NT_SUCCESS(Status))
        return;

    Devices = __FdoMultiSzToAnsi(Buffer);
    XENBUS_STORE(Free, &Fdo->Store, Buffer);

    if (Devices == NULL)
        return;

    __FdoEnumerate(Fdo, Devices, &NeedInvalidate, &NeedReboot);
    __FdoFreeAnsi(Devices);

    if (NeedInvalidate) {
        StorPortNotification(BusChangeDetected, Fdo, 0);
    }
    if (NeedReboot) {
        DriverRequestReboot();
    }
}

__checkReturn
static DECLSPEC_NOINLINE NTSTATUS
FdoScan(
    __in PXENVBD_THREAD              Thread,
    __in PVOID                       Context
    )
{
    PXENVBD_FDO     Fdo = Context;
    PKEVENT         Event = ThreadGetEvent(Thread);

    for (;;) {
        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Thread))
            break;

        if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0)
            FdoScanTargets(Fdo);

        KeSetEvent(&Fdo->ScanEvent, IO_NO_INCREMENT, FALSE);
    }
    KeSetEvent(&Fdo->ScanEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

//=============================================================================
// Initialize, Start, Stop

__checkReturn
__drv_maxIRQL(APC_LEVEL)
static FORCEINLINE NTSTATUS
__FdoQueryInterfaces(
    __in PXENVBD_FDO             Fdo
    )
{
    NTSTATUS        Status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    // Get STORE Interface
    Status = QUERY_INTERFACE(Fdo,
                             XENBUS,
                             STORE,
                             (PINTERFACE)&Fdo->Store,
                             sizeof (Fdo->Store),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // Get EVTCHN Interface
    Status = QUERY_INTERFACE(Fdo,
                             XENBUS,
                             EVTCHN,
                             (PINTERFACE)&Fdo->Evtchn,
                             sizeof (Fdo->Evtchn),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Get GNTTAB Interface
    Status = QUERY_INTERFACE(Fdo,
                             XENBUS,
                             GNTTAB,
                             (PINTERFACE)&Fdo->Gnttab,
                             sizeof (Fdo->Gnttab),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail3;

    // Get SUSPEND Interface
    Status = QUERY_INTERFACE(Fdo,
                             XENBUS,
                             SUSPEND,
                             (PINTERFACE)&Fdo->Suspend,
                             sizeof (Fdo->Suspend),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail4;

    // Get DEBUG Interface
    Status = QUERY_INTERFACE(Fdo,
                             XENBUS,
                             DEBUG,
                             (PINTERFACE)&Fdo->Debug,
                             sizeof (Fdo->Debug),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail5;

    // Get UNPLUG Interface
    Status = QUERY_INTERFACE(Fdo,
                             XENBUS,
                             UNPLUG,
                             (PINTERFACE)&Fdo->Unplug,
                             sizeof (Fdo->Unplug),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail6;

    // Get EMULATED Interface (optional)
    Status = QUERY_INTERFACE(Fdo,
                             XENFILT,
                             EMULATED,
                             (PINTERFACE)&Fdo->Emulated,
                             sizeof (Fdo->Emulated),
                             TRUE);
    if (!NT_SUCCESS(Status))
        goto fail7;

    return STATUS_SUCCESS;

fail7:
    RtlZeroMemory(&Fdo->Unplug,
                  sizeof (XENBUS_UNPLUG_INTERFACE));
fail6:
    RtlZeroMemory(&Fdo->Debug,
                  sizeof (XENBUS_DEBUG_INTERFACE));
fail5:
    RtlZeroMemory(&Fdo->Suspend,
                  sizeof (XENBUS_SUSPEND_INTERFACE));
fail4:
    RtlZeroMemory(&Fdo->Gnttab,
                  sizeof (XENBUS_GNTTAB_INTERFACE));
fail3:
    RtlZeroMemory(&Fdo->Evtchn,
                  sizeof (XENBUS_EVTCHN_INTERFACE));
fail2:
    RtlZeroMemory(&Fdo->Store,
                  sizeof (XENBUS_STORE_INTERFACE));
fail1:
    return Status;
}
static FORCEINLINE VOID
__FdoZeroInterfaces(
    __in PXENVBD_FDO             Fdo
    )
{
    RtlZeroMemory(&Fdo->Emulated,
                  sizeof (XENFILT_EMULATED_INTERFACE));
    RtlZeroMemory(&Fdo->Unplug,
                  sizeof (XENBUS_UNPLUG_INTERFACE));
    RtlZeroMemory(&Fdo->Debug,
                  sizeof (XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Fdo->Suspend,
                  sizeof (XENBUS_SUSPEND_INTERFACE));
    RtlZeroMemory(&Fdo->Gnttab,
                  sizeof (XENBUS_GNTTAB_INTERFACE));
    RtlZeroMemory(&Fdo->Evtchn,
                  sizeof (XENBUS_EVTCHN_INTERFACE));
    RtlZeroMemory(&Fdo->Store,
                  sizeof (XENBUS_STORE_INTERFACE));
}
static FORCEINLINE NTSTATUS
__FdoAcquire(
    __in PXENVBD_FDO    Fdo
    )
{
    NTSTATUS            status;

    if (Fdo->Emulated.Interface.Context) {
        status = XENFILT_EMULATED(Acquire, &Fdo->Emulated);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    status = XENBUS_SUSPEND(Acquire, &Fdo->Suspend);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_DEBUG(Acquire, &Fdo->Debug);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_GNTTAB(Acquire, &Fdo->Gnttab);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_EVTCHN(Acquire, &Fdo->Evtchn);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_STORE(Acquire, &Fdo->Store);
    if (!NT_SUCCESS(status))
        goto fail6;

    return STATUS_SUCCESS;

fail6:
    XENBUS_EVTCHN(Release, &Fdo->Evtchn);
fail5:
    XENBUS_GNTTAB(Release, &Fdo->Gnttab);
fail4:
    XENBUS_DEBUG(Release, &Fdo->Debug);
fail3:
    XENBUS_SUSPEND(Release, &Fdo->Suspend);
fail2:
    if (Fdo->Emulated.Interface.Context)
        XENFILT_EMULATED(Release, &Fdo->Emulated);
fail1:
    return status;
}
static FORCEINLINE VOID
__FdoRelease(
    __in PXENVBD_FDO             Fdo
    )
{
    XENBUS_STORE(Release, &Fdo->Store);
    XENBUS_EVTCHN(Release, &Fdo->Evtchn);
    XENBUS_GNTTAB(Release, &Fdo->Gnttab);
    XENBUS_DEBUG(Release, &Fdo->Debug);
    XENBUS_SUSPEND(Release, &Fdo->Suspend);
    if (Fdo->Emulated.Interface.Context)
        XENFILT_EMULATED(Release, &Fdo->Emulated);
}

static FORCEINLINE BOOLEAN
__FdoMatchDistribution(
    IN  PXENVBD_FDO Fdo,
    IN  PCHAR       Buffer
    )
{
    PCHAR           Vendor;
    PCHAR           Product;
    PCHAR           Context;
    const CHAR      *Text;
    BOOLEAN         Match;
    ULONG           Index;
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Fdo);

    status = STATUS_INVALID_PARAMETER;

    Vendor = __strtok_r(Buffer, " ", &Context);
    if (Vendor == NULL)
        goto fail1;

    Product = __strtok_r(NULL, " ", &Context);
    if (Product == NULL)
        goto fail2;

    Match = TRUE;

    Text = VENDOR_NAME_STR;

    for (Index = 0; Text[Index] != 0; Index++) {
        if (!isalnum((UCHAR)Text[Index])) {
            if (Vendor[Index] != '_') {
                Match = FALSE;
                break;
            }
        } else {
            if (Vendor[Index] != Text[Index]) {
                Match = FALSE;
                break;
            }
        }
    }

    Text = "XENVBD";

    if (_stricmp(Product, Text) != 0)
        Match = FALSE;

    return Match;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return FALSE;
}

static VOID
FdoClearDistribution(
    IN  PXENVBD_FDO Fdo
    )
{
    PCHAR           Buffer;
    PANSI_STRING    Distributions;
    ULONG           Index;
    NTSTATUS        status;

    Trace("====>\n");

    status = XENBUS_STORE(Directory,
                          &Fdo->Store,
                          NULL,
                          NULL,
                          "drivers",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Distributions = __FdoMultiSzToUpcaseAnsi(Buffer);

        XENBUS_STORE(Free,
                     &Fdo->Store,
                     Buffer);
    } else {
        Distributions = NULL;
    }

    if (Distributions == NULL)
        goto done;

    for (Index = 0; Distributions[Index].Buffer != NULL; Index++) {
        PANSI_STRING    Distribution = &Distributions[Index];

        status = XENBUS_STORE(Read,
                              &Fdo->Store,
                              NULL,
                              "drivers",
                              Distribution->Buffer,
                              &Buffer);
        if (!NT_SUCCESS(status))
            continue;

        if (__FdoMatchDistribution(Fdo, Buffer))
            (VOID) XENBUS_STORE(Remove,
                                &Fdo->Store,
                                NULL,
                                "drivers",
                                Distribution->Buffer);

        XENBUS_STORE(Free,
                     &Fdo->Store,
                     Buffer);
    }

    __FdoFreeAnsi(Distributions);

done:
    Trace("<====\n");
}

#define MAXIMUM_INDEX   255

static NTSTATUS
FdoSetDistribution(
    IN  PXENVBD_FDO Fdo
    )
{
    ULONG           Index;
    CHAR            Distribution[MAXNAMELEN];
    CHAR            Vendor[MAXNAMELEN];
    const CHAR      *Product;
    NTSTATUS        status;

    Trace("====>\n");

    Index = 0;
    while (Index <= MAXIMUM_INDEX) {
        PCHAR   Buffer;

        status = RtlStringCbPrintfA(Distribution,
                                    MAXNAMELEN,
                                    "%u",
                                    Index);
        ASSERT(NT_SUCCESS(status));

        status = XENBUS_STORE(Read,
                              &Fdo->Store,
                              NULL,
                              "drivers",
                              Distribution,
                              &Buffer);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_OBJECT_NAME_NOT_FOUND)
                goto update;

            goto fail1;
        }

        XENBUS_STORE(Free,
                     &Fdo->Store,
                     Buffer);

        Index++;
    }

    status = STATUS_UNSUCCESSFUL;
    goto fail2;

update:
    status = RtlStringCbPrintfA(Vendor,
                                MAXNAMELEN,
                                "%s",
                                VENDOR_NAME_STR);
    ASSERT(NT_SUCCESS(status));

    for (Index  = 0; Vendor[Index] != '\0'; Index++)
        if (!isalnum((UCHAR)Vendor[Index]))
            Vendor[Index] = '_';

    Product = "XENVBD";

#if DBG
#define ATTRIBUTES   "(DEBUG)"
#else
#define ATTRIBUTES   ""
#endif

    (VOID) XENBUS_STORE(Printf,
                        &Fdo->Store,
                        NULL,
                        "drivers",
                        Distribution,
                        "%s %s %u.%u.%u %s",
                        Vendor,
                        Product,
                        MAJOR_VERSION,
                        MINOR_VERSION,
                        MICRO_VERSION,
                        ATTRIBUTES
                        );

#undef  ATTRIBUTES

    Trace("<====\n");
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoD3ToD0(
    __in PXENVBD_FDO    Fdo
    )
{
    NTSTATUS            Status;

    Trace("=====>\n");

    (VOID) FdoSetDistribution(Fdo);

    ASSERT3P(Fdo->ScanWatch, ==, NULL);
    Status = XENBUS_STORE(WatchAdd,
                          &Fdo->Store,
                          "device",
                          FdoEnum(Fdo),
                          ThreadGetEvent(Fdo->ScanThread),
                          &Fdo->ScanWatch);
    if (!NT_SUCCESS(Status))
        goto fail1;

    (VOID) XENBUS_STORE(Printf,
                        &Fdo->Store,
                        NULL,
                        "feature/hotplug",
                        "vbd",
                        "%u",
                        TRUE);

    Trace("<=====\n");
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", Status);

    return Status;
}

static FORCEINLINE VOID
__FdoD0ToD3(
    __in PXENVBD_FDO    Fdo
    )
{
    Trace("=====>\n");

    (VOID) XENBUS_STORE(Remove,
                        &Fdo->Store,
                        NULL,
                        "feature/hotplug",
                        "vbd");

    (VOID) XENBUS_STORE(WatchRemove,
                        &Fdo->Store,
                        Fdo->ScanWatch);
    Fdo->ScanWatch = NULL;

    FdoClearDistribution(Fdo);

    Trace("<=====\n");
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
FdoSuspendLateCallback(
    __in PVOID                   Argument
    )
{
    PXENVBD_FDO     Fdo = Argument;
    NTSTATUS        Status;

    Verbose("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    __FdoD0ToD3(Fdo);

    Status = __FdoD3ToD0(Fdo);
    ASSERT(NT_SUCCESS(Status));
}

static NTSTATUS
FdoD3ToD0(
    __in PXENVBD_FDO             Fdo
    )
{
    NTSTATUS    Status;
    ULONG       TargetId;

    if (!__FdoSetDevicePowerState(Fdo, PowerDeviceD0))
        return STATUS_SUCCESS;

    Trace("=====> (%d)\n", KeGetCurrentIrql());
    Verbose("D3->D0\n");

    // Get Interfaces
    Status = __FdoAcquire(Fdo);
    if (!NT_SUCCESS(Status))
        goto fail1;
    
    // register debug callback
    ASSERT3P(Fdo->DebugCallback, ==, NULL);
    Status = XENBUS_DEBUG(Register, 
                          &Fdo->Debug, 
                          __MODULE__, 
                          FdoDebugCallback, 
                          Fdo, 
                          &Fdo->DebugCallback);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Power UP any PDOs
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            Status = PdoD3ToD0(Pdo);
            PdoDereference(Pdo);

            if (!NT_SUCCESS(Status))
                goto fail3;
        }
    }

    Status = __FdoD3ToD0(Fdo);
    if (!NT_SUCCESS(Status))
        goto fail4;

    // register suspend callback to re-register the watch
    ASSERT3P(Fdo->SuspendCallback, ==, NULL);
    Status = XENBUS_SUSPEND(Register,
                            &Fdo->Suspend,
                            SUSPEND_CALLBACK_LATE,
                            FdoSuspendLateCallback,
                            Fdo,
                            &Fdo->SuspendCallback);
    if (!NT_SUCCESS(Status))
        goto fail5;

    Trace("<===== (%d)\n", KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail5:
    Error("Fail5\n");

    __FdoD0ToD3(Fdo);

fail4:
    Error("Fail4\n");

fail3:
    Error("Fail3\n");

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            PdoD0ToD3(Pdo);
            PdoDereference(Pdo);
        }
    }

    XENBUS_DEBUG(Deregister, &Fdo->Debug, Fdo->DebugCallback);
    Fdo->DebugCallback = NULL;

fail2:
    Error("Fail2\n");

    __FdoRelease(Fdo);
   
fail1:
    Error("Fail1 (%08x)\n", Status);

    __FdoSetDevicePowerState(Fdo, PowerDeviceD3);
    return Status;
}

static VOID
FdoD0ToD3(
    __in PXENVBD_FDO             Fdo
    )
{
    ULONG       TargetId;

    if (!__FdoSetDevicePowerState(Fdo, PowerDeviceD3))
        return;

    Trace("=====> (%d)\n", KeGetCurrentIrql());
    Verbose("D0->D3\n");

    // remove suspend callback
    XENBUS_SUSPEND(Deregister, &Fdo->Suspend, Fdo->SuspendCallback);
    Fdo->SuspendCallback = NULL;

    __FdoD0ToD3(Fdo);

    // Power DOWN any PDOs
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            PdoD0ToD3(Pdo);
            PdoDereference(Pdo);
        }
    }

    // free debug callback
    if (Fdo->DebugCallback != NULL) {
        XENBUS_DEBUG(Deregister, &Fdo->Debug, Fdo->DebugCallback);
        Fdo->DebugCallback = NULL;
    }

    // Release Interfaces
    __FdoRelease(Fdo);

    Trace("<===== (%d)\n", KeGetCurrentIrql());
}

__checkReturn
static DECLSPEC_NOINLINE NTSTATUS
FdoDevicePower(
    __in PXENVBD_THREAD             Thread,
    __in PVOID                      Context
    )
{
    PXENVBD_FDO     Fdo = Context;

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  Stack;
        DEVICE_POWER_STATE  DeviceState;
        POWER_ACTION        Action;
        NTSTATUS            Status;

        if (!ThreadWait(Thread))
            break;

        // must have a pended DevicePowerIrp
        ASSERT3P(Fdo->DevicePowerIrp, !=, NULL);

        Irp = Fdo->DevicePowerIrp;
        Fdo->DevicePowerIrp = NULL;

        Stack = IoGetCurrentIrpStackLocation(Irp);
        DeviceState = Stack->Parameters.Power.State.DeviceState;
        Action = Stack->Parameters.Power.ShutdownType;

        switch (Stack->MinorFunction) {
        case IRP_MN_SET_POWER:
            switch (DeviceState) {
            case PowerDeviceD0:
                Verbose("FDO:PowerDeviceD0\n");
                FdoD3ToD0(Fdo);
                break;

            case PowerDeviceD3:
                Verbose("FDO:PowerDeviceD3 (%s)\n", PowerActionName(Action));
                FdoD0ToD3(Fdo);
                break;

            default:
                break;
            }
            break;
        case IRP_MN_QUERY_POWER:
        default:
            break;
        }
        FdoDereference(Fdo);
        Status = DriverDispatchPower(Fdo->DeviceObject, Irp);
        if (!NT_SUCCESS(Status)) {
            Warning("StorPort failed PowerIRP with %08x\n", Status);
        }
    }

    return STATUS_SUCCESS;
}

__checkReturn
__drv_maxIRQL(PASSIVE_LEVEL)
static NTSTATUS
__FdoInitialize(
    __in PXENVBD_FDO             Fdo
    )
{
    ULONG       StorStatus;
    NTSTATUS    Status;

    Trace("=====> (%d)\n", KeGetCurrentIrql());
    
    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    // initialize the memory
    Fdo->DevicePower = PowerDeviceD3;
    KeInitializeSpinLock(&Fdo->TargetLock);
    KeInitializeSpinLock(&Fdo->Lock);
    KeInitializeEvent(&Fdo->RemoveEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&Fdo->ScanEvent, SynchronizationEvent, FALSE);

    Fdo->ReferenceCount = 1;
    Fdo->Signature = FDO_SIGNATURE;

    StorStatus = StorPortGetDeviceObjects(Fdo,
                                          &Fdo->DeviceObject,
                                          &Fdo->PhysicalDeviceObject,
                                          &Fdo->LowerDeviceObject);
    Status = STATUS_UNSUCCESSFUL;
    if (StorStatus != STOR_STATUS_SUCCESS) {
        Error("StorPortGetDeviceObjects() (%x:%s)\n", StorStatus, StorStatusName(StorStatus));
        goto fail1;
    }

    // get interfaces
    Status = __FdoQueryInterfaces(Fdo);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // start enum thread
    Status = ThreadCreate(FdoScan, Fdo, &Fdo->ScanThread);
    if (!NT_SUCCESS(Status))
        goto fail3;

    Status = ThreadCreate(FdoDevicePower, Fdo, &Fdo->DevicePowerThread);
    if (!NT_SUCCESS(Status))
        goto fail4;

    // query enumerator
    // fix this up to query from device location(?)
    //RtlInitAnsiString(&Fdo->Enumerator, "vbd");

    // link fdo
    DriverLinkFdo(Fdo);

    Trace("<===== (%d)\n", KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");
    ThreadAlert(Fdo->ScanThread);
    ThreadJoin(Fdo->ScanThread);
    Fdo->ScanThread = NULL;
fail3:
    Error("fail3\n");
    __FdoZeroInterfaces(Fdo);
fail2:
    Error("fail2\n");
    Fdo->DeviceObject = NULL;
    Fdo->PhysicalDeviceObject = NULL;
    Fdo->LowerDeviceObject = NULL;
fail1:
    Error("fail1 (%08x)\n", Status);
    return Status;
}
__drv_maxIRQL(PASSIVE_LEVEL)
static VOID
__FdoTerminate(
    __in PXENVBD_FDO             Fdo
    )
{
    ULONG   TargetId;

    Trace("=====> (%d)\n", KeGetCurrentIrql());

    DriverUnlinkFdo(Fdo);
    ASSERT3U(Fdo->DevicePower, ==, PowerDeviceD3);
    FdoDereference(Fdo);

    // should wait until ReferenceCount == 0
    Verbose("Terminating, %d Refs\n", Fdo->ReferenceCount);
    ASSERT3S(Fdo->ReferenceCount, >=, 0);
    KeWaitForSingleObject(&Fdo->RemoveEvent, Executive, KernelMode, FALSE, NULL);
    ASSERT3S(Fdo->ReferenceCount, ==, 0);

    // stop device power thread
    ThreadAlert(Fdo->DevicePowerThread);
    ThreadJoin(Fdo->DevicePowerThread);
    Fdo->DevicePowerThread = NULL;

    // stop enum thread
    ThreadAlert(Fdo->ScanThread);
    ThreadJoin(Fdo->ScanThread);
    Fdo->ScanThread = NULL;

    // clear device objects
    Fdo->DeviceObject = NULL;
    Fdo->PhysicalDeviceObject = NULL;
    Fdo->LowerDeviceObject = NULL;
    
    // delete targets
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdoAlways(Fdo, TargetId, __FUNCTION__);
        if (Pdo) {
            // Pdo may not be in Deleted state yet, force it as Fdo is terminating
            if (PdoGetDevicePnpState(Pdo) != Deleted)
                PdoSetDevicePnpState(Pdo, Deleted);
            // update missing (for debug output more than anything else
            PdoSetMissing(Pdo, "FdoTerminate");
            // drop ref-count acquired in __FdoGetPdo *before* destroying Pdo
            PdoDereference(Pdo);
            PdoDestroy(Pdo);
        }
    }

    // cleanup memory
    ASSERT3U(Fdo->DevicePower, ==, PowerDeviceD3);
    ASSERT3P(Fdo->DebugCallback, ==, NULL);
    ASSERT3P(Fdo->SuspendCallback, ==, NULL);

    Fdo->Signature = 0;
    Fdo->DevicePower = 0;
    Fdo->CurrentSrbs = Fdo->MaximumSrbs = Fdo->TotalSrbs = 0;
    RtlZeroMemory(&Fdo->Enumerator, sizeof(ANSI_STRING));
    RtlZeroMemory(&Fdo->TargetLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Fdo->Lock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Fdo->ScanEvent, sizeof(KEVENT));
    RtlZeroMemory(&Fdo->RemoveEvent, sizeof(KEVENT));
    __FdoZeroInterfaces(Fdo);

    ASSERT(IsZeroMemory(Fdo, sizeof(XENVBD_FDO)));
    Trace("<===== (%d)\n", KeGetCurrentIrql());
}
//=============================================================================
// Query Methods
__checkReturn
FORCEINLINE PDEVICE_OBJECT
FdoGetDeviceObject(
    __in PXENVBD_FDO                 Fdo
    )
{
    if (Fdo)
        return Fdo->DeviceObject;
    return NULL;
}

FORCEINLINE ULONG
FdoSizeofXenvbdFdo(
    )
{
    return (ULONG)sizeof(XENVBD_FDO);
}

FORCEINLINE PCHAR
FdoEnum(
    __in PXENVBD_FDO                 Fdo
    )
{
    if (Fdo->Enumerator.Buffer)
        return Fdo->Enumerator.Buffer;
    else
        return "vbd";
}

//=============================================================================
// SRB Methods
FORCEINLINE VOID
FdoStartSrb(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    LONG    Value;

    UNREFERENCED_PARAMETER(Srb);

    Value = InterlockedIncrement(&Fdo->CurrentSrbs);
    if (Value > Fdo->MaximumSrbs)
        Fdo->MaximumSrbs = Value;
    InterlockedIncrement(&Fdo->TotalSrbs);
}

FORCEINLINE VOID
FdoCompleteSrb(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    ASSERT3U(Srb->SrbStatus, !=, SRB_STATUS_PENDING);

    InterlockedDecrement(&Fdo->CurrentSrbs);

    StorPortNotification(RequestComplete, Fdo, Srb);
}

//=============================================================================
// StorPort Methods
BOOLEAN
FdoResetBus(
    __in PXENVBD_FDO                 Fdo
    )
{
    ULONG           TargetId;

    Verbose("====>\n");
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            PdoReset(Pdo);
            PdoDereference(Pdo);
        }
    }
    Verbose("<====\n");

    return TRUE;
}

static VOID
FdoUnplugRequest(
    IN  PXENVBD_FDO Fdo,
    IN  BOOLEAN     Make
    )
{
    NTSTATUS        status;

    status = XENBUS_UNPLUG(Acquire, &Fdo->Unplug);
    if (!NT_SUCCESS(status))
        return;

    XENBUS_UNPLUG(Request,
                  &Fdo->Unplug,
                  XENBUS_UNPLUG_DEVICE_TYPE_DISKS,
                  Make);

    XENBUS_UNPLUG(Release, &Fdo->Unplug);
}

ULONG
FdoFindAdapter(
    __in PXENVBD_FDO                 Fdo,
    __inout PPORT_CONFIGURATION_INFORMATION  ConfigInfo
    )
{
    // setup config info
    ConfigInfo->MaximumTransferLength       = XENVBD_MAX_TRANSFER_LENGTH;
    ConfigInfo->NumberOfPhysicalBreaks      = XENVBD_MAX_PHYSICAL_BREAKS;
    ConfigInfo->AlignmentMask               = 0; // Byte-Aligned
    ConfigInfo->NumberOfBuses               = 1;
    ConfigInfo->InitiatorBusId[0]           = 1;
    ConfigInfo->ScatterGather               = TRUE;
    ConfigInfo->Master                      = TRUE;
    ConfigInfo->CachesData                  = FALSE;
    ConfigInfo->MapBuffers                  = STOR_MAP_NON_READ_WRITE_BUFFERS;
    ConfigInfo->MaximumNumberOfTargets      = XENVBD_MAX_TARGETS;
    ConfigInfo->MaximumNumberOfLogicalUnits = 1;
    ConfigInfo->WmiDataProvider             = FALSE; // should be TRUE
    ConfigInfo->SynchronizationModel        = StorSynchronizeFullDuplex;

    if (ConfigInfo->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED) {
        Trace("64bit DMA\n");
        ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;
    }

    // gets called on resume from hibernate, so only setup if not already done
    if (Fdo->Signature == FDO_SIGNATURE) {
        Verbose("FDO already initalized (0x%p)\n", Fdo);
        return SP_RETURN_FOUND;
    }

    // We need to do this to avoid an assertion in a checked kernel
    (VOID) StorPortGetUncachedExtension(Fdo, ConfigInfo, PAGE_SIZE);

    if (!NT_SUCCESS(__FdoInitialize(Fdo)))
        return SP_RETURN_ERROR;

    FdoUnplugRequest(Fdo, TRUE);

    if (!NT_SUCCESS(FdoD3ToD0(Fdo)))
        return SP_RETURN_ERROR;

    return SP_RETURN_FOUND;
}

static FORCEINLINE VOID
__FdoSrbPnp(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_PNP_REQUEST_BLOCK     Srb
    )
{
    if (!(Srb->SrbPnPFlags & SRB_PNP_FLAGS_ADAPTER_REQUEST)) {
        PXENVBD_PDO     Pdo;

        Pdo = __FdoGetPdo(Fdo, Srb->TargetId);
        if (Pdo) {
            PdoSrbPnp(Pdo, Srb);
            PdoDereference(Pdo);
        }
    }
}

BOOLEAN 
FdoBuildIo(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    InitSrbExt(Srb);

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:
    case SRB_FUNCTION_RESET_DEVICE:
    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_SHUTDOWN:
        FdoStartSrb(Fdo, Srb);
        return TRUE;

        // dont pass to StartIo
    case SRB_FUNCTION_PNP:
        __FdoSrbPnp(Fdo, (PSCSI_PNP_REQUEST_BLOCK)Srb);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    case SRB_FUNCTION_ABORT_COMMAND:
        Srb->SrbStatus = SRB_STATUS_ABORT_FAILED;
        break;
    case SRB_FUNCTION_RESET_BUS:
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        FdoResetBus(Fdo);
        break;
        
    default:
        break;
    }
    
    StorPortNotification(RequestComplete, Fdo, Srb);
    return FALSE;
}   

BOOLEAN 
FdoStartIo(
    __in PXENVBD_FDO                 Fdo,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    PXENVBD_PDO Pdo;
    BOOLEAN     CompleteSrb = TRUE;

    Pdo = __FdoGetPdo(Fdo, Srb->TargetId);
    if (Pdo) {
        CompleteSrb = PdoStartIo(Pdo, Srb);
        PdoDereference(Pdo);
    }

    if (CompleteSrb) {
        FdoCompleteSrb(Fdo, Srb);
    }
    return TRUE;
}

static PXENVBD_PDO
FdoGetPdoFromDeviceObject(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject
    )
{
    ULONG           TargetId;

    ASSERT3P(DeviceObject, !=, NULL);

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_PDO Pdo = __FdoGetPdo(Fdo, TargetId);
        if (Pdo) {
            if (PdoGetDeviceObject(Pdo) == DeviceObject)
                return Pdo;
            PdoDereference(Pdo);
        }
    }

    return NULL;
}

static PXENVBD_PDO
FdoMapDeviceObjectToPdo(
    __in PXENVBD_FDO                Fdo,
    __in PDEVICE_OBJECT             DeviceObject
    )
{
    PXENVBD_PDO                 Pdo;
    KEVENT                      Complete;
    PIRP                        Irp;
    IO_STATUS_BLOCK             StatusBlock;
    PIO_STACK_LOCATION          Stack;
    NTSTATUS                    Status;
    PWCHAR                      String;
    ULONG                       TargetId;
    DECLARE_UNICODE_STRING_SIZE(UniStr, 4);

    KeInitializeEvent(&Complete, NotificationEvent, FALSE);
    
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, DeviceObject, NULL, 0, NULL, &Complete, &StatusBlock);
    if (Irp == NULL)
        goto fail1;

    Stack = IoGetNextIrpStackLocation(Irp);
    Stack->MinorFunction = IRP_MN_QUERY_ID;
    Stack->Parameters.QueryId.IdType = BusQueryInstanceID;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Complete, Executive, KernelMode, FALSE, NULL);
        Status = StatusBlock.Status;
    }
    if (!NT_SUCCESS(Status))
        goto fail2;

    String = (PWCHAR)StatusBlock.Information;
    switch (wcslen(String)) {
    case 3:
        UniStr.Length = 1 * sizeof(WCHAR);
        UniStr_buffer[0] = String[1];
        UniStr_buffer[1] = UNICODE_NULL;
        break;
    case 6:
        UniStr.Length = 2 * sizeof(WCHAR);
        UniStr_buffer[0] = String[2];
        UniStr_buffer[1] = String[3];
        UniStr_buffer[2] = UNICODE_NULL;
        break;
    default:
        goto fail3;
    }

    Status = RtlUnicodeStringToInteger(&UniStr, 16, &TargetId);
    if (!NT_SUCCESS(Status))
        goto fail4;

    Pdo = __FdoGetPdo(Fdo, TargetId);
    if (Pdo == NULL)
        goto fail5;

    PdoSetDeviceObject(Pdo, DeviceObject);
    ExFreePool(String);

    return Pdo;

fail5:
fail4:
fail3:
    ExFreePool(String);
fail2:
fail1:
    return NULL;
}

__checkReturn
NTSTATUS
FdoForwardPnp(
    __in PXENVBD_FDO                Fdo,
    __in PDEVICE_OBJECT             DeviceObject,
    __in PIRP                       Irp
    )
{
    PIO_STACK_LOCATION  Stack;
    PXENVBD_PDO         Pdo;

    ASSERT3P(DeviceObject, !=, Fdo->DeviceObject);

    Pdo = FdoGetPdoFromDeviceObject(Fdo, DeviceObject);
    if (Pdo != NULL) {
        FdoDereference(Fdo);
        return PdoDispatchPnp(Pdo, DeviceObject, Irp);
    }

    Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->MinorFunction == IRP_MN_QUERY_ID &&
        Stack->Parameters.QueryId.IdType == BusQueryDeviceID) {
        Pdo = FdoMapDeviceObjectToPdo(Fdo, DeviceObject);
        if (Pdo != NULL) {
            FdoDereference(Fdo);
            return PdoDispatchPnp(Pdo, DeviceObject, Irp);
        }
    }

    FdoDereference(Fdo);
    return DriverDispatchPnp(DeviceObject, Irp);
}

__checkReturn
NTSTATUS
FdoDispatchPnp(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    )
{
    PIO_STACK_LOCATION  Stack;

    ASSERT3P(DeviceObject, ==, Fdo->DeviceObject);

    Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->MinorFunction) {
    case IRP_MN_REMOVE_DEVICE:
        Verbose("FDO:IRP_MN_REMOVE_DEVICE\n");
        FdoD0ToD3(Fdo);
        FdoUnplugRequest(Fdo, FALSE);
        // drop ref-count acquired in DriverGetFdo *before* destroying Fdo
        FdoDereference(Fdo);
        __FdoTerminate(Fdo);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        if (Stack->Parameters.QueryDeviceRelations.Type == BusRelations) {
            KeClearEvent(&Fdo->ScanEvent);
            ThreadWake(Fdo->ScanThread);

            Trace("waiting for scan thread\n");

            (VOID) KeWaitForSingleObject(&Fdo->ScanEvent,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
        }
        FdoDereference(Fdo);
        break;

    default:
        FdoDereference(Fdo);
        break;
    }

    return DriverDispatchPnp(DeviceObject, Irp);
}

__checkReturn
NTSTATUS
FdoDispatchPower(
    __in PXENVBD_FDO                 Fdo,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    )
{
    PIO_STACK_LOCATION  Stack;
    POWER_STATE_TYPE    PowerType;
    NTSTATUS            status;

    ASSERT3P(DeviceObject, ==, Fdo->DeviceObject);

    Stack = IoGetCurrentIrpStackLocation(Irp);
    PowerType = Stack->Parameters.Power.Type;

    switch (PowerType) {
    case DevicePowerState:
        if (Fdo->DevicePowerThread == NULL) {
            Verbose("DevicePower IRP before DevicePowerThread ready\n");
            FdoDereference(Fdo);
            status = DriverDispatchPower(DeviceObject, Irp);
            break;
        }

        IoMarkIrpPending(Irp);

        ASSERT3P(Fdo->DevicePowerIrp, ==, NULL);
        ASSERT3P(DeviceObject, ==, Fdo->DeviceObject);

        Fdo->DevicePowerIrp = Irp;
        ThreadWake(Fdo->DevicePowerThread);
        
        status = STATUS_PENDING;
        break;

    case SystemPowerState:
    default:
        FdoDereference(Fdo);
        status = DriverDispatchPower(DeviceObject, Irp);
        break;
    }

    return status;
}

PXENBUS_STORE_INTERFACE
FdoAcquireStore(
    __in PXENVBD_FDO    Fdo
    )
{
    NTSTATUS            status;

    status = XENBUS_STORE(Acquire, &Fdo->Store);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Fdo->Store;
}

PXENBUS_EVTCHN_INTERFACE
FdoAcquireEvtchn(
    __in PXENVBD_FDO    Fdo
    )
{
    NTSTATUS            status;

    status = XENBUS_EVTCHN(Acquire, &Fdo->Evtchn);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Fdo->Evtchn;
}

PXENBUS_GNTTAB_INTERFACE
FdoAcquireGnttab(
    __in PXENVBD_FDO    Fdo
    )
{
    NTSTATUS            status;

    status = XENBUS_GNTTAB(Acquire, &Fdo->Gnttab);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Fdo->Gnttab;
}

PXENBUS_DEBUG_INTERFACE
FdoAcquireDebug(
    __in PXENVBD_FDO    Fdo
    )
{
    NTSTATUS            status;

    status = XENBUS_DEBUG(Acquire, &Fdo->Debug);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Fdo->Debug;
}

PXENBUS_SUSPEND_INTERFACE
FdoAcquireSuspend(
    __in PXENVBD_FDO    Fdo    
    )
{
    NTSTATUS            status;

    status = XENBUS_SUSPEND(Acquire, &Fdo->Suspend);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Fdo->Suspend;
}
