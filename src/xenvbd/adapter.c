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
#include <ntddk.h>
#include <storport.h>
#include <ntstrsafe.h>
#include <stdlib.h>

#include <version.h>
#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <emulated_interface.h>

#include "adapter.h"
#include "driver.h"
#include "registry.h"
#include "target.h"
#include "srbext.h"
#include "thread.h"
#include "buffer.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

#define MAXNAMELEN  128

#define ADAPTER_SIGNATURE   'odfX'

struct _XENVBD_ADAPTER {
    ULONG                       Signature;
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
    PXENVBD_TARGET                 Targets[XENVBD_MAX_TARGETS];

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
__AdapterSetDevicePowerState(
    __in PXENVBD_ADAPTER                 Adapter,
    __in DEVICE_POWER_STATE          State
    )
{
    KIRQL       Irql;
    BOOLEAN     Changed = FALSE;

    KeAcquireSpinLock(&Adapter->Lock, &Irql);

    if (Adapter->DevicePower != State) {
        Verbose("POWER %s to %s\n", PowerDeviceStateName(Adapter->DevicePower), PowerDeviceStateName(State));
        Changed = TRUE;
        Adapter->DevicePower = State;
    }

    KeReleaseSpinLock(&Adapter->Lock, Irql);

    return Changed;
}

static FORCEINLINE DEVICE_POWER_STATE
__AdapterGetDevicePowerState(
    __in PXENVBD_ADAPTER                Adapter
    )
{
    KIRQL               Irql;
    DEVICE_POWER_STATE  State;

    KeAcquireSpinLock(&Adapter->Lock, &Irql);
    State = Adapter->DevicePower;
    KeReleaseSpinLock(&Adapter->Lock, Irql);

    return State;
}

__checkReturn
static FORCEINLINE PXENVBD_TARGET
__AdapterGetTargetAlways(
    __in PXENVBD_ADAPTER                 Adapter,
    __in ULONG                       TargetId,
    __in PCHAR                       Caller
    )
{
    PXENVBD_TARGET Target;
    KIRQL       Irql;

    ASSERT3U(TargetId, <, XENVBD_MAX_TARGETS);

    KeAcquireSpinLock(&Adapter->TargetLock, &Irql);
    Target = Adapter->Targets[TargetId];
    if (Target) {
        __TargetReference(Target, Caller);
    }
    KeReleaseSpinLock(&Adapter->TargetLock, Irql);

    return Target;
}

__checkReturn
static FORCEINLINE PXENVBD_TARGET
___AdapterGetTarget(
    __in PXENVBD_ADAPTER                 Adapter,
    __in ULONG                       TargetId,
    __in PCHAR                       Caller
    )
{
    PXENVBD_TARGET Target = NULL;
    KIRQL       Irql;

    ASSERT3U(TargetId, <, XENVBD_MAX_TARGETS);

    KeAcquireSpinLock(&Adapter->TargetLock, &Irql);
    if (Adapter->Targets[TargetId] &&
        __TargetReference(Adapter->Targets[TargetId], Caller) > 0) {
        Target = Adapter->Targets[TargetId];
    }
    KeReleaseSpinLock(&Adapter->TargetLock, Irql);

    return Target;
}
#define __AdapterGetTarget(f, t) ___AdapterGetTarget(f, t, __FUNCTION__)

BOOLEAN
AdapterLinkTarget(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PXENVBD_TARGET                 Target
    )
{
    KIRQL       Irql;
    PXENVBD_TARGET Current;
    BOOLEAN     Result = FALSE;
    ULONG       TargetId = TargetGetTargetId(Target);

    KeAcquireSpinLock(&Adapter->TargetLock, &Irql);
    Current = Adapter->Targets[TargetId];
    if (Adapter->Targets[TargetId] == NULL) {
        Adapter->Targets[TargetId] = Target;
        Result = TRUE;
    }
    KeReleaseSpinLock(&Adapter->TargetLock, Irql);

    if (!Result) {
        Warning("Target[%d] : Current 0x%p, New 0x%p\n", TargetId, Current, Target);
    }
    return Result;
}
BOOLEAN
AdapterUnlinkTarget(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PXENVBD_TARGET                 Target
    )
{
    KIRQL       Irql;
    PXENVBD_TARGET Current;
    BOOLEAN     Result = FALSE;
    ULONG       TargetId = TargetGetTargetId(Target);

    KeAcquireSpinLock(&Adapter->TargetLock, &Irql);
    Current = Adapter->Targets[TargetId];
    if (Adapter->Targets[TargetId] == Target) {
        Adapter->Targets[TargetId] = NULL;
        Result = TRUE;
    }
    KeReleaseSpinLock(&Adapter->TargetLock, Irql);

    if (!Result) {
        Warning("Target[%d] : Current 0x%p, Expected 0x%p\n", TargetId, Current, Target);
    }
    return Result;
}

//=============================================================================
// QueryInterface

__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
AdapterQueryInterface(
    IN  PXENVBD_ADAPTER     Adapter,
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
                                       Adapter->LowerDeviceObject,
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

    status = IoCallDriver(Adapter->LowerDeviceObject, Irp);
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
    _Adapter,                                                                               \
    _ProviderName,                                                                      \
    _InterfaceName,                                                                     \
    _Interface,                                                                         \
    _Size,                                                                              \
    _Optional)                                                                          \
    AdapterQueryInterface((_Adapter),                                                           \
                      &GUID_ ## _ProviderName ## _ ## _InterfaceName ## _INTERFACE,     \
                      _ProviderName ## _ ## _InterfaceName ## _INTERFACE_VERSION_MAX,   \
                      (_Interface),                                                     \
                      (_Size),                                                          \
                      (_Optional))

//=============================================================================
// Debug

static DECLSPEC_NOINLINE VOID
AdapterDebugCallback(
    __in PVOID                       Context,
    __in BOOLEAN                     Crashing
    )
{
    PXENVBD_ADAPTER     Adapter = Context;
    ULONG           TargetId;

    if (Adapter == NULL || Adapter->DebugCallback == NULL)
        return;

    XENBUS_DEBUG(Printf, &Adapter->Debug,
                 "ADAPTER: Version: %d.%d.%d.%d (%d/%d/%d)\n",
                 MAJOR_VERSION, MINOR_VERSION, MICRO_VERSION, BUILD_NUMBER,
                 DAY, MONTH, YEAR);
    XENBUS_DEBUG(Printf, &Adapter->Debug,
                 "ADAPTER: Adapter: 0x%p %s\n",
                 Context,
                 Crashing ? "CRASHING" : "");
    XENBUS_DEBUG(Printf, &Adapter->Debug,
                 "ADAPTER: DevObj 0x%p LowerDevObj 0x%p PhysDevObj 0x%p\n",
                 Adapter->DeviceObject,
                 Adapter->LowerDeviceObject,
                 Adapter->PhysicalDeviceObject);
    XENBUS_DEBUG(Printf, &Adapter->Debug,
                 "ADAPTER: DevicePowerState: %s\n",
                 PowerDeviceStateName(Adapter->DevicePower));
    XENBUS_DEBUG(Printf, &Adapter->Debug,
                 "ADAPTER: Enumerator      : %s (0x%p)\n",
                 AdapterEnum(Adapter), Adapter->Enumerator.Buffer);
    XENBUS_DEBUG(Printf, &Adapter->Debug,
                 "ADAPTER: Srbs            : %d / %d (%d Total)\n",
                 Adapter->CurrentSrbs, Adapter->MaximumSrbs, Adapter->TotalSrbs);

    BufferDebugCallback(&Adapter->Debug);

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        // no need to use __AdapterGetTarget (which is locked at DISPATCH) as called at HIGH_LEVEL
        PXENVBD_TARGET Target = Adapter->Targets[TargetId];
        if (Target == NULL)
            continue;

        XENBUS_DEBUG(Printf, &Adapter->Debug,
                     "ADAPTER: ====> Target[%-3d]    : 0x%p\n",
                     TargetId, Target);

        // call Target's debug callback directly
        TargetDebugCallback(Target, &Adapter->Debug);

        XENBUS_DEBUG(Printf, &Adapter->Debug,
                     "ADAPTER: <==== Target[%-3d]    : 0x%p\n",
                     TargetId, Target);
    }

    Adapter->MaximumSrbs = Adapter->CurrentSrbs;
    Adapter->TotalSrbs = 0;
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

static FORCEINLINE BOOLEAN
__AdapterHiddenTarget(
    IN  PXENVBD_ADAPTER     Adapter,
    IN  PCHAR               DeviceId,
    OUT PXENVBD_DEVICE_TYPE DeviceType
    )
{
    NTSTATUS    status;
    PCHAR       Buffer;
    CHAR        Path[sizeof("device/vbd/XXXXXXXX")];
    ULONG       Value;

    *DeviceType = XENVBD_DEVICE_TYPE_UNKNOWN;
    status = RtlStringCbPrintfA(Path,
                                sizeof(Path),
                                "device/vbd/%s",
                                DeviceId);
    if (!NT_SUCCESS(status))
        goto fail;

    // Ejected?
    status = XENBUS_STORE(Read, &Adapter->Store, NULL, Path, "ejected", &Buffer);
    if (NT_SUCCESS(status)) {
        Value = strtoul(Buffer, NULL, 10);
        XENBUS_STORE(Free, &Adapter->Store, Buffer);

        if (Value)
            goto ignore;
    }

    // Not Disk?
    status = XENBUS_STORE(Read, &Adapter->Store, NULL, Path, "device-type", &Buffer);
    if (!NT_SUCCESS(status))
        goto ignore;
    *DeviceType = __DeviceType(Buffer);
    XENBUS_STORE(Free, &Adapter->Store, Buffer);

    switch (*DeviceType) {
    case XENVBD_DEVICE_TYPE_DISK:
        break;
    default:
        goto ignore;
    }

    // Try to Create
    return FALSE;

fail:
    Error("Fail\n");
    return TRUE;

ignore:
    return TRUE;
}
__checkReturn
static FORCEINLINE BOOLEAN
__AdapterIsTargetUnplugged(
    __in PXENVBD_ADAPTER                 Adapter,
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
    if (Adapter->Emulated.Interface.Context == NULL) {
        Warning("Target[%d] : (%s/%s) Emulated NOT_KNOWN (assumed PRESENT)\n",
                            Target, Enumerator, Device);
        return FALSE;
    }

    // Ask XenFilt if Ctrlr(0), Target(Target), Lun(0) is present
    if (XENFILT_EMULATED(IsDiskPresent, &Adapter->Emulated, 0, Target, 0)) {
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
__AdapterEnumerate(
    __in    PXENVBD_ADAPTER     Adapter,
    __in    PANSI_STRING    Devices,
    __out   PBOOLEAN        NeedInvalidate,
    __out   PBOOLEAN        NeedReboot
    )
{
    ULONG               TargetId;
    PANSI_STRING        Device;
    ULONG               Index;
    PXENVBD_TARGET         Target;

    *NeedInvalidate = FALSE;
    *NeedReboot = FALSE;

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        BOOLEAN     Missing = TRUE;

        Target = __AdapterGetTarget(Adapter, TargetId);
        if (Target == NULL)
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

        if (Missing && !TargetIsMissing(Target)) {
            TargetSetMissing(Target, "Device Disappeared");
            if (TargetGetDevicePnpState(Target) == Present)
                TargetSetDevicePnpState(Target, Deleted);
            else
                *NeedInvalidate = TRUE;
        }

        if (TargetGetDevicePnpState(Target) == Deleted) {
            TargetDereference(Target);
            TargetDestroy(Target);
        } else {
            TargetDereference(Target);
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

        Target = __AdapterGetTarget(Adapter, TargetId);
        if (Target) {
            TargetDereference(Target);
            continue;
        }

        if (__AdapterHiddenTarget(Adapter, Device->Buffer, &DeviceType)) {
            continue;
        }

        if (!__AdapterIsTargetUnplugged(Adapter,
                                AdapterEnum(Adapter),
                                Device->Buffer,
                                TargetId)) {
            *NeedReboot = TRUE;
            continue;
        }

        if (TargetCreate(Adapter,
                      Device->Buffer,
                      TargetId,
                      DeviceType)) {
            *NeedInvalidate = TRUE;
        }
    }
}

static FORCEINLINE PANSI_STRING
__AdapterMultiSzToAnsi(
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

    Ansi = __AllocatePoolWithTag(NonPagedPool,
                                 sizeof (ANSI_STRING) * (Count + 1),
                                 ADAPTER_SIGNATURE);

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __AllocatePoolWithTag(NonPagedPool,
                                                   Ansi[Index].MaximumLength,
                                                   ADAPTER_SIGNATURE);

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
            __FreePoolWithTag(Ansi[Index].Buffer, ADAPTER_SIGNATURE);

    __FreePoolWithTag(Ansi, ADAPTER_SIGNATURE);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static FORCEINLINE PANSI_STRING
__AdapterMultiSzToUpcaseAnsi(
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

    Ansi = __AllocatePoolWithTag(NonPagedPool,
                                 sizeof (ANSI_STRING) * (Count + 1),
                                 ADAPTER_SIGNATURE);

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __AllocatePoolWithTag(NonPagedPool,
                                                   Ansi[Index].MaximumLength,
                                                   ADAPTER_SIGNATURE);

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
            __FreePoolWithTag(Ansi[Index].Buffer, ADAPTER_SIGNATURE);

    __FreePoolWithTag(Ansi, ADAPTER_SIGNATURE);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static FORCEINLINE VOID
__AdapterFreeAnsi(
    IN  PANSI_STRING    Ansi
    )
{
    ULONG               Index;

    for (Index = 0; Ansi[Index].Buffer != NULL; Index++)
            __FreePoolWithTag(Ansi[Index].Buffer, ADAPTER_SIGNATURE);

    __FreePoolWithTag(Ansi, ADAPTER_SIGNATURE);
}

static DECLSPEC_NOINLINE VOID
AdapterScanTargets(
    __in    PXENVBD_ADAPTER Adapter
    )
{
    NTSTATUS        Status;
    PCHAR           Buffer;
    PANSI_STRING    Devices;
    BOOLEAN         NeedInvalidate;
    BOOLEAN         NeedReboot;

    Status = XENBUS_STORE(Directory, &Adapter->Store, NULL, "device", AdapterEnum(Adapter), &Buffer);
    if (!NT_SUCCESS(Status))
        return;

    Devices = __AdapterMultiSzToAnsi(Buffer);
    XENBUS_STORE(Free, &Adapter->Store, Buffer);

    if (Devices == NULL)
        return;

    __AdapterEnumerate(Adapter, Devices, &NeedInvalidate, &NeedReboot);
    __AdapterFreeAnsi(Devices);

    if (NeedInvalidate) {
        StorPortNotification(BusChangeDetected, Adapter, 0);
    }
    if (NeedReboot) {
        DriverRequestReboot();
    }
}

__checkReturn
static DECLSPEC_NOINLINE NTSTATUS
AdapterScan(
    __in PXENVBD_THREAD              Thread,
    __in PVOID                       Context
    )
{
    PXENVBD_ADAPTER     Adapter = Context;
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

        if (__AdapterGetDevicePowerState(Adapter) == PowerDeviceD0)
            AdapterScanTargets(Adapter);

        KeSetEvent(&Adapter->ScanEvent, IO_NO_INCREMENT, FALSE);
    }
    KeSetEvent(&Adapter->ScanEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

//=============================================================================
// Initialize, Start, Stop

__drv_requiresIRQL(PASSIVE_LEVEL)
static FORCEINLINE NTSTATUS
__AdapterQueryInterfaces(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    NTSTATUS        Status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    // Get STORE Interface
    Status = QUERY_INTERFACE(Adapter,
                             XENBUS,
                             STORE,
                             (PINTERFACE)&Adapter->Store,
                             sizeof (Adapter->Store),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // Get EVTCHN Interface
    Status = QUERY_INTERFACE(Adapter,
                             XENBUS,
                             EVTCHN,
                             (PINTERFACE)&Adapter->Evtchn,
                             sizeof (Adapter->Evtchn),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Get GNTTAB Interface
    Status = QUERY_INTERFACE(Adapter,
                             XENBUS,
                             GNTTAB,
                             (PINTERFACE)&Adapter->Gnttab,
                             sizeof (Adapter->Gnttab),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail3;

    // Get SUSPEND Interface
    Status = QUERY_INTERFACE(Adapter,
                             XENBUS,
                             SUSPEND,
                             (PINTERFACE)&Adapter->Suspend,
                             sizeof (Adapter->Suspend),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail4;

    // Get DEBUG Interface
    Status = QUERY_INTERFACE(Adapter,
                             XENBUS,
                             DEBUG,
                             (PINTERFACE)&Adapter->Debug,
                             sizeof (Adapter->Debug),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail5;

    // Get UNPLUG Interface
    Status = QUERY_INTERFACE(Adapter,
                             XENBUS,
                             UNPLUG,
                             (PINTERFACE)&Adapter->Unplug,
                             sizeof (Adapter->Unplug),
                             FALSE);
    if (!NT_SUCCESS(Status))
        goto fail6;

    // Get EMULATED Interface (optional)
    Status = QUERY_INTERFACE(Adapter,
                             XENFILT,
                             EMULATED,
                             (PINTERFACE)&Adapter->Emulated,
                             sizeof (Adapter->Emulated),
                             TRUE);
    if (!NT_SUCCESS(Status))
        goto fail7;

    return STATUS_SUCCESS;

fail7:
    RtlZeroMemory(&Adapter->Unplug,
                  sizeof (XENBUS_UNPLUG_INTERFACE));
fail6:
    RtlZeroMemory(&Adapter->Debug,
                  sizeof (XENBUS_DEBUG_INTERFACE));
fail5:
    RtlZeroMemory(&Adapter->Suspend,
                  sizeof (XENBUS_SUSPEND_INTERFACE));
fail4:
    RtlZeroMemory(&Adapter->Gnttab,
                  sizeof (XENBUS_GNTTAB_INTERFACE));
fail3:
    RtlZeroMemory(&Adapter->Evtchn,
                  sizeof (XENBUS_EVTCHN_INTERFACE));
fail2:
    RtlZeroMemory(&Adapter->Store,
                  sizeof (XENBUS_STORE_INTERFACE));
fail1:
    return Status;
}
static FORCEINLINE VOID
__AdapterZeroInterfaces(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    RtlZeroMemory(&Adapter->Emulated,
                  sizeof (XENFILT_EMULATED_INTERFACE));
    RtlZeroMemory(&Adapter->Unplug,
                  sizeof (XENBUS_UNPLUG_INTERFACE));
    RtlZeroMemory(&Adapter->Debug,
                  sizeof (XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Adapter->Suspend,
                  sizeof (XENBUS_SUSPEND_INTERFACE));
    RtlZeroMemory(&Adapter->Gnttab,
                  sizeof (XENBUS_GNTTAB_INTERFACE));
    RtlZeroMemory(&Adapter->Evtchn,
                  sizeof (XENBUS_EVTCHN_INTERFACE));
    RtlZeroMemory(&Adapter->Store,
                  sizeof (XENBUS_STORE_INTERFACE));
}
static FORCEINLINE NTSTATUS
__AdapterAcquire(
    __in PXENVBD_ADAPTER    Adapter
    )
{
    NTSTATUS            status;

    if (Adapter->Emulated.Interface.Context) {
        status = XENFILT_EMULATED(Acquire, &Adapter->Emulated);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    status = XENBUS_SUSPEND(Acquire, &Adapter->Suspend);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_DEBUG(Acquire, &Adapter->Debug);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_GNTTAB(Acquire, &Adapter->Gnttab);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_EVTCHN(Acquire, &Adapter->Evtchn);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_STORE(Acquire, &Adapter->Store);
    if (!NT_SUCCESS(status))
        goto fail6;

    return STATUS_SUCCESS;

fail6:
    XENBUS_EVTCHN(Release, &Adapter->Evtchn);
fail5:
    XENBUS_GNTTAB(Release, &Adapter->Gnttab);
fail4:
    XENBUS_DEBUG(Release, &Adapter->Debug);
fail3:
    XENBUS_SUSPEND(Release, &Adapter->Suspend);
fail2:
    if (Adapter->Emulated.Interface.Context)
        XENFILT_EMULATED(Release, &Adapter->Emulated);
fail1:
    return status;
}
static FORCEINLINE VOID
__AdapterRelease(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    XENBUS_STORE(Release, &Adapter->Store);
    XENBUS_EVTCHN(Release, &Adapter->Evtchn);
    XENBUS_GNTTAB(Release, &Adapter->Gnttab);
    XENBUS_DEBUG(Release, &Adapter->Debug);
    XENBUS_SUSPEND(Release, &Adapter->Suspend);
    if (Adapter->Emulated.Interface.Context)
        XENFILT_EMULATED(Release, &Adapter->Emulated);
}

static FORCEINLINE BOOLEAN
__AdapterMatchDistribution(
    IN  PXENVBD_ADAPTER Adapter,
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

    UNREFERENCED_PARAMETER(Adapter);

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
AdapterClearDistribution(
    IN  PXENVBD_ADAPTER Adapter
    )
{
    PCHAR           Buffer;
    PANSI_STRING    Distributions;
    ULONG           Index;
    NTSTATUS        status;

    Trace("====>\n");

    status = XENBUS_STORE(Directory,
                          &Adapter->Store,
                          NULL,
                          NULL,
                          "drivers",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Distributions = __AdapterMultiSzToUpcaseAnsi(Buffer);

        XENBUS_STORE(Free,
                     &Adapter->Store,
                     Buffer);
    } else {
        Distributions = NULL;
    }

    if (Distributions == NULL)
        goto done;

    for (Index = 0; Distributions[Index].Buffer != NULL; Index++) {
        PANSI_STRING    Distribution = &Distributions[Index];

        status = XENBUS_STORE(Read,
                              &Adapter->Store,
                              NULL,
                              "drivers",
                              Distribution->Buffer,
                              &Buffer);
        if (!NT_SUCCESS(status))
            continue;

        if (__AdapterMatchDistribution(Adapter, Buffer))
            (VOID) XENBUS_STORE(Remove,
                                &Adapter->Store,
                                NULL,
                                "drivers",
                                Distribution->Buffer);

        XENBUS_STORE(Free,
                     &Adapter->Store,
                     Buffer);
    }

    __AdapterFreeAnsi(Distributions);

done:
    Trace("<====\n");
}

#define MAXIMUM_INDEX   255

static NTSTATUS
AdapterSetDistribution(
    IN  PXENVBD_ADAPTER Adapter
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
                              &Adapter->Store,
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
                     &Adapter->Store,
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
                        &Adapter->Store,
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
__AdapterD3ToD0(
    __in PXENVBD_ADAPTER    Adapter
    )
{
    NTSTATUS            Status;

    Trace("=====>\n");

    (VOID) AdapterSetDistribution(Adapter);

    ASSERT3P(Adapter->ScanWatch, ==, NULL);
    Status = XENBUS_STORE(WatchAdd,
                          &Adapter->Store,
                          "device",
                          AdapterEnum(Adapter),
                          ThreadGetEvent(Adapter->ScanThread),
                          &Adapter->ScanWatch);
    if (!NT_SUCCESS(Status))
        goto fail1;

    (VOID) XENBUS_STORE(Printf,
                        &Adapter->Store,
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
__AdapterD0ToD3(
    __in PXENVBD_ADAPTER    Adapter
    )
{
    Trace("=====>\n");

    (VOID) XENBUS_STORE(Remove,
                        &Adapter->Store,
                        NULL,
                        "feature/hotplug",
                        "vbd");

    (VOID) XENBUS_STORE(WatchRemove,
                        &Adapter->Store,
                        Adapter->ScanWatch);
    Adapter->ScanWatch = NULL;

    AdapterClearDistribution(Adapter);

    Trace("<=====\n");
}

__drv_requiresIRQL(DISPATCH_LEVEL)
static VOID
AdapterSuspendLateCallback(
    __in PVOID                   Argument
    )
{
    PXENVBD_ADAPTER     Adapter = Argument;
    NTSTATUS        Status;

    Verbose("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    __AdapterD0ToD3(Adapter);

    Status = __AdapterD3ToD0(Adapter);
    ASSERT(NT_SUCCESS(Status));
}

static NTSTATUS
AdapterD3ToD0(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    NTSTATUS    Status;
    ULONG       TargetId;

    if (!__AdapterSetDevicePowerState(Adapter, PowerDeviceD0))
        return STATUS_SUCCESS;

    Trace("=====> (%d)\n", KeGetCurrentIrql());
    Verbose("D3->D0\n");

    // Get Interfaces
    Status = __AdapterAcquire(Adapter);
    if (!NT_SUCCESS(Status))
        goto fail1;

    // register debug callback
    ASSERT3P(Adapter->DebugCallback, ==, NULL);
    Status = XENBUS_DEBUG(Register,
                          &Adapter->Debug,
                          __MODULE__,
                          AdapterDebugCallback,
                          Adapter,
                          &Adapter->DebugCallback);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // Power UP any TARGETs
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = __AdapterGetTarget(Adapter, TargetId);
        if (Target) {
            Status = TargetD3ToD0(Target);
            TargetDereference(Target);

            if (!NT_SUCCESS(Status))
                goto fail3;
        }
    }

    Status = __AdapterD3ToD0(Adapter);
    if (!NT_SUCCESS(Status))
        goto fail4;

    // register suspend callback to re-register the watch
    ASSERT3P(Adapter->SuspendCallback, ==, NULL);
    Status = XENBUS_SUSPEND(Register,
                            &Adapter->Suspend,
                            SUSPEND_CALLBACK_LATE,
                            AdapterSuspendLateCallback,
                            Adapter,
                            &Adapter->SuspendCallback);
    if (!NT_SUCCESS(Status))
        goto fail5;

    Trace("<===== (%d)\n", KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail5:
    Error("Fail5\n");

    __AdapterD0ToD3(Adapter);

fail4:
    Error("Fail4\n");

fail3:
    Error("Fail3\n");

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = __AdapterGetTarget(Adapter, TargetId);
        if (Target) {
            TargetD0ToD3(Target);
            TargetDereference(Target);
        }
    }

    XENBUS_DEBUG(Deregister, &Adapter->Debug, Adapter->DebugCallback);
    Adapter->DebugCallback = NULL;

fail2:
    Error("Fail2\n");

    __AdapterRelease(Adapter);

fail1:
    Error("Fail1 (%08x)\n", Status);

    __AdapterSetDevicePowerState(Adapter, PowerDeviceD3);
    return Status;
}

static VOID
AdapterD0ToD3(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    ULONG       TargetId;

    if (!__AdapterSetDevicePowerState(Adapter, PowerDeviceD3))
        return;

    Trace("=====> (%d)\n", KeGetCurrentIrql());
    Verbose("D0->D3\n");

    // remove suspend callback
    XENBUS_SUSPEND(Deregister, &Adapter->Suspend, Adapter->SuspendCallback);
    Adapter->SuspendCallback = NULL;

    __AdapterD0ToD3(Adapter);

    // Power DOWN any TARGETs
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = __AdapterGetTarget(Adapter, TargetId);
        if (Target) {
            TargetD0ToD3(Target);
            TargetDereference(Target);
        }
    }

    // free debug callback
    if (Adapter->DebugCallback != NULL) {
        XENBUS_DEBUG(Deregister, &Adapter->Debug, Adapter->DebugCallback);
        Adapter->DebugCallback = NULL;
    }

    // Release Interfaces
    __AdapterRelease(Adapter);

    Trace("<===== (%d)\n", KeGetCurrentIrql());
}

__checkReturn
static DECLSPEC_NOINLINE NTSTATUS
AdapterDevicePower(
    __in PXENVBD_THREAD             Thread,
    __in PVOID                      Context
    )
{
    PXENVBD_ADAPTER     Adapter = Context;

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  Stack;
        DEVICE_POWER_STATE  DeviceState;
        POWER_ACTION        Action;
        NTSTATUS            Status;

        if (!ThreadWait(Thread))
            break;

        // must have a pended DevicePowerIrp
        ASSERT3P(Adapter->DevicePowerIrp, !=, NULL);

        Irp = Adapter->DevicePowerIrp;
        Adapter->DevicePowerIrp = NULL;

        Stack = IoGetCurrentIrpStackLocation(Irp);
        DeviceState = Stack->Parameters.Power.State.DeviceState;
        Action = Stack->Parameters.Power.ShutdownType;

        switch (Stack->MinorFunction) {
        case IRP_MN_SET_POWER:
            switch (DeviceState) {
            case PowerDeviceD0:
                Verbose("ADAPTER:PowerDeviceD0\n");
                AdapterD3ToD0(Adapter);
                break;

            case PowerDeviceD3:
                Verbose("ADAPTER:PowerDeviceD3 (%s)\n", PowerActionName(Action));
                AdapterD0ToD3(Adapter);
                break;

            default:
                break;
            }
            break;
        case IRP_MN_QUERY_POWER:
        default:
            break;
        }
        Status = DriverDispatchPower(Adapter->DeviceObject, Irp);
        if (!NT_SUCCESS(Status)) {
            Warning("StorPort failed PowerIRP with %08x\n", Status);
        }
    }

    return STATUS_SUCCESS;
}

__checkReturn
__drv_requiresIRQL(PASSIVE_LEVEL)
static NTSTATUS
__AdapterInitialize(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    ULONG       StorStatus;
    NTSTATUS    Status;

    Trace("=====> (%d)\n", KeGetCurrentIrql());

    ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    // initialize the memory
    Adapter->DevicePower = PowerDeviceD3;
    KeInitializeSpinLock(&Adapter->TargetLock);
    KeInitializeSpinLock(&Adapter->Lock);
    KeInitializeEvent(&Adapter->ScanEvent, SynchronizationEvent, FALSE);

    Adapter->Signature = ADAPTER_SIGNATURE;

    StorStatus = StorPortGetDeviceObjects(Adapter,
                                          &Adapter->DeviceObject,
                                          &Adapter->PhysicalDeviceObject,
                                          &Adapter->LowerDeviceObject);
    Status = STATUS_UNSUCCESSFUL;
    if (StorStatus != STOR_STATUS_SUCCESS) {
        Error("StorPortGetDeviceObjects() (%x:%s)\n", StorStatus, StorStatusName(StorStatus));
        goto fail1;
    }

    // get interfaces
    Status = __AdapterQueryInterfaces(Adapter);
    if (!NT_SUCCESS(Status))
        goto fail2;

    // start enum thread
    Status = ThreadCreate(AdapterScan, Adapter, &Adapter->ScanThread);
    if (!NT_SUCCESS(Status))
        goto fail3;

    Status = ThreadCreate(AdapterDevicePower, Adapter, &Adapter->DevicePowerThread);
    if (!NT_SUCCESS(Status))
        goto fail4;

    Trace("<===== (%d)\n", KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");
    ThreadAlert(Adapter->ScanThread);
    ThreadJoin(Adapter->ScanThread);
    Adapter->ScanThread = NULL;
fail3:
    Error("fail3\n");
    __AdapterZeroInterfaces(Adapter);
fail2:
    Error("fail2\n");
    Adapter->DeviceObject = NULL;
    Adapter->PhysicalDeviceObject = NULL;
    Adapter->LowerDeviceObject = NULL;
fail1:
    Error("fail1 (%08x)\n", Status);
    return Status;
}
__drv_maxIRQL(PASSIVE_LEVEL)
static VOID
__AdapterTerminate(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    ULONG   TargetId;

    Trace("=====> (%d)\n", KeGetCurrentIrql());

    ASSERT3U(Adapter->DevicePower, ==, PowerDeviceD3);

    // stop device power thread
    ThreadAlert(Adapter->DevicePowerThread);
    ThreadJoin(Adapter->DevicePowerThread);
    Adapter->DevicePowerThread = NULL;

    // stop enum thread
    ThreadAlert(Adapter->ScanThread);
    ThreadJoin(Adapter->ScanThread);
    Adapter->ScanThread = NULL;

    // clear device objects
    Adapter->DeviceObject = NULL;
    Adapter->PhysicalDeviceObject = NULL;
    Adapter->LowerDeviceObject = NULL;

    // delete targets
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = __AdapterGetTargetAlways(Adapter, TargetId, __FUNCTION__);
        if (Target) {
            // Target may not be in Deleted state yet, force it as Adapter is terminating
            if (TargetGetDevicePnpState(Target) != Deleted)
                TargetSetDevicePnpState(Target, Deleted);
            // update missing (for debug output more than anything else
            TargetSetMissing(Target, "AdapterTerminate");
            // drop ref-count acquired in __AdapterGetTarget *before* destroying Target
            TargetDereference(Target);
            TargetDestroy(Target);
        }
    }

    // cleanup memory
    ASSERT3U(Adapter->DevicePower, ==, PowerDeviceD3);
    ASSERT3P(Adapter->DebugCallback, ==, NULL);
    ASSERT3P(Adapter->SuspendCallback, ==, NULL);

    Adapter->Signature = 0;
    Adapter->DevicePower = 0;
    Adapter->CurrentSrbs = Adapter->MaximumSrbs = Adapter->TotalSrbs = 0;
    RtlZeroMemory(&Adapter->Enumerator, sizeof(ANSI_STRING));
    RtlZeroMemory(&Adapter->TargetLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Adapter->Lock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Adapter->ScanEvent, sizeof(KEVENT));
    __AdapterZeroInterfaces(Adapter);

    ASSERT(IsZeroMemory(Adapter, sizeof(XENVBD_ADAPTER)));
    Trace("<===== (%d)\n", KeGetCurrentIrql());
}
//=============================================================================
// Query Methods
__checkReturn
FORCEINLINE PDEVICE_OBJECT
AdapterGetDeviceObject(
    __in PXENVBD_ADAPTER                 Adapter
    )
{
    if (Adapter)
        return Adapter->DeviceObject;
    return NULL;
}

FORCEINLINE ULONG
AdapterSizeofXenvbdAdapter(
    )
{
    return (ULONG)sizeof(XENVBD_ADAPTER);
}

FORCEINLINE PCHAR
AdapterEnum(
    __in PXENVBD_ADAPTER                 Adapter
    )
{
    if (Adapter->Enumerator.Buffer)
        return Adapter->Enumerator.Buffer;
    else
        return "vbd";
}

//=============================================================================
// SRB Methods
FORCEINLINE VOID
AdapterStartSrb(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    LONG    Value;

    UNREFERENCED_PARAMETER(Srb);

    Value = InterlockedIncrement(&Adapter->CurrentSrbs);
    if (Value > Adapter->MaximumSrbs)
        Adapter->MaximumSrbs = Value;
    InterlockedIncrement(&Adapter->TotalSrbs);
}

FORCEINLINE VOID
AdapterCompleteSrb(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    ASSERT3U(Srb->SrbStatus, !=, SRB_STATUS_PENDING);

    InterlockedDecrement(&Adapter->CurrentSrbs);

    StorPortNotification(RequestComplete, Adapter, Srb);
}

//=============================================================================
// StorPort Methods
BOOLEAN
AdapterResetBus(
    __in PXENVBD_ADAPTER                 Adapter
    )
{
    ULONG           TargetId;

    Verbose("====>\n");
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = __AdapterGetTarget(Adapter, TargetId);
        if (Target) {
            TargetReset(Target);
            TargetDereference(Target);
        }
    }
    Verbose("<====\n");

    return TRUE;
}

static VOID
AdapterUnplugRequest(
    IN  PXENVBD_ADAPTER Adapter,
    IN  BOOLEAN     Make
    )
{
    NTSTATUS        status;

    status = XENBUS_UNPLUG(Acquire, &Adapter->Unplug);
    if (!NT_SUCCESS(status))
        return;

    XENBUS_UNPLUG(Request,
                  &Adapter->Unplug,
                  XENBUS_UNPLUG_DEVICE_TYPE_DISKS,
                  Make);

    XENBUS_UNPLUG(Release, &Adapter->Unplug);
}

ULONG
AdapterFindAdapter(
    __in PXENVBD_ADAPTER                 Adapter,
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
    if (Adapter->Signature == ADAPTER_SIGNATURE) {
        Verbose("ADAPTER already initalized (0x%p)\n", Adapter);
        return SP_RETURN_FOUND;
    }

    // We need to do this to avoid an assertion in a checked kernel
    (VOID) StorPortGetUncachedExtension(Adapter, ConfigInfo, PAGE_SIZE);

    if (!NT_SUCCESS(__AdapterInitialize(Adapter)))
        return SP_RETURN_ERROR;

    AdapterUnplugRequest(Adapter, TRUE);

    if (!NT_SUCCESS(AdapterD3ToD0(Adapter)))
        return SP_RETURN_ERROR;

    return SP_RETURN_FOUND;
}

static FORCEINLINE VOID
__AdapterSrbPnp(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_PNP_REQUEST_BLOCK     Srb
    )
{
    if (!(Srb->SrbPnPFlags & SRB_PNP_FLAGS_ADAPTER_REQUEST)) {
        PXENVBD_TARGET     Target;

        Target = __AdapterGetTarget(Adapter, Srb->TargetId);
        if (Target) {
            TargetSrbPnp(Target, Srb);
            TargetDereference(Target);
        }
    }
}

BOOLEAN
AdapterBuildIo(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    InitSrbExt(Srb);

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:
    case SRB_FUNCTION_RESET_DEVICE:
    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_SHUTDOWN:
        AdapterStartSrb(Adapter, Srb);
        return TRUE;

        // dont pass to StartIo
    case SRB_FUNCTION_PNP:
        __AdapterSrbPnp(Adapter, (PSCSI_PNP_REQUEST_BLOCK)Srb);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    case SRB_FUNCTION_ABORT_COMMAND:
        Srb->SrbStatus = SRB_STATUS_ABORT_FAILED;
        break;
    case SRB_FUNCTION_RESET_BUS:
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        AdapterResetBus(Adapter);
        break;

    default:
        break;
    }

    StorPortNotification(RequestComplete, Adapter, Srb);
    return FALSE;
}

BOOLEAN
AdapterStartIo(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_REQUEST_BLOCK         Srb
    )
{
    PXENVBD_TARGET Target;
    BOOLEAN     CompleteSrb = TRUE;

    Target = __AdapterGetTarget(Adapter, Srb->TargetId);
    if (Target) {
        CompleteSrb = TargetStartIo(Target, Srb);
        TargetDereference(Target);
    }

    if (CompleteSrb) {
        AdapterCompleteSrb(Adapter, Srb);
    }
    return TRUE;
}

static PXENVBD_TARGET
AdapterGetTargetFromDeviceObject(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PDEVICE_OBJECT              DeviceObject
    )
{
    ULONG           TargetId;

    ASSERT3P(DeviceObject, !=, NULL);

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = __AdapterGetTarget(Adapter, TargetId);
        if (Target) {
            if (TargetGetDeviceObject(Target) == DeviceObject)
                return Target;
            TargetDereference(Target);
        }
    }

    return NULL;
}

static PXENVBD_TARGET
AdapterMapDeviceObjectToTarget(
    __in PXENVBD_ADAPTER                Adapter,
    __in PDEVICE_OBJECT             DeviceObject
    )
{
    PXENVBD_TARGET                 Target;
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

    Target = __AdapterGetTarget(Adapter, TargetId);
    if (Target == NULL)
        goto fail5;

    TargetSetDeviceObject(Target, DeviceObject);
    ExFreePool(String);

    return Target;

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
AdapterForwardPnp(
    __in PXENVBD_ADAPTER                Adapter,
    __in PDEVICE_OBJECT             DeviceObject,
    __in PIRP                       Irp
    )
{
    PIO_STACK_LOCATION  Stack;
    PXENVBD_TARGET         Target;

    ASSERT3P(DeviceObject, !=, Adapter->DeviceObject);

    Target = AdapterGetTargetFromDeviceObject(Adapter, DeviceObject);
    if (Target != NULL) {
        return TargetDispatchPnp(Target, DeviceObject, Irp);
    }

    Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->MinorFunction == IRP_MN_QUERY_ID &&
        Stack->Parameters.QueryId.IdType == BusQueryDeviceID) {
        Target = AdapterMapDeviceObjectToTarget(Adapter, DeviceObject);
        if (Target != NULL) {
            return TargetDispatchPnp(Target, DeviceObject, Irp);
        }
    }

    return DriverDispatchPnp(DeviceObject, Irp);
}

__checkReturn
NTSTATUS
AdapterDispatchPnp(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    )
{
    PIO_STACK_LOCATION  Stack;

    ASSERT3P(DeviceObject, ==, Adapter->DeviceObject);

    Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->MinorFunction) {
    case IRP_MN_REMOVE_DEVICE:
        Verbose("ADAPTER:IRP_MN_REMOVE_DEVICE\n");
        AdapterD0ToD3(Adapter);
        AdapterUnplugRequest(Adapter, FALSE);
        __AdapterTerminate(Adapter);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        if (Stack->Parameters.QueryDeviceRelations.Type == BusRelations) {
            KeClearEvent(&Adapter->ScanEvent);
            ThreadWake(Adapter->ScanThread);

            Trace("waiting for scan thread\n");

            (VOID) KeWaitForSingleObject(&Adapter->ScanEvent,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
        }
        break;

    default:
        break;
    }

    return DriverDispatchPnp(DeviceObject, Irp);
}

__checkReturn
NTSTATUS
AdapterDispatchPower(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    )
{
    PIO_STACK_LOCATION  Stack;
    POWER_STATE_TYPE    PowerType;
    NTSTATUS            status;

    ASSERT3P(DeviceObject, ==, Adapter->DeviceObject);

    Stack = IoGetCurrentIrpStackLocation(Irp);
    PowerType = Stack->Parameters.Power.Type;

    switch (PowerType) {
    case DevicePowerState:
        if (Adapter->DevicePowerThread == NULL) {
            Verbose("DevicePower IRP before DevicePowerThread ready\n");
            status = DriverDispatchPower(DeviceObject, Irp);
            break;
        }

        IoMarkIrpPending(Irp);

        ASSERT3P(Adapter->DevicePowerIrp, ==, NULL);
        ASSERT3P(DeviceObject, ==, Adapter->DeviceObject);

        Adapter->DevicePowerIrp = Irp;
        ThreadWake(Adapter->DevicePowerThread);

        status = STATUS_PENDING;
        break;

    case SystemPowerState:
    default:
        status = DriverDispatchPower(DeviceObject, Irp);
        break;
    }

    return status;
}

PXENBUS_STORE_INTERFACE
AdapterAcquireStore(
    __in PXENVBD_ADAPTER    Adapter
    )
{
    NTSTATUS            status;

    status = XENBUS_STORE(Acquire, &Adapter->Store);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Adapter->Store;
}

PXENBUS_EVTCHN_INTERFACE
AdapterAcquireEvtchn(
    __in PXENVBD_ADAPTER    Adapter
    )
{
    NTSTATUS            status;

    status = XENBUS_EVTCHN(Acquire, &Adapter->Evtchn);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Adapter->Evtchn;
}

PXENBUS_GNTTAB_INTERFACE
AdapterAcquireGnttab(
    __in PXENVBD_ADAPTER    Adapter
    )
{
    NTSTATUS            status;

    status = XENBUS_GNTTAB(Acquire, &Adapter->Gnttab);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Adapter->Gnttab;
}

PXENBUS_DEBUG_INTERFACE
AdapterAcquireDebug(
    __in PXENVBD_ADAPTER    Adapter
    )
{
    NTSTATUS            status;

    status = XENBUS_DEBUG(Acquire, &Adapter->Debug);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Adapter->Debug;
}

PXENBUS_SUSPEND_INTERFACE
AdapterAcquireSuspend(
    __in PXENVBD_ADAPTER    Adapter
    )
{
    NTSTATUS            status;

    status = XENBUS_SUSPEND(Acquire, &Adapter->Suspend);
    if (!NT_SUCCESS(status))
        return NULL;

    return &Adapter->Suspend;
}
