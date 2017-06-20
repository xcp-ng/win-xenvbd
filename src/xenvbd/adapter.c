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
#include <unplug_interface.h>

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

#define XENVBD_MAX_QUEUE_DEPTH  254
#define MAXNAMELEN              128
#define ADAPTER_POOL_TAG        'adAX'

struct _XENVBD_ADAPTER {
    PDEVICE_OBJECT              DeviceObject;
    PDEVICE_OBJECT              LowerDeviceObject;
    PDEVICE_OBJECT              PhysicalDeviceObject;
    KSPIN_LOCK                  Lock;
    DEVICE_POWER_STATE          DevicePower;
    PXENVBD_THREAD              DevicePowerThread;
    PIRP                        DevicePowerIrp;

    XENBUS_EVTCHN_INTERFACE     EvtchnInterface;
    XENBUS_STORE_INTERFACE      StoreInterface;
    XENBUS_GNTTAB_INTERFACE     GnttabInterface;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    XENBUS_UNPLUG_INTERFACE     UnplugInterface;
    XENFILT_EMULATED_INTERFACE  EmulatedInterface;

    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallback;

    KSPIN_LOCK                  TargetLock;
    PXENVBD_TARGET              TargetList[XENVBD_MAX_TARGETS];
    PXENVBD_THREAD              ScanThread;
    KEVENT                      ScanEvent;
    PXENBUS_STORE_WATCH         ScanWatch;

    ULONG                       BuildIo;
    ULONG                       StartIo;
    ULONG                       Completed;
};

static FORCEINLINE PVOID
__AdapterAllocate(
    IN  ULONG   Size
    )
{
    PVOID       Buffer;
    Buffer = ExAllocatePoolWithTag(NonPagedPool,
                                   Size,
                                   ADAPTER_POOL_TAG);
    if (Buffer)
        RtlZeroMemory(Buffer, Size);
    return Buffer;
}

static FORCEINLINE VOID
__AdapterFree(
    IN  PVOID   Buffer
    )
{
    ExFreePoolWithTag(Buffer, ADAPTER_POOL_TAG);
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

    Ansi = __AdapterAllocate(sizeof (ANSI_STRING) * (Count + 1));
    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __AdapterAllocate(Ansi[Index].MaximumLength);

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
            __AdapterFree(Ansi[Index].Buffer);

    __AdapterFree(Ansi);

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

    Ansi = __AdapterAllocate(sizeof (ANSI_STRING) * (Count + 1));
    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __AdapterAllocate(Ansi[Index].MaximumLength);

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
            __AdapterFree(Ansi[Index].Buffer);

    __AdapterFree(Ansi);

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
            __AdapterFree(Ansi[Index].Buffer);

    __AdapterFree(Ansi);
}

static FORCEINLINE BOOLEAN
__AdapterSetDevicePowerState(
    IN  PXENVBD_ADAPTER     Adapter,
    IN  DEVICE_POWER_STATE  State
    )
{
    KIRQL                   Irql;
    BOOLEAN                 Changed = FALSE;

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
    IN  PXENVBD_ADAPTER Adapter
    )
{
    KIRQL               Irql;
    DEVICE_POWER_STATE  State;

    KeAcquireSpinLock(&Adapter->Lock, &Irql);
    State = Adapter->DevicePower;
    KeReleaseSpinLock(&Adapter->Lock, Irql);

    return State;
}

static FORCEINLINE PXENVBD_TARGET
AdapterGetTarget(
    IN  PXENVBD_ADAPTER Adapter,
    IN  ULONG           TargetId
    )
{
    PXENVBD_TARGET      Target;
    KIRQL               Irql;

    ASSERT3U(TargetId, <, XENVBD_MAX_TARGETS);

    KeAcquireSpinLock(&Adapter->TargetLock, &Irql);
    Target = Adapter->TargetList[TargetId];
    KeReleaseSpinLock(&Adapter->TargetLock, Irql);

    return Target;
}

static FORCEINLINE BOOLEAN
__AdapterHiddenTarget(
    IN  PXENVBD_ADAPTER     Adapter,
    IN  PCHAR               DeviceId
    )
{
    NTSTATUS                status;
    PCHAR                   Buffer;
    CHAR                    Path[sizeof("device/vbd/XXXXXXXX")];
    BOOLEAN                 Ejected;
    BOOLEAN                 IsDisk;

    status = RtlStringCbPrintfA(Path,
                                sizeof(Path),
                                "device/vbd/%s",
                                DeviceId);
    if (!NT_SUCCESS(status))
        goto fail1;

    // Ejected?
    status = XENBUS_STORE(Read,
                          &Adapter->StoreInterface,
                          NULL,
                          Path,
                          "ejected",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Ejected = (BOOLEAN)strtoul(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Adapter->StoreInterface,
                     Buffer);

        if (Ejected)
            goto ignore;
    }

    // Not Disk?
    status = XENBUS_STORE(Read,
                          &Adapter->StoreInterface,
                          NULL,
                          Path,
                          "device-type",
                          &Buffer);
    if (!NT_SUCCESS(status))
        goto ignore;

    IsDisk = (strcmp(Buffer, "disk") == 0);

    XENBUS_STORE(Free,
                 &Adapter->StoreInterface,
                 Buffer);

    if (!IsDisk)
        goto ignore;

    // Try to Create
    return FALSE;

fail1:
    Error("fail1\n");
    return TRUE;

ignore:
    return TRUE;
}

BOOLEAN
AdapterIsTargetEmulated(
    IN  PXENVBD_ADAPTER Adapter,
    IN  ULONG           TargetId
    )
{
    BOOLEAN             Emulated;
    NTSTATUS            status;

    // Only check targets that could be emulated
    if (TargetId > 3)
        return FALSE;

    // Check presense of Emulated interface. Absence indicates emulated cannot be unplugged
    if (Adapter->EmulatedInterface.Interface.Context == NULL)
        return TRUE;

    // Acquire failed, assume emulated
    status = XENFILT_EMULATED(Acquire, &Adapter->EmulatedInterface);
    if (!NT_SUCCESS(status))
        return TRUE;

    // Ask XenFilt if Ctrlr(0), Target(Target), Lun(0) is present
    Emulated = XENFILT_EMULATED(IsDiskPresent,
                                &Adapter->EmulatedInterface,
                                0,
                                TargetId,
                                0);

    XENFILT_EMULATED(Release, &Adapter->EmulatedInterface);

    return Emulated;
}

static FORCEINLINE VOID
__AdapterEnumerate(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PANSI_STRING    Devices
    )
{
    KIRQL               Irql;
    ULONG               TargetId;
    ULONG               DeviceId;
    PANSI_STRING        Device;
    ULONG               Index;
    PXENVBD_TARGET      Target;
    BOOLEAN             NeedInvalidate;
    BOOLEAN             NeedReboot;

    NeedInvalidate = FALSE;
    NeedReboot = FALSE;

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        BOOLEAN     Missing = TRUE;

        Target = AdapterGetTarget(Adapter, TargetId);
        if (Target == NULL)
            continue;

        for (Index = 0; Devices[Index].Buffer != NULL; ++Index) {
            Device = &Devices[Index];

            if (Device->Length == 0)
                continue;

            DeviceId = strtoul(Device->Buffer, NULL, 10);
            if (TargetGetDeviceId(Target) == DeviceId) {
                Device->Length = 0;
                Missing = FALSE;
                break;
            }
        }

        if (Missing && !TargetIsMissing(Target)) {
            TargetSetMissing(Target, "Device Disappeared");
            if (TargetGetDevicePnpState(Target) == Present)
                TargetSetDevicePnpState(Target, Deleted);
            else
                NeedInvalidate = TRUE;
        }

        if (TargetGetDevicePnpState(Target) == Deleted) {
            KeAcquireSpinLock(&Adapter->TargetLock, &Irql);
            ASSERT3P(Adapter->TargetList[TargetId], ==, Target);
            Adapter->TargetList[TargetId] = NULL;
            KeReleaseSpinLock(&Adapter->TargetLock, Irql);

            TargetDestroy(Target);
        }
    }

    // add new targets
    for (Index = 0; Devices[Index].Buffer != NULL; ++Index) {
        NTSTATUS        status;

        Device = &Devices[Index];

        if (Device->Length == 0)
            continue;

        if (__AdapterHiddenTarget(Adapter, Device->Buffer))
            continue;

        status = TargetCreate(Adapter,
                              Device->Buffer,
                              &Target);
        if (status == STATUS_RETRY)
            NeedReboot = TRUE;
        if (!NT_SUCCESS(status))
            continue;

        TargetId = TargetGetTargetId(Target);

        KeAcquireSpinLock(&Adapter->TargetLock, &Irql);
        ASSERT3P(Adapter->TargetList[TargetId], ==, NULL);
        Adapter->TargetList[TargetId] = Target;
        KeReleaseSpinLock(&Adapter->TargetLock, Irql);

        NeedInvalidate = TRUE;
    }

    if (NeedInvalidate)
        AdapterTargetListChanged(Adapter);
    if (NeedReboot)
        DriverRequestReboot();
}

static DECLSPEC_NOINLINE NTSTATUS
AdapterScanThread(
    IN  PXENVBD_THREAD  Thread,
    IN  PVOID           Context
    )
{
    PXENVBD_ADAPTER     Adapter = Context;
    PKEVENT             Event = ThreadGetEvent(Thread);

    for (;;) {
        NTSTATUS        status;
        PCHAR           Buffer;
        PANSI_STRING    Devices;

        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Thread))
            break;
        if (__AdapterGetDevicePowerState(Adapter) != PowerDeviceD0)
            goto done;

        status = XENBUS_STORE(Directory,
                              &Adapter->StoreInterface,
                              NULL,
                              "device",
                              "vbd",
                              &Buffer);
        if (NT_SUCCESS(status)) {
            Devices = __AdapterMultiSzToAnsi(Buffer);

            XENBUS_STORE(Free,
                         &Adapter->StoreInterface,
                         Buffer);
        } else {
            Devices = NULL;
        }

        if (Devices == NULL)
            goto done;

        __AdapterEnumerate(Adapter,
                           Devices);

        __AdapterFreeAnsi(Devices);

done:
        KeSetEvent(&Adapter->ScanEvent, IO_NO_INCREMENT, FALSE);
    }
    KeSetEvent(&Adapter->ScanEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
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
                          &Adapter->StoreInterface,
                          NULL,
                          NULL,
                          "drivers",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Distributions = __AdapterMultiSzToUpcaseAnsi(Buffer);

        XENBUS_STORE(Free,
                     &Adapter->StoreInterface,
                     Buffer);
    } else {
        Distributions = NULL;
    }

    if (Distributions == NULL)
        goto done;

    for (Index = 0; Distributions[Index].Buffer != NULL; Index++) {
        PANSI_STRING    Distribution = &Distributions[Index];

        status = XENBUS_STORE(Read,
                              &Adapter->StoreInterface,
                              NULL,
                              "drivers",
                              Distribution->Buffer,
                              &Buffer);
        if (!NT_SUCCESS(status))
            continue;

        if (__AdapterMatchDistribution(Adapter, Buffer))
            (VOID) XENBUS_STORE(Remove,
                                &Adapter->StoreInterface,
                                NULL,
                                "drivers",
                                Distribution->Buffer);

        XENBUS_STORE(Free,
                     &Adapter->StoreInterface,
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
                              &Adapter->StoreInterface,
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
                     &Adapter->StoreInterface,
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
                        &Adapter->StoreInterface,
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
    IN  PXENVBD_ADAPTER Adapter
    )
{
    NTSTATUS            status;

    Trace("=====>\n");

    status = XENBUS_STORE(Acquire, &Adapter->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    (VOID) AdapterSetDistribution(Adapter);

    status = XENBUS_STORE(WatchAdd,
                          &Adapter->StoreInterface,
                          "device",
                          "vbd",
                          ThreadGetEvent(Adapter->ScanThread),
                          &Adapter->ScanWatch);
    if (!NT_SUCCESS(status))
        goto fail2;

    (VOID) XENBUS_STORE(Printf,
                        &Adapter->StoreInterface,
                        NULL,
                        "feature/hotplug",
                        "vbd",
                        "%u",
                        TRUE);

    Trace("<=====\n");
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    XENBUS_STORE(Release, &Adapter->StoreInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__AdapterD0ToD3(
    IN  PXENVBD_ADAPTER Adapter
    )
{
    Trace("=====>\n");

    (VOID) XENBUS_STORE(Remove,
                        &Adapter->StoreInterface,
                        NULL,
                        "feature/hotplug",
                        "vbd");

    (VOID) XENBUS_STORE(WatchRemove,
                        &Adapter->StoreInterface,
                        Adapter->ScanWatch);
    Adapter->ScanWatch = NULL;

    AdapterClearDistribution(Adapter);

    XENBUS_STORE(Release, &Adapter->StoreInterface);

    Trace("<=====\n");
}

static VOID
AdapterSuspendLateCallback(
    IN  PVOID       Argument
    )
{
    PXENVBD_ADAPTER Adapter = Argument;
    NTSTATUS        status;

    Verbose("%u.%u.%u.%u (%02u/%02u/%04u)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

    __AdapterD0ToD3(Adapter);

    status = __AdapterD3ToD0(Adapter);
    ASSERT(NT_SUCCESS(status));
}

static DECLSPEC_NOINLINE VOID
AdapterDebugCallback(
    IN  PVOID       Context,
    IN  BOOLEAN     Crashing
    )
{
    PXENVBD_ADAPTER Adapter = Context;
    ULONG           TargetId;

    XENBUS_DEBUG(Printf,
                 &Adapter->DebugInterface,
                 "ADAPTER: Version: %u.%u.%u.%u (%02u/%02u/%04u)\n",
                 MAJOR_VERSION, MINOR_VERSION, MICRO_VERSION, BUILD_NUMBER,
                 DAY, MONTH, YEAR);
    XENBUS_DEBUG(Printf,
                 &Adapter->DebugInterface,
                 "ADAPTER: Adapter: 0x%p %s\n",
                 Context,
                 Crashing ? "CRASHING" : "");
    XENBUS_DEBUG(Printf,
                 &Adapter->DebugInterface,
                 "ADAPTER: DevObj 0x%p LowerDevObj 0x%p PhysDevObj 0x%p\n",
                 Adapter->DeviceObject,
                 Adapter->LowerDeviceObject,
                 Adapter->PhysicalDeviceObject);
    XENBUS_DEBUG(Printf,
                 &Adapter->DebugInterface,
                 "ADAPTER: DevicePowerState: %s\n",
                 PowerDeviceStateName(Adapter->DevicePower));
    XENBUS_DEBUG(Printf,
                 &Adapter->DebugInterface,
                 "ADAPTER: Srbs            : %u built, %u started, %u completed\n",
                 Adapter->BuildIo,
                 Adapter->StartIo,
                 Adapter->Completed);

    BufferDebugCallback(&Adapter->DebugInterface);

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        // no need to use AdapterGetTarget (which is locked at DISPATCH) as called at HIGH_LEVEL
        PXENVBD_TARGET Target = Adapter->TargetList[TargetId];
        if (Target == NULL)
            continue;

        XENBUS_DEBUG(Printf, &Adapter->DebugInterface,
                     "ADAPTER: ====> Target[%-3d]    : 0x%p\n",
                     TargetId, Target);

        // call Target's debug callback directly
        TargetDebugCallback(Target, &Adapter->DebugInterface);

        XENBUS_DEBUG(Printf, &Adapter->DebugInterface,
                     "ADAPTER: <==== Target[%-3d]    : 0x%p\n",
                     TargetId, Target);
    }
}

static NTSTATUS
AdapterD3ToD0(
    IN  PXENVBD_ADAPTER Adapter
    )
{
    NTSTATUS            status;
    ULONG               TargetId;

    if (!__AdapterSetDevicePowerState(Adapter, PowerDeviceD0))
        return STATUS_SUCCESS;

    Verbose("D3->D0\n");

    status = XENBUS_SUSPEND(Acquire, &Adapter->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Acquire, &Adapter->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_DEBUG(Register,
                          &Adapter->DebugInterface,
                          __MODULE__,
                          AdapterDebugCallback,
                          Adapter,
                          &Adapter->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = __AdapterD3ToD0(Adapter);
    if (!NT_SUCCESS(status))
        goto fail4;

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = AdapterGetTarget(Adapter, TargetId);
        if (Target == NULL)
            continue;

        status = TargetD3ToD0(Target);

        if (!NT_SUCCESS(status))
            goto fail5;
    }

    status = XENBUS_SUSPEND(Register,
                            &Adapter->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            AdapterSuspendLateCallback,
                            Adapter,
                            &Adapter->SuspendCallback);
    if (!NT_SUCCESS(status))
        goto fail6;

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = AdapterGetTarget(Adapter, TargetId);
        if (Target == NULL)
            continue;
        TargetD0ToD3(Target);
    }

    __AdapterD0ToD3(Adapter);

fail4:
    Error("fail4\n");

    XENBUS_DEBUG(Deregister,
                 &Adapter->DebugInterface,
                 Adapter->DebugCallback);
    Adapter->DebugCallback = NULL;

fail3:
    Error("fail3\n");

    XENBUS_DEBUG(Release, &Adapter->DebugInterface);

fail2:
    Error("fail2\n");

    XENBUS_SUSPEND(Release, &Adapter->SuspendInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    __AdapterSetDevicePowerState(Adapter, PowerDeviceD3);
    return status;
}

static VOID
AdapterD0ToD3(
    IN  PXENVBD_ADAPTER Adapter
    )
{
    ULONG               TargetId;

    if (!__AdapterSetDevicePowerState(Adapter, PowerDeviceD3))
        return;

    Verbose("D0->D3\n");

    XENBUS_SUSPEND(Deregister,
                   &Adapter->SuspendInterface,
                   Adapter->SuspendCallback);
    Adapter->SuspendCallback = NULL;

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = AdapterGetTarget(Adapter, TargetId);
        if (Target == NULL)
            continue;
        TargetD0ToD3(Target);
    }

    __AdapterD0ToD3(Adapter);

    XENBUS_DEBUG(Deregister,
                 &Adapter->DebugInterface,
                 Adapter->DebugCallback);
    Adapter->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Adapter->DebugInterface);

    XENBUS_SUSPEND(Release, &Adapter->SuspendInterface);
}

static DECLSPEC_NOINLINE NTSTATUS
AdapterDevicePowerThread(
    IN  PXENVBD_THREAD  Thread,
    IN  PVOID           Context
    )
{
    PXENVBD_ADAPTER     Adapter = Context;

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  Stack;
        DEVICE_POWER_STATE  DeviceState;
        POWER_ACTION        Action;

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
                AdapterD3ToD0(Adapter);
                break;

            case PowerDeviceD3:
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
        (VOID) DriverDispatchPower(Adapter->DeviceObject, Irp);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
__AdapterQueryInterface(
    IN  PXENVBD_ADAPTER Adapter,
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

#define AdapterQueryInterface(_adapter, _name, _itf, _opt)      \
    __AdapterQueryInterface((_adapter),                         \
                            &GUID_ ## _name ## _INTERFACE,      \
                            _name ## _INTERFACE_VERSION_MAX,    \
                            (PINTERFACE)(_itf),                 \
                            sizeof( ## _name ## _INTERFACE),    \
                            (_opt))
static NTSTATUS
AdapterInitialize(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PDEVICE_OBJECT  PhysicalDeviceObject,
    IN  PDEVICE_OBJECT  LowerDeviceObject
    )
{
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Adapter->DeviceObject           = DeviceObject;
    Adapter->PhysicalDeviceObject   = PhysicalDeviceObject;
    Adapter->LowerDeviceObject      = LowerDeviceObject;
    Adapter->DevicePower            = PowerDeviceD3;

    KeInitializeSpinLock(&Adapter->TargetLock);
    KeInitializeSpinLock(&Adapter->Lock);
    KeInitializeEvent(&Adapter->ScanEvent, SynchronizationEvent, FALSE);

    status = AdapterQueryInterface(Adapter,
                                   XENBUS_STORE,
                                   &Adapter->StoreInterface,
                                   FALSE);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = AdapterQueryInterface(Adapter,
                                   XENBUS_EVTCHN,
                                   &Adapter->EvtchnInterface,
                                   FALSE);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = AdapterQueryInterface(Adapter,
                                   XENBUS_GNTTAB,
                                   &Adapter->GnttabInterface,
                                   FALSE);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = AdapterQueryInterface(Adapter,
                                   XENBUS_SUSPEND,
                                   &Adapter->SuspendInterface,
                                   FALSE);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = AdapterQueryInterface(Adapter,
                                   XENBUS_DEBUG,
                                   &Adapter->DebugInterface,
                                   FALSE);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = AdapterQueryInterface(Adapter,
                                   XENBUS_UNPLUG,
                                   &Adapter->UnplugInterface,
                                   FALSE);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = AdapterQueryInterface(Adapter,
                                   XENFILT_EMULATED,
                                   &Adapter->EmulatedInterface,
                                   TRUE);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = ThreadCreate(AdapterScanThread,
                          Adapter,
                          &Adapter->ScanThread);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = ThreadCreate(AdapterDevicePowerThread,
                          Adapter,
                          &Adapter->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail9;

    return STATUS_SUCCESS;

fail9:
    Error("fail9\n");
    ThreadAlert(Adapter->ScanThread);
    ThreadJoin(Adapter->ScanThread);
    Adapter->ScanThread = NULL;
fail8:
    Error("fail8\n");
    RtlZeroMemory(&Adapter->EmulatedInterface,
                  sizeof (XENFILT_EMULATED_INTERFACE));
fail7:
    Error("fail7\n");
    RtlZeroMemory(&Adapter->UnplugInterface,
                  sizeof (XENBUS_UNPLUG_INTERFACE));
fail6:
    Error("fail6\n");
    RtlZeroMemory(&Adapter->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));
fail5:
    Error("fail5\n");
    RtlZeroMemory(&Adapter->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));
fail4:
    Error("fail4\n");
    RtlZeroMemory(&Adapter->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));
fail3:
    Error("fail3\n");
    RtlZeroMemory(&Adapter->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));
fail2:
    Error("fail2\n");
    RtlZeroMemory(&Adapter->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));
fail1:
    Error("fail1 (%08x)\n", status);

    RtlZeroMemory(&Adapter->TargetLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Adapter->Lock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Adapter->ScanEvent, sizeof(KEVENT));

    Adapter->DevicePower            = 0;
    Adapter->DeviceObject           = NULL;
    Adapter->PhysicalDeviceObject   = NULL;
    Adapter->LowerDeviceObject      = NULL;

    return status;
}

static VOID
AdapterTeardown(
    IN  PXENVBD_ADAPTER Adapter
    )
{
    ULONG               TargetId;

    ASSERT3U(Adapter->DevicePower, ==, PowerDeviceD3);

    ThreadAlert(Adapter->DevicePowerThread);
    ThreadJoin(Adapter->DevicePowerThread);
    Adapter->DevicePowerThread = NULL;

    ThreadAlert(Adapter->ScanThread);
    ThreadJoin(Adapter->ScanThread);
    Adapter->ScanThread = NULL;

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = AdapterGetTarget(Adapter, TargetId);
        if (Target == NULL)
            continue;

        // Target may not be in Deleted state yet, force it as Adapter is terminating
        if (TargetGetDevicePnpState(Target) != Deleted)
            TargetSetDevicePnpState(Target, Deleted);
        // update missing (for debug output more than anything else
        TargetSetMissing(Target, "AdapterTeardown");
        // drop ref-count acquired in __AdapterGetTarget *before* destroying Target
        TargetDestroy(Target);
    }

    RtlZeroMemory(&Adapter->EmulatedInterface,
                  sizeof (XENFILT_EMULATED_INTERFACE));

    RtlZeroMemory(&Adapter->UnplugInterface,
                  sizeof (XENBUS_UNPLUG_INTERFACE));

    RtlZeroMemory(&Adapter->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Adapter->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&Adapter->GnttabInterface,
                  sizeof (XENBUS_GNTTAB_INTERFACE));

    RtlZeroMemory(&Adapter->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&Adapter->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Adapter->TargetLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Adapter->Lock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Adapter->ScanEvent, sizeof(KEVENT));

    Adapter->DevicePower            = 0;
    Adapter->DeviceObject           = NULL;
    Adapter->PhysicalDeviceObject   = NULL;
    Adapter->LowerDeviceObject      = NULL;

    Adapter->BuildIo                = 0;
    Adapter->StartIo                = 0;
    Adapter->Completed              = 0;

    ASSERT(IsZeroMemory(Adapter, sizeof(XENVBD_ADAPTER)));
    Trace("<===== (%d)\n", KeGetCurrentIrql());
}

VOID
AdapterCompleteSrb(
    IN  PXENVBD_ADAPTER     Adapter,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    ASSERT3U(Srb->SrbStatus, !=, SRB_STATUS_PENDING);

    ++Adapter->Completed;

    StorPortNotification(RequestComplete, Adapter, Srb);
}

VOID
AdapterTargetListChanged(
    IN  PXENVBD_ADAPTER Adapter
    )
{
    StorPortNotification(BusChangeDetected,
                         Adapter,
                         NULL);
}

VOID
AdapterSetDeviceQueueDepth(
    IN  PXENVBD_ADAPTER Adapter,
    IN  ULONG           TargetId
    )
{
    if (!StorPortSetDeviceQueueDepth(Adapter,
                                     0,
                                     (UCHAR)TargetId,
                                     0,
                                     XENVBD_MAX_QUEUE_DEPTH))
        Verbose("Target[%d] : Failed to set queue depth\n",
                TargetId);
}

static VOID
AdapterUnplugRequest(
    IN  PXENVBD_ADAPTER Adapter,
    IN  BOOLEAN         Make
    )
{
    NTSTATUS            status;

    status = XENBUS_UNPLUG(Acquire, &Adapter->UnplugInterface);
    if (!NT_SUCCESS(status))
        return;

    XENBUS_UNPLUG(Request,
                  &Adapter->UnplugInterface,
                  XENBUS_UNPLUG_DEVICE_TYPE_DISKS,
                  Make);

    XENBUS_UNPLUG(Release, &Adapter->UnplugInterface);
}

static PXENVBD_TARGET
AdapterGetTargetFromDeviceObject(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    ULONG               TargetId;

    ASSERT3P(DeviceObject, !=, NULL);

    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = AdapterGetTarget(Adapter, TargetId);
        if (Target == NULL)
            continue;
        if (TargetGetDeviceObject(Target) == DeviceObject)
            return Target;
    }

    return NULL;
}

static PXENVBD_TARGET
AdapterMapDeviceObjectToTarget(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    PXENVBD_TARGET      Target;
    KEVENT              Complete;
    PIRP                Irp;
    IO_STATUS_BLOCK     StatusBlock;
    PIO_STACK_LOCATION  Stack;
    NTSTATUS            Status;
    PWCHAR              String;
    ULONG               TargetId;
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

    Target = AdapterGetTarget(Adapter, TargetId);
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

static NTSTATUS
AdapterForwardPnp(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  Stack;
    PXENVBD_TARGET      Target;

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

NTSTATUS
AdapterDispatchPnp(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  Stack;

    if (Adapter->DeviceObject != DeviceObject)
        return AdapterForwardPnp(Adapter, DeviceObject, Irp);

    Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->MinorFunction) {
    case IRP_MN_REMOVE_DEVICE:
        AdapterD0ToD3(Adapter);
        AdapterUnplugRequest(Adapter, FALSE);
        AdapterTeardown(Adapter);
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
            Trace("scan thread wait complete\n");
        }
        break;

    default:
        break;
    }

    return DriverDispatchPnp(DeviceObject, Irp);
}

NTSTATUS
AdapterDispatchPower(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  Stack;
    POWER_STATE_TYPE    PowerType;
    NTSTATUS            status;

    if (Adapter->DeviceObject != DeviceObject)
        return DriverDispatchPower(DeviceObject, Irp);

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

HW_RESET_BUS        AdapterHwResetBus;

BOOLEAN
AdapterHwResetBus(
    IN  PVOID       DevExt,
    IN  ULONG       PathId
    )
{
    PXENVBD_ADAPTER Adapter = DevExt;
    ULONG           TargetId;

    UNREFERENCED_PARAMETER(PathId);

    Verbose("====>\n");
    for (TargetId = 0; TargetId < XENVBD_MAX_TARGETS; ++TargetId) {
        PXENVBD_TARGET Target = AdapterGetTarget(Adapter, TargetId);
        if (Target == NULL)
            continue;

        TargetReset(Target);
    }
    Verbose("<====\n");

    return TRUE;
}


static FORCEINLINE VOID
__AdapterSrbPnp(
    IN  PXENVBD_ADAPTER         Adapter,
    IN  PSCSI_PNP_REQUEST_BLOCK Srb
    )
{
    if (!(Srb->SrbPnPFlags & SRB_PNP_FLAGS_ADAPTER_REQUEST)) {
        PXENVBD_TARGET          Target;

        Target = AdapterGetTarget(Adapter, Srb->TargetId);
        if (Target) {
            TargetSrbPnp(Target, Srb);
        }
    }
}

HW_BUILDIO          AdapterHwBuildIo;

BOOLEAN
AdapterHwBuildIo(
    IN  PVOID               DevExt,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_ADAPTER         Adapter = DevExt;

    InitSrbExt(Srb);

    switch (Srb->Function) {
    case SRB_FUNCTION_EXECUTE_SCSI:
    case SRB_FUNCTION_RESET_DEVICE:
    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_SHUTDOWN:
        ++Adapter->BuildIo;
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
        AdapterHwResetBus(Adapter, Srb->PathId);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    default:
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }

    AdapterCompleteSrb(Adapter, Srb);
    return FALSE;
}

HW_STARTIO          AdapterHwStartIo;

BOOLEAN
AdapterHwStartIo(
    IN  PVOID               DevExt,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_ADAPTER         Adapter = DevExt;
    PXENVBD_TARGET          Target;

    Target = AdapterGetTarget(Adapter, Srb->TargetId);
    if (Target == NULL)
        goto fail1;

    ++Adapter->StartIo;
    if (TargetStartIo(Target, Srb))
        AdapterCompleteSrb(Adapter, Srb);

    return TRUE;

fail1:
    Srb->SrbStatus = SRB_STATUS_INVALID_TARGET_ID;
    AdapterCompleteSrb(Adapter, Srb);
    return TRUE;
}

HW_ADAPTER_CONTROL  AdapterHwAdapterControl;

SCSI_ADAPTER_CONTROL_STATUS
AdapterHwAdapterControl(
    IN  PVOID                       DevExt,
    IN  SCSI_ADAPTER_CONTROL_TYPE   ControlType,
    IN  PVOID                       Parameters
    )
{
    PSCSI_SUPPORTED_CONTROL_TYPE_LIST   List;

    UNREFERENCED_PARAMETER(DevExt);

    switch (ControlType) {
    case ScsiQuerySupportedControlTypes:
        List = Parameters;
        List->SupportedTypeList[ScsiQuerySupportedControlTypes] = TRUE;
        break;

    default:
        break;
    }
    return ScsiAdapterControlSuccess;
}

HW_FIND_ADAPTER     AdapterHwFindAdapter;

ULONG
AdapterHwFindAdapter(
    IN  PVOID                               DevExt,
    IN  PVOID                               Context,
    IN  PVOID                               BusInformation,
    IN  PCHAR                               ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION  ConfigInfo,
    OUT PBOOLEAN                            Again
    )
{
    PXENVBD_ADAPTER                         Adapter = DevExt;
    PDEVICE_OBJECT                          DeviceObject;
    PDEVICE_OBJECT                          PhysicalDeviceObject;
    PDEVICE_OBJECT                          LowerDeviceObject;
    NTSTATUS                                status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);
    UNREFERENCED_PARAMETER(Again);

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

    if (ConfigInfo->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED)
        ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;

    // We need to do this to avoid an assertion in a checked kernel
    (VOID) StorPortGetUncachedExtension(DevExt, ConfigInfo, PAGE_SIZE);

    (VOID) StorPortGetDeviceObjects(DevExt,
                                    &DeviceObject,
                                    &PhysicalDeviceObject,
                                    &LowerDeviceObject);
    if (Adapter->DeviceObject == DeviceObject)
        return SP_RETURN_FOUND;

    status = AdapterInitialize(Adapter,
                               DeviceObject,
                               PhysicalDeviceObject,
                               LowerDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    AdapterUnplugRequest(Adapter, TRUE);

    status = AdapterD3ToD0(Adapter);
    if (!NT_SUCCESS(status))
        goto fail2;

    DriverSetAdapter(Adapter);
    return SP_RETURN_FOUND;

fail2:
    Error("fail2\n");
    AdapterUnplugRequest(Adapter, FALSE);
    AdapterTeardown(Adapter);
fail1:
    Error("fail1\n");
    return SP_RETURN_ERROR;
}

HW_INITIALIZE   AdapterHwInitialize;

BOOLEAN
AdapterHwInitialize(
    IN  PVOID   DevExt
    )
{
    UNREFERENCED_PARAMETER(DevExt);
    return TRUE;
}

HW_INTERRUPT    AdapterHwInterrupt;

BOOLEAN
AdapterHwInterrupt(
    IN  PVOID   DevExt
    )
{
    UNREFERENCED_PARAMETER(DevExt);
    return TRUE;
}

NTSTATUS
AdapterDriverEntry(
    IN  PUNICODE_STRING     RegistryPath,
    IN  PDRIVER_OBJECT      DriverObject
    )
{
    HW_INITIALIZATION_DATA  InitData;
    NTSTATUS                status;

    RtlZeroMemory(&InitData, sizeof(InitData));
    InitData.HwInitializationDataSize   = sizeof(InitData);
    InitData.AdapterInterfaceType       = Internal;
    InitData.HwInitialize               = AdapterHwInitialize;
    InitData.HwStartIo                  = AdapterHwStartIo;
    InitData.HwInterrupt                = AdapterHwInterrupt;
#pragma warning(suppress : 4152)
    InitData.HwFindAdapter              = AdapterHwFindAdapter;
    InitData.HwResetBus                 = AdapterHwResetBus;
    InitData.HwDmaStarted               = NULL;
    InitData.HwAdapterState             = NULL;
    InitData.DeviceExtensionSize        = sizeof(XENVBD_ADAPTER);
    InitData.SpecificLuExtensionSize    = sizeof(ULONG); // not actually used
    InitData.SrbExtensionSize           = sizeof(XENVBD_SRBEXT);
    InitData.NumberOfAccessRanges       = 2;
    InitData.MapBuffers                 = STOR_MAP_NON_READ_WRITE_BUFFERS;
    InitData.NeedPhysicalAddresses      = TRUE;
    InitData.TaggedQueuing              = TRUE;
    InitData.AutoRequestSense           = TRUE;
    InitData.MultipleRequestPerLu       = TRUE;
    InitData.HwAdapterControl           = AdapterHwAdapterControl;
    InitData.HwBuildIo                  = AdapterHwBuildIo;

    status = StorPortInitialize(DriverObject,
                                RegistryPath,
                                &InitData,
                                NULL);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 %08x\n", status);
    return status;
}

#define ADAPTER_GET_INTERFACE(_name, _type)                     \
VOID                                                            \
AdapterGet ## _name ## Interface(                               \
    IN  PXENVBD_ADAPTER Adapter,                                \
    OUT _type           _name ## Interface                      \
    )                                                           \
{                                                               \
    * ## _name ## Interface = Adapter-> ## _name ## Interface;  \
}

ADAPTER_GET_INTERFACE(Store, PXENBUS_STORE_INTERFACE)
ADAPTER_GET_INTERFACE(Debug, PXENBUS_DEBUG_INTERFACE)
ADAPTER_GET_INTERFACE(Evtchn, PXENBUS_EVTCHN_INTERFACE)
ADAPTER_GET_INTERFACE(Gnttab, PXENBUS_GNTTAB_INTERFACE)
ADAPTER_GET_INTERFACE(Suspend, PXENBUS_SUSPEND_INTERFACE)

#undef ADAPTER_GET_INTERFACE
