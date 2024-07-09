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

#include "registry.h"
#include "driver.h"
#include "util.h"
#include "debug.h"
#include "assert.h"

#include <version.h>

typedef struct _XENDISK_DRIVER {
    PDRIVER_OBJECT  DriverObject;
    HANDLE          ParametersKey;
} XENDISK_DRIVER, *PXENDISK_DRIVER;

static XENDISK_DRIVER   Driver;

static FORCEINLINE VOID
__DriverSetDriverObject(
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    Driver.DriverObject = DriverObject;
}

static FORCEINLINE PDRIVER_OBJECT
__DriverGetDriverObject(
    VOID
    )
{
    return Driver.DriverObject;
}

PDRIVER_OBJECT
DriverGetDriverObject(
    VOID
    )
{
    return __DriverGetDriverObject();
}

static FORCEINLINE VOID
__DriverSetParametersKey(
    IN  HANDLE  Key
    )
{
    Driver.ParametersKey = Key;
}

static FORCEINLINE HANDLE
__DriverGetParametersKey(
    VOID
    )
{
    return Driver.ParametersKey;
}

HANDLE
DriverGetParametersKey(
    VOID
    )
{
    return __DriverGetParametersKey();
}

DRIVER_UNLOAD   DriverUnload;

VOID
DriverUnload(
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    HANDLE              ParametersKey;

    ASSERT3P(DriverObject, ==, __DriverGetDriverObject());

    Trace("====>\n");

    ParametersKey = __DriverGetParametersKey();
    __DriverSetParametersKey(NULL);

    RegistryCloseKey(ParametersKey);

    RegistryTeardown();

    Verbose("XENDISK %d.%d.%d (%d) (%02d.%02d.%04d)\n",
            MAJOR_VERSION,
            MINOR_VERSION,
            MICRO_VERSION,
            BUILD_NUMBER,
            DAY,
            MONTH,
            YEAR);

    __DriverSetDriverObject(NULL);

    ASSERT(IsZeroMemory(&Driver, sizeof (XENDISK_DRIVER)));

    Trace("<====\n");
}

DRIVER_ADD_DEVICE   AddDevice;

NTSTATUS
#pragma prefast(suppress:28152) // Does not clear DO_DEVICE_INITIALIZING
AddDevice(
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PDEVICE_OBJECT  PhysicalDeviceObject
    )
{
    NTSTATUS            status;

    ASSERT3P(DriverObject, ==, __DriverGetDriverObject());

    status = FdoCreate(PhysicalDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

DRIVER_DISPATCH Dispatch;

NTSTATUS
Dispatch(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PXENDISK_DX         Dx;
    NTSTATUS            status;

    Dx = (PXENDISK_DX)DeviceObject->DeviceExtension;
    ASSERT3P(Dx->DeviceObject, ==, DeviceObject);

    if (Dx->DevicePnpState == Deleted) {
        PIO_STACK_LOCATION  StackLocation = IoGetCurrentIrpStackLocation(Irp);
        UCHAR               MajorFunction = StackLocation->MajorFunction;
        UCHAR               MinorFunction = StackLocation->MinorFunction;

        status = STATUS_NO_SUCH_DEVICE;

        if (MajorFunction == IRP_MJ_PNP) {
            /* FDO and PDO deletions can block after being marked deleted, but before IoDeleteDevice */
            if (MinorFunction == IRP_MN_SURPRISE_REMOVAL || MinorFunction == IRP_MN_REMOVE_DEVICE)
                status = STATUS_SUCCESS;

            ASSERT((MinorFunction != IRP_MN_CANCEL_REMOVE_DEVICE) && (MinorFunction != IRP_MN_CANCEL_STOP_DEVICE));
        }

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        goto done;
    }

    status = STATUS_NOT_SUPPORTED;
    switch (Dx->Type) {
    case PHYSICAL_DEVICE_OBJECT: {
        PXENDISK_PDO    Pdo = Dx->Pdo;

        status = PdoDispatch(Pdo, Irp);
        break;
    }
    case FUNCTION_DEVICE_OBJECT: {
        PXENDISK_FDO    Fdo = Dx->Fdo;

        status = FdoDispatch(Fdo, Irp);
        break;
    }
    default:
        ASSERT(FALSE);
        break;
    }

done:
    return status;
}

DRIVER_INITIALIZE   DriverEntry;

NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PUNICODE_STRING RegistryPath
    )
{
    HANDLE              ParametersKey;
    ULONG               Index;
    NTSTATUS            status;

    ASSERT3P(__DriverGetDriverObject(), ==, NULL);
    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    Trace("====>\n");

    __DriverSetDriverObject(DriverObject);

    DriverObject->DriverUnload = DriverUnload;

    Verbose("XENDISK %d.%d.%d (%d) (%02d.%02d.%04d)\n",
            MAJOR_VERSION,
            MINOR_VERSION,
            MICRO_VERSION,
            BUILD_NUMBER,
            DAY,
            MONTH,
            YEAR);

    status = RegistryInitialize(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenParametersKey(KEY_READ, &ParametersKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    __DriverSetParametersKey(ParametersKey);

    DriverObject->DriverExtension->AddDevice = AddDevice;

    for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++) {
#pragma prefast(suppress:28169) // No __drv_dispatchType annotation
#pragma prefast(suppress:28168) // No matching __drv_dispatchType annotation for IRP_MJ_CREATE
        DriverObject->MajorFunction[Index] = Dispatch;
    }

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RegistryTeardown();

fail1:
    Error("fail1 (%08x)\n", status);

    __DriverSetDriverObject(NULL);

    ASSERT(IsZeroMemory(&Driver, sizeof (XENDISK_DRIVER)));

    return status;
}
