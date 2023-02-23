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

#define INITGUID 1

#include <ntddk.h>
#include <wdmguid.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <storport.h>
#include <Ntddstor.h>
#include <Ntddscsi.h>
#include <names.h>

#include "fdo.h"
#include "pdo.h"
#include "driver.h"
#include "registry.h"
#include "thread.h"
#include "debug.h"
#include "assert.h"
#include "util.h"

#define PDO_TAG 'ODP'

#define MAXNAMELEN  128

struct _XENDISK_PDO {
    PXENDISK_DX                 Dx;
    PDEVICE_OBJECT              LowerDeviceObject;
    PDEVICE_OBJECT              PhysicalDeviceObject;
    CHAR                        Name[MAXNAMELEN];

    PXENDISK_THREAD             SystemPowerThread;
    PIRP                        SystemPowerIrp;
    PXENDISK_THREAD             DevicePowerThread;
    PIRP                        DevicePowerIrp;

    PXENDISK_FDO                Fdo;

    BOOLEAN                     InterceptTrim;
    ULONG                       SectorSize;
    ULONG                       PhysSectorSize;
};

static FORCEINLINE PVOID
__PdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, PDO_TAG);
}

static FORCEINLINE VOID
__PdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, PDO_TAG);
}

static FORCEINLINE VOID
__PdoSetDevicePnpState(
    IN  PXENDISK_PDO        Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENDISK_DX             Dx = Pdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

VOID
PdoSetDevicePnpState(
    IN  PXENDISK_PDO        Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    __PdoSetDevicePnpState(Pdo, State);
}

static FORCEINLINE VOID
__PdoRestoreDevicePnpState(
    IN  PXENDISK_PDO        Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENDISK_DX             Dx = Pdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__PdoGetDevicePnpState(
    IN  PXENDISK_PDO    Pdo
    )
{
    PXENDISK_DX         Dx = Pdo->Dx;

    return Dx->DevicePnpState;
}

DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXENDISK_PDO    Pdo
    )
{
    return __PdoGetDevicePnpState(Pdo);
}

static FORCEINLINE VOID
__PdoSetDevicePowerState(
    IN  PXENDISK_PDO        Pdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENDISK_DX             Dx = Pdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__PdoGetDevicePowerState(
    IN  PXENDISK_PDO    Pdo
    )
{
    PXENDISK_DX         Dx = Pdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__PdoSetSystemPowerState(
    IN  PXENDISK_PDO        Pdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENDISK_DX             Dx = Pdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__PdoGetSystemPowerState(
    IN  PXENDISK_PDO    Pdo
    )
{
    PXENDISK_DX         Dx = Pdo->Dx;

    return Dx->SystemPowerState;
}

PDEVICE_OBJECT
PdoGetPhysicalDeviceObject(
    IN  PXENDISK_PDO    Pdo
    )
{
    return Pdo->PhysicalDeviceObject;
}

static FORCEINLINE VOID
__PdoLink(
    IN  PXENDISK_PDO    Pdo,
    IN  PXENDISK_FDO    Fdo
    )
{
    Pdo->Fdo = Fdo;
    FdoAddPhysicalDeviceObject(Fdo, Pdo->Dx->DeviceObject);
}

static FORCEINLINE VOID
__PdoUnlink(
    IN  PXENDISK_PDO    Pdo
    )
{
    PXENDISK_FDO        Fdo = Pdo->Fdo;

    ASSERT(Fdo != NULL);

    FdoRemovePhysicalDeviceObject(Fdo, Pdo->Dx->DeviceObject);

    Pdo->Fdo = NULL;
}

static FORCEINLINE PXENDISK_FDO
__PdoGetFdo(
    IN  PXENDISK_PDO Pdo
    )
{
    return Pdo->Fdo;
}

static FORCEINLINE VOID
__PdoSetName(
    IN  PXENDISK_PDO    Pdo,
    IN  PCHAR           DeviceID,
    IN  PCHAR           InstanceID
    )
{
    NTSTATUS            status;

    status = RtlStringCbPrintfA(Pdo->Name,
                                MAXNAMELEN,
                                "%s\\%s",
                                DeviceID,
                                InstanceID);
    ASSERT(NT_SUCCESS(status));
}

static FORCEINLINE PCHAR
__PdoGetName(
    IN  PXENDISK_PDO    Pdo
    )
{
    return Pdo->Name;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoForwardIrpSynchronously(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PKEVENT             Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
PdoForwardIrpSynchronously(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    KEVENT              Event;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __PdoForwardIrpSynchronously,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = Irp->IoStatus.Status;
    } else {
        ASSERT3U(status, ==, Irp->IoStatus.Status);
    }

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoForwardIrpAndForget(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoForwardIrpAndForget(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                            __PdoForwardIrpAndForget,
                            Pdo,
                            TRUE,
                            TRUE,
                            TRUE);

    return IoCallDriver(Pdo->LowerDeviceObject, Irp);
}

static NTSTATUS
PdoCompleteIrp(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp,
    IN  NTSTATUS        Status
    )
{
    Irp->IoStatus.Status = Status;
    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoSendAwaitSrb(
    IN  PDEVICE_OBJECT          DeviceObject,
    IN  PIRP                    Irp,
    IN  PVOID                   Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    *(Irp->UserIosb) = Irp->IoStatus;

    if (Irp->MdlAddress) {
        MmUnlockPages(Irp->MdlAddress);
        IoFreeMdl(Irp->MdlAddress);
    }

    KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);

    IoFreeIrp(Irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
PdoSendAwaitSrb(
    IN  PXENDISK_PDO            Pdo,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PIRP                        Irp;
    IO_STATUS_BLOCK             IoStatus;
    KEVENT                      Event;
    PIO_STACK_LOCATION          Stack;
    NTSTATUS                    status;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = STATUS_NO_MEMORY;
    Irp = IoAllocateIrp((CCHAR)(Pdo->LowerDeviceObject->StackSize + 1), FALSE);
    if (Irp == NULL)
        goto fail1;

    Stack = IoGetNextIrpStackLocation(Irp);
    Stack->MajorFunction = IRP_MJ_SCSI;
    Stack->Parameters.Scsi.Srb = Srb;

    IoSetCompletionRoutine(Irp,
                            __PdoSendAwaitSrb,
                            Srb,
                            TRUE,
                            TRUE,
                            TRUE);
    Irp->UserIosb = &IoStatus;
    Irp->UserEvent = &Event;

    Irp->MdlAddress = IoAllocateMdl(Srb->DataBuffer,
                                    Srb->DataTransferLength,
                                    FALSE,
                                    FALSE,
                                    Irp);
    if (Irp->MdlAddress == NULL)
        goto fail2;

#pragma warning(disable:6320)
    try {
        MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
    } except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();

        goto fail3;
    }
#pragma warning(default:6320)

    Srb->OriginalRequest = Irp;

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        status = IoStatus.Status;
    }

    return status;

fail3:
    Error("fail3\n");

    IoFreeMdl(Irp->MdlAddress);

fail2:
    Error("fail2\n");

    IoFreeIrp(Irp);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
PdoSendReadCapacity16Synchronous(
    IN  PXENDISK_PDO        Pdo,
    OUT PULONG              SectorSize,
    OUT PULONG              PhysSectorSize,
    OUT PULONG64            SectorCount
    )
{
    SCSI_REQUEST_BLOCK       Srb;
    PCDB                     Cdb;
    PREAD_CAPACITY16_DATA    Capacity;
    ULONG                    Length;
    NTSTATUS                 status;

    Trace("====>\n");

    Length = sizeof(READ_CAPACITY16_DATA);

    status = STATUS_NO_MEMORY;
    Capacity = __PdoAllocate(Length);
    if (Capacity == NULL)
        goto fail1;

    RtlZeroMemory(&Srb, sizeof(SCSI_REQUEST_BLOCK));
    Srb.Length = sizeof(SCSI_REQUEST_BLOCK);
    Srb.SrbFlags = 0;
    Srb.Function = SRB_FUNCTION_EXECUTE_SCSI;
    Srb.DataBuffer = Capacity;
    Srb.DataTransferLength = Length;
    Srb.TimeOutValue = (ULONG)-1;
    Srb.CdbLength = 16;

    Cdb = (PCDB)&Srb.Cdb[0];
    Cdb->READ_CAPACITY16.OperationCode = SCSIOP_READ_CAPACITY16;
    Cdb->READ_CAPACITY16.ServiceAction = SERVICE_ACTION_READ_CAPACITY16;
    *(PULONG)Cdb->READ_CAPACITY16.AllocationLength = _byteswap_ulong(Length);

    status = PdoSendAwaitSrb(Pdo, &Srb);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_UNSUCCESSFUL;
    if (Srb.DataTransferLength < Length)
        goto fail3;

    *SectorSize = _byteswap_ulong(Capacity->BytesPerBlock);
    *PhysSectorSize = *SectorSize << Capacity->LogicalPerPhysicalExponent;
    *SectorCount = _byteswap_uint64(Capacity->LogicalBlockAddress.QuadPart) + 1;

    __PdoFree(Capacity);

    Trace("<====\n");
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    __PdoFree(Capacity);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
PdoSendTrimSynchronous(
    IN  PXENDISK_PDO            Pdo,
    IN  PDEVICE_DATA_SET_RANGE  Ranges,
    IN  ULONG                   Count
    )
{
    SCSI_REQUEST_BLOCK          Srb;
    PCDB                        Cdb;
    PUNMAP_LIST_HEADER          Unmap;
    ULONG                       Length;
    ULONG                       Index;
    NTSTATUS                    status;

    Length = sizeof(UNMAP_LIST_HEADER) +
             (Count * sizeof(UNMAP_BLOCK_DESCRIPTOR));

    status = STATUS_NO_MEMORY;
    Unmap = __PdoAllocate(Length);
    if (Unmap == NULL)
        goto fail1;

    RtlZeroMemory(&Srb, sizeof(SCSI_REQUEST_BLOCK));
    Srb.Length = sizeof(SCSI_REQUEST_BLOCK);
    Srb.SrbFlags = 0;
    Srb.Function = SRB_FUNCTION_EXECUTE_SCSI;
    Srb.DataBuffer = Unmap;
    Srb.DataTransferLength = Length;
    Srb.TimeOutValue = (ULONG)-1;
    Srb.CdbLength = 10;

    Cdb = (PCDB)&Srb.Cdb[0];
    Cdb->UNMAP.OperationCode = SCSIOP_UNMAP;
    *(PUSHORT)Cdb->UNMAP.AllocationLength = _byteswap_ushort((USHORT)Length);

    *(PUSHORT)Unmap->DataLength = _byteswap_ushort((USHORT)(Length - FIELD_OFFSET(UNMAP_LIST_HEADER, BlockDescrDataLength)));
    *(PUSHORT)Unmap->BlockDescrDataLength = _byteswap_ushort((USHORT)(Length - FIELD_OFFSET(UNMAP_LIST_HEADER, Descriptors[0])));

    for (Index = 0; Index < Count; ++Index) {
        PUNMAP_BLOCK_DESCRIPTOR Block = &Unmap->Descriptors[Index];
        PDEVICE_DATA_SET_RANGE  Range = &Ranges[Index];

        ULONG   LengthInSectors = (ULONG)(Range->LengthInBytes / Pdo->SectorSize);
        ULONG64 OffsetInSectors = (ULONG64)(Range->StartingOffset / Pdo->SectorSize);

        *(PULONG64)Block->StartingLba = _byteswap_uint64(OffsetInSectors);
        *(PULONG)Block->LbaCount = _byteswap_ulong(LengthInSectors);
    }

    status = PdoSendAwaitSrb(Pdo, &Srb);
    if (!NT_SUCCESS(status))
        goto fail2;

    __PdoFree(Unmap);
    return status;

fail2:
    Error("fail2\n");

    __PdoFree(Unmap);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static const CHAR *
PropertyIdName(
    IN  STORAGE_PROPERTY_ID Id
    )
{
#define _STORAGE_PROPERTY_NAME(_Id) \
    case Storage ## _Id:            \
        return #_Id;

    switch (Id) {
    _STORAGE_PROPERTY_NAME(DeviceProperty);
    _STORAGE_PROPERTY_NAME(AdapterProperty);
    _STORAGE_PROPERTY_NAME(DeviceIdProperty);
    _STORAGE_PROPERTY_NAME(DeviceUniqueIdProperty);
    _STORAGE_PROPERTY_NAME(DeviceWriteCacheProperty);
    _STORAGE_PROPERTY_NAME(MiniportProperty);
    _STORAGE_PROPERTY_NAME(AccessAlignmentProperty);
    _STORAGE_PROPERTY_NAME(DeviceSeekPenaltyProperty);
    _STORAGE_PROPERTY_NAME(DeviceTrimProperty);
    _STORAGE_PROPERTY_NAME(DeviceWriteAggregationProperty);
    _STORAGE_PROPERTY_NAME(DeviceDeviceTelemetryProperty);
    _STORAGE_PROPERTY_NAME(DeviceLBProvisioningProperty);
    _STORAGE_PROPERTY_NAME(DevicePowerProperty);
    _STORAGE_PROPERTY_NAME(DeviceCopyOffloadProperty);
    _STORAGE_PROPERTY_NAME(DeviceResiliencyProperty);
    _STORAGE_PROPERTY_NAME(DeviceMediumProductType);
    _STORAGE_PROPERTY_NAME(AdapterCryptoProperty);
    _STORAGE_PROPERTY_NAME(DeviceIoCapabilityProperty);
    _STORAGE_PROPERTY_NAME(AdapterProtocolSpecificProperty);
    _STORAGE_PROPERTY_NAME(DeviceProtocolSpecificProperty);
    _STORAGE_PROPERTY_NAME(AdapterTemperatureProperty);
    _STORAGE_PROPERTY_NAME(DeviceTemperatureProperty);
    _STORAGE_PROPERTY_NAME(AdapterPhysicalTopologyProperty);
    _STORAGE_PROPERTY_NAME(DevicePhysicalTopologyProperty);
    _STORAGE_PROPERTY_NAME(DeviceAttributesProperty);
    default:
        break;
    }

    return "UNKNOWN";

#undef _STORAGE_PROPERTY_NAME
}

static const CHAR *
QueryTypeName(
    IN  STORAGE_QUERY_TYPE  Type
    )
{
#define _STORAGE_QUERY_NAME(_Type)   \
    case Property ## _Type ## Query: \
        return #_Type;

    switch (Type) {
    _STORAGE_QUERY_NAME(Standard);
    _STORAGE_QUERY_NAME(Exists);
    _STORAGE_QUERY_NAME(Mask);
    default:
        break;
    }

    return "UNKNOWN";

#undef _STORAGE_QUERY_NAME
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryProperty(
    IN  PXENDISK_PDO        Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    PSTORAGE_PROPERTY_QUERY Query;
    NTSTATUS                status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (StackLocation->Parameters.DeviceIoControl.InputBufferLength <
        sizeof (STORAGE_PROPERTY_QUERY))
        return PdoCompleteIrp(Pdo, Irp, STATUS_INFO_LENGTH_MISMATCH);

    Query = Irp->AssociatedIrp.SystemBuffer;

    Trace("%s %s\n", PropertyIdName(Query->PropertyId), QueryTypeName(Query->QueryType));

    switch (Query->PropertyId) {
    case StorageDeviceTrimProperty:
        if (!Pdo->InterceptTrim) {
            status = PdoForwardIrpAndForget(Pdo, Irp);
            break;
        }

        if (Query->QueryType == PropertyStandardQuery) {
            PDEVICE_TRIM_DESCRIPTOR Trim;

            if (StackLocation->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof (DEVICE_TRIM_DESCRIPTOR))
                return PdoCompleteIrp(Pdo, Irp, STATUS_BUFFER_OVERFLOW);

            Trim = Irp->AssociatedIrp.SystemBuffer;

            RtlZeroMemory(Trim, sizeof(DEVICE_TRIM_DESCRIPTOR));

            Trim->Version = sizeof(DEVICE_TRIM_DESCRIPTOR);
            Trim->Size = sizeof(DEVICE_TRIM_DESCRIPTOR);
            Trim->TrimEnabled = TRUE;

            Irp->IoStatus.Information = sizeof(DEVICE_TRIM_DESCRIPTOR);
        } else {
            Irp->IoStatus.Information = 0;
        }

        status = PdoCompleteIrp(Pdo, Irp, STATUS_SUCCESS);
        break;

    case StorageAccessAlignmentProperty: {
        if (Query->QueryType == PropertyStandardQuery) {
            PSTORAGE_ACCESS_ALIGNMENT_DESCRIPTOR AccessAlignment;

            if (StackLocation->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR))
                return PdoCompleteIrp(Pdo, Irp, STATUS_BUFFER_OVERFLOW);

            AccessAlignment = Irp->AssociatedIrp.SystemBuffer;

            RtlZeroMemory(AccessAlignment, sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR));

            AccessAlignment->Version = sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
            AccessAlignment->Size = sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
            AccessAlignment->BytesPerCacheLine = 0;
            AccessAlignment->BytesOffsetForCacheAlignment = 0;
            AccessAlignment->BytesPerLogicalSector = Pdo->SectorSize;
            AccessAlignment->BytesPerPhysicalSector = Pdo->PhysSectorSize;
            AccessAlignment->BytesOffsetForSectorAlignment = 0;

            Irp->IoStatus.Information = sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR);
        } else {
            Irp->IoStatus.Information = 0;
        }

        status = PdoCompleteIrp(Pdo, Irp, STATUS_SUCCESS);
        break;
    }
    default:
        status = PdoForwardIrpAndForget(Pdo, Irp);
        break;
    }

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoManageDataSetAttributes(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PDEVICE_MANAGE_DATA_SET_ATTRIBUTES  Attributes;
    PDEVICE_DATA_SET_RANGE              Ranges;
    ULONG                               NumRanges;
    NTSTATUS                            status;

    Attributes = Irp->AssociatedIrp.SystemBuffer;

    switch (Attributes->Action) {
    case DeviceDsmAction_Trim:
        if (!Pdo->InterceptTrim) {
            status = PdoForwardIrpAndForget(Pdo, Irp);
            break;
        }

        Ranges = (PDEVICE_DATA_SET_RANGE)((PUCHAR)Attributes + Attributes->DataSetRangesOffset);
        NumRanges = Attributes->DataSetRangesLength / sizeof(DEVICE_DATA_SET_RANGE);

        status = PdoSendTrimSynchronous(Pdo, Ranges, NumRanges);

        status = PdoCompleteIrp(Pdo, Irp, status);
        break;

    default:
        status = PdoForwardIrpAndForget(Pdo, Irp);
        break;
    }

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchControl(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    ULONG               ControlCode;
    ULONG               Method;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    ControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;
    Method = METHOD_FROM_CTL_CODE(ControlCode);

    switch (ControlCode) {
    case IOCTL_STORAGE_QUERY_PROPERTY:
        ASSERT(Method == METHOD_BUFFERED);
        status = PdoQueryProperty(Pdo, Irp);
        break;

    case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:
        ASSERT(Method == METHOD_BUFFERED);
        status = PdoManageDataSetAttributes(Pdo, Irp);
        break;

    default:
        status = PdoForwardIrpAndForget(Pdo, Irp);
        break;
    }

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoStartDevice(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    ULONG               SectorSize;
    ULONG               PhysSectorSize;
    ULONG64             SectorCount;
    ULONG64             Size;
    POWER_STATE         PowerState;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = PdoSendReadCapacity16Synchronous(Pdo,
                                              &SectorSize,
                                              &PhysSectorSize,
                                              &SectorCount);
    if (!NT_SUCCESS(status))
        goto fail3;

    Pdo->SectorSize = SectorSize;
    Pdo->PhysSectorSize = PhysSectorSize;

    Size = SectorSize * SectorCount;
    Size >>= 20; // Scale to megabytes

    Verbose("%s: %luMB (%uB sectors)\n",
            __PdoGetName(Pdo), Size, SectorSize);

    __PdoSetSystemPowerState(Pdo, PowerSystemWorking);
    __PdoSetDevicePowerState(Pdo, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(Pdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePnpState(Pdo, Started);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoQueryStopDevice(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryStopDevice(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoSetDevicePnpState(Pdo, StopPending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __PdoQueryStopDevice,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoCancelStopDevice(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoCancelStopDevice(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    Irp->IoStatus.Status = STATUS_SUCCESS;

    __PdoRestoreDevicePnpState(Pdo, StopPending);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __PdoCancelStopDevice,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoStopDevice(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    Pdo->PhysSectorSize = 0;
    Pdo->SectorSize = 0;

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoStopDevice(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    POWER_STATE         PowerState;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    __PdoSetDevicePowerState(Pdo, PowerDeviceD3);
    __PdoSetSystemPowerState(Pdo, PowerSystemShutdown);

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(Pdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

done:
    __PdoSetDevicePnpState(Pdo, Stopped);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __PdoStopDevice,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoQueryRemoveDevice(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryRemoveDevice(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoSetDevicePnpState(Pdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __PdoQueryRemoveDevice,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoCancelRemoveDevice(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoCancelRemoveDevice(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoRestoreDevicePnpState(Pdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __PdoCancelRemoveDevice,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoSurpriseRemoval(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoSurpriseRemoval(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoSetDevicePnpState(Pdo, SurpriseRemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __PdoSurpriseRemoval,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoRemoveDevice(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PXENDISK_FDO        Fdo = __PdoGetFdo(Pdo);
    POWER_STATE         PowerState;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    __PdoSetDevicePowerState(Pdo, PowerDeviceD3);
    __PdoSetSystemPowerState(Pdo, PowerSystemShutdown);

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(Pdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

done:
    FdoAcquireMutex(Fdo);
    __PdoSetDevicePnpState(Pdo, Deleted);
    FdoReleaseMutex(Fdo);

    IoReleaseRemoveLockAndWait(&Pdo->Dx->RemoveLock, Irp);

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Pdo->PhysSectorSize = 0;
    Pdo->SectorSize = 0;

    FdoAcquireMutex(Fdo);
    PdoDestroy(Pdo);
    FdoReleaseMutex(Fdo);

    IoInvalidateDeviceRelations(FdoGetPhysicalDeviceObject(Fdo),
                                BusRelations);

    return status;

fail1:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoEject(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PXENDISK_FDO        Fdo = __PdoGetFdo(Pdo);
    NTSTATUS            status;

    __PdoSetDevicePnpState(Pdo, Deleted);

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    FdoAcquireMutex(Fdo);
    PdoDestroy(Pdo);
    FdoReleaseMutex(Fdo);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoDispatchPnp(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchPnp(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    switch (StackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
        status = PdoStartDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        status = PdoQueryStopDevice(Pdo, Irp);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        status = PdoCancelStopDevice(Pdo, Irp);
        break;

    case IRP_MN_STOP_DEVICE:
        status = PdoStopDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        status = PdoQueryRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        status = PdoSurpriseRemoval(Pdo, Irp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        status = PdoRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        status = PdoCancelRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_EJECT:
        status = PdoEject(Pdo, Irp);
        break;

    default:
        status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
        if (!NT_SUCCESS(status))
            goto fail1;

        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               __PdoDispatchPnp,
                               Pdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Pdo->LowerDeviceObject, Irp);
        break;
    }

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetDevicePowerUp(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __PdoGetDevicePowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Verbose("%s: %s -> %s\n",
            __PdoGetName(Pdo),
            PowerDeviceStateName(__PdoGetDevicePowerState(Pdo)),
            PowerDeviceStateName(DeviceState));

    __PdoSetDevicePowerState(Pdo, DeviceState);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetDevicePowerDown(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __PdoGetDevicePowerState(Pdo));

    Verbose("%s: %s -> %s\n",
            __PdoGetName(Pdo),
            PowerDeviceStateName(__PdoGetDevicePowerState(Pdo)),
            PowerDeviceStateName(DeviceState));

    __PdoSetDevicePowerState(Pdo, DeviceState);

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetDevicePower(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerDeviceStateName(DeviceState),
          PowerActionName(PowerAction));

    if (DeviceState == __PdoGetDevicePowerState(Pdo)) {
        status = PdoForwardIrpSynchronously(Pdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (DeviceState < __PdoGetDevicePowerState(Pdo)) ?
             __PdoSetDevicePowerUp(Pdo, Irp) :
             __PdoSetDevicePowerDown(Pdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerDeviceStateName(DeviceState),
          PowerActionName(PowerAction),
          status);
    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetSystemPowerUp(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __PdoGetSystemPowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Verbose("%s: %s -> %s\n",
            __PdoGetName(Pdo),
            PowerSystemStateName(__PdoGetSystemPowerState(Pdo)),
            PowerSystemStateName(SystemState));

    __PdoSetSystemPowerState(Pdo, SystemState);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetSystemPowerDown(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __PdoGetSystemPowerState(Pdo));

    Verbose("%s: %s -> %s\n",
            __PdoGetName(Pdo),
            PowerSystemStateName(__PdoGetSystemPowerState(Pdo)),
            PowerSystemStateName(SystemState));

    __PdoSetSystemPowerState(Pdo, SystemState);

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetSystemPower(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerSystemStateName(SystemState),
          PowerActionName(PowerAction));

    if (SystemState == __PdoGetSystemPowerState(Pdo)) {
        status = PdoForwardIrpSynchronously(Pdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (SystemState < __PdoGetSystemPowerState(Pdo)) ?
             __PdoSetSystemPowerUp(Pdo, Irp) :
             __PdoSetSystemPowerDown(Pdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerSystemStateName(SystemState),
          PowerActionName(PowerAction),
          status);
    return status;
}

static FORCEINLINE NTSTATUS
__PdoQueryDevicePowerUp(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __PdoGetDevicePowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoQueryDevicePowerDown(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __PdoGetDevicePowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoQueryDevicePower(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerDeviceStateName(DeviceState),
          PowerActionName(PowerAction));

    if (DeviceState == __PdoGetDevicePowerState(Pdo)) {
        status = PdoForwardIrpSynchronously(Pdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (DeviceState < __PdoGetDevicePowerState(Pdo)) ?
             __PdoQueryDevicePowerUp(Pdo, Irp) :
             __PdoQueryDevicePowerDown(Pdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerDeviceStateName(DeviceState),
          PowerActionName(PowerAction),
          status);
    return status;
}

static FORCEINLINE NTSTATUS
__PdoQuerySystemPowerUp(
    IN  PXENDISK_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __PdoGetSystemPowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoQuerySystemPowerDown(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __PdoGetSystemPowerState(Pdo));

    status = PdoForwardIrpSynchronously(Pdo, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoQuerySystemPower(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerSystemStateName(SystemState),
          PowerActionName(PowerAction));

    if (SystemState == __PdoGetSystemPowerState(Pdo)) {
        status = PdoForwardIrpSynchronously(Pdo, Irp);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    status = (SystemState < __PdoGetSystemPowerState(Pdo)) ?
             __PdoQuerySystemPowerUp(Pdo, Irp) :
             __PdoQuerySystemPowerDown(Pdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerSystemStateName(SystemState),
          PowerActionName(PowerAction),
          status);

    return status;
}

static NTSTATUS
PdoDevicePower(
    IN  PXENDISK_THREAD Self,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  StackLocation;
        UCHAR               MinorFunction;

        if (Pdo->DevicePowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Pdo->DevicePowerIrp;

        if (Irp == NULL)
            continue;

        Pdo->DevicePowerIrp = NULL;
        KeMemoryBarrier();

        StackLocation = IoGetCurrentIrpStackLocation(Irp);
        MinorFunction = StackLocation->MinorFunction;

        switch (StackLocation->MinorFunction) {
        case IRP_MN_SET_POWER:
            (VOID) __PdoSetDevicePower(Pdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) __PdoQueryDevicePower(Pdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }

        IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSystemPower(
    IN  PXENDISK_THREAD Self,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  StackLocation;
        UCHAR               MinorFunction;

        if (Pdo->SystemPowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Pdo->SystemPowerIrp;

        if (Irp == NULL)
            continue;

        Pdo->SystemPowerIrp = NULL;
        KeMemoryBarrier();

        StackLocation = IoGetCurrentIrpStackLocation(Irp);
        MinorFunction = StackLocation->MinorFunction;

        switch (StackLocation->MinorFunction) {
        case IRP_MN_SET_POWER:
            (VOID) __PdoSetSystemPower(Pdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) __PdoQuerySystemPower(Pdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }

        IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    }

    return STATUS_SUCCESS;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoDispatchPower(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchPower(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    POWER_STATE_TYPE    PowerType;
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    if (MinorFunction != IRP_MN_QUERY_POWER &&
        MinorFunction != IRP_MN_SET_POWER) {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               __PdoDispatchPower,
                               Pdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

        goto done;
    }

    PowerType = StackLocation->Parameters.Power.Type;

    Trace("====> (%02x:%s)\n",
          MinorFunction,
          PowerMinorFunctionName(MinorFunction));

    switch (PowerType) {
    case DevicePowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Pdo->DevicePowerIrp, ==, NULL);
        Pdo->DevicePowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Pdo->DevicePowerThread);

        status = STATUS_PENDING;
        break;

    case SystemPowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Pdo->SystemPowerIrp, ==, NULL);
        Pdo->SystemPowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Pdo->SystemPowerThread);

        status = STATUS_PENDING;
        break;

    default:
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp,
                               __PdoDispatchPower,
                               Pdo,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(Pdo->LowerDeviceObject, Irp);
        break;
    }

    Trace("<==== (%02x:%s) (%08x)\n",
          MinorFunction,
          PowerMinorFunctionName(MinorFunction),
          status);

done:
    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__PdoDispatchDefault(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PXENDISK_PDO        Pdo = Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    IoReleaseRemoveLock(&Pdo->Dx->RemoveLock, Irp);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchDefault(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    status = IoAcquireRemoveLock(&Pdo->Dx->RemoveLock, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __PdoDispatchDefault,
                           Pdo,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Pdo->LowerDeviceObject, Irp);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
PdoDispatch(
    IN  PXENDISK_PDO    Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->MajorFunction) {
    case IRP_MJ_DEVICE_CONTROL:
        status = PdoDispatchControl(Pdo, Irp);
        break;

    case IRP_MJ_PNP:
        status = PdoDispatchPnp(Pdo, Irp);
        break;

    case IRP_MJ_POWER:
        status = PdoDispatchPower(Pdo, Irp);
        break;

    default:
        status = PdoDispatchDefault(Pdo, Irp);
        break;
    }

    return status;
}

NTSTATUS
PdoCreate(
    IN  PXENDISK_FDO    Fdo,
    IN  PDEVICE_OBJECT  PhysicalDeviceObject,
    IN  PCHAR           DeviceID,
    IN  PCHAR           InstanceID
    )
{
    PDEVICE_OBJECT      LowerDeviceObject;
    ULONG               DeviceType;
    PDEVICE_OBJECT      FilterDeviceObject;
    PXENDISK_DX         Dx;
    PXENDISK_PDO        Pdo;
    HANDLE              ParametersKey;
    ULONG               InterceptTrim;
    NTSTATUS            status;

    LowerDeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);
    DeviceType = LowerDeviceObject->DeviceType;
    ObDereferenceObject(LowerDeviceObject);

#pragma prefast(suppress:28197) // Possibly leaking memory 'PhysicalDeviceObject'
    status = IoCreateDevice(DriverGetDriverObject(),
                            sizeof(XENDISK_DX),
                            NULL,
                            DeviceType,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &FilterDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENDISK_DX)FilterDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENDISK_DX));

    Dx->Type = PHYSICAL_DEVICE_OBJECT;
    Dx->DeviceObject = FilterDeviceObject;
    Dx->DevicePnpState = Present;
    Dx->SystemPowerState = PowerSystemShutdown;
    Dx->DevicePowerState = PowerDeviceD3;

    IoInitializeRemoveLock(&Dx->RemoveLock, PDO_TAG, 0, 0);

    Pdo = __PdoAllocate(sizeof (XENDISK_PDO));

    status = STATUS_NO_MEMORY;
    if (Pdo == NULL)
        goto fail2;

    LowerDeviceObject = IoAttachDeviceToDeviceStack(FilterDeviceObject,
                                                    PhysicalDeviceObject);

    status = STATUS_UNSUCCESSFUL;
    if (LowerDeviceObject == NULL)
        goto fail3;

    Pdo->Dx = Dx;
    Pdo->PhysicalDeviceObject = PhysicalDeviceObject;
    Pdo->LowerDeviceObject = LowerDeviceObject;

    status = ThreadCreate(PdoSystemPower, Pdo, &Pdo->SystemPowerThread);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = ThreadCreate(PdoDevicePower, Pdo, &Pdo->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail5;

    __PdoSetName(Pdo, DeviceID, InstanceID);

    ParametersKey = DriverGetParametersKey();

    Pdo->InterceptTrim = TRUE;

    status = RegistryQueryDwordValue(ParametersKey,
                                     "InterceptTrim",
                                     &InterceptTrim);
    if (NT_SUCCESS(status))
        Pdo->InterceptTrim = (InterceptTrim != 0) ? TRUE : FALSE;

    Verbose("%p (%s)\n", FilterDeviceObject, __PdoGetName(Pdo));

    Dx->Pdo = Pdo;

#pragma prefast(suppress:28182) // Dereferencing NULL pointer
    FilterDeviceObject->DeviceType = LowerDeviceObject->DeviceType;
    FilterDeviceObject->Characteristics = LowerDeviceObject->Characteristics;

    FilterDeviceObject->Flags |= LowerDeviceObject->Flags;
    FilterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    __PdoLink(Pdo, Fdo);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

fail4:
    Error("fail4\n");

    Pdo->PhysicalDeviceObject = NULL;
    Pdo->LowerDeviceObject = NULL;
    Pdo->Dx = NULL;

    IoDetachDevice(LowerDeviceObject);

fail3:
    Error("fail3\n");

    ASSERT(IsZeroMemory(Pdo, sizeof (XENDISK_PDO)));
    __PdoFree(Pdo);

fail2:
    Error("fail2\n");

    IoDeleteDevice(FilterDeviceObject);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
PdoDestroy(
    IN  PXENDISK_PDO    Pdo
    )
{
    PDEVICE_OBJECT      LowerDeviceObject = Pdo->LowerDeviceObject;
    PXENDISK_DX         Dx = Pdo->Dx;
    PDEVICE_OBJECT      FilterDeviceObject = Dx->DeviceObject;

    ASSERT3U(__PdoGetDevicePnpState(Pdo), ==, Deleted);

    __PdoUnlink(Pdo);

    Verbose("%s\n", __PdoGetName(Pdo));

    Dx->Pdo = NULL;

    Pdo->InterceptTrim = FALSE;

    RtlZeroMemory(Pdo->Name, sizeof (Pdo->Name));

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

    Pdo->PhysicalDeviceObject = NULL;
    Pdo->LowerDeviceObject = NULL;
    Pdo->Dx = NULL;

    IoDetachDevice(LowerDeviceObject);

    ASSERT(IsZeroMemory(Pdo, sizeof (XENDISK_PDO)));
    __PdoFree(Pdo);

    IoDeleteDevice(FilterDeviceObject);
}
