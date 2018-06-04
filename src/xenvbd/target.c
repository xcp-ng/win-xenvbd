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

#include <ntddk.h>
#include <ntstrsafe.h>
#include <storport.h>
#include <stdlib.h>

#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>

#include "target.h"
#include "driver.h"
#include "adapter.h"
#include "frontend.h"
#include "srbext.h"

#include "debug.h"
#include "assert.h"
#include "util.h"

struct _XENVBD_TARGET {
    PXENVBD_ADAPTER             Adapter;
    PDEVICE_OBJECT              DeviceObject;
    DEVICE_PNP_STATE            DevicePnpState;
    DEVICE_PNP_STATE            PrevPnpState;
    DEVICE_POWER_STATE          DevicePowerState;
    KSPIN_LOCK                  Lock;

    // Frontend (Ring, includes XenBus interfaces)
    PXENVBD_FRONTEND            Frontend;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;

    // Eject
    BOOLEAN                     WrittenEjected;
    BOOLEAN                     EjectRequested;
    BOOLEAN                     EjectPending;
    BOOLEAN                     Missing;
    const CHAR*                 Reason;
};

#define TARGET_POOL_TAG            'odPX'

__checkReturn
__drv_allocatesMem(mem)
__bcount(Size)
static FORCEINLINE PVOID
#pragma warning(suppress: 28195)
__TargetAlloc(
    __in ULONG  Size
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Size, TARGET_POOL_TAG);
}

static FORCEINLINE VOID
#pragma warning(suppress: 28197)
__TargetFree(
    __in __drv_freesMem(mem) PVOID Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, TARGET_POOL_TAG);
}

static FORCEINLINE PCHAR
__PnpStateName(
    __in DEVICE_PNP_STATE        State
    )
{
    switch (State) {
    case Invalid:               return "Invalid";
    case Present:               return "Present";
    case Enumerated:            return "Enumerated";
    case Added:                 return "Added";
    case Started:               return "Started";
    case StopPending:           return "StopPending";
    case Stopped:               return "Stopped";
    case RemovePending:         return "RemovePending";
    case SurpriseRemovePending: return "SurpriseRemovePending";
    case Deleted:               return "Deleted";
    default:                    return "UNKNOWN";
    }
}

__checkReturn
static FORCEINLINE BOOLEAN
TargetSetDevicePowerState(
    __in PXENVBD_TARGET             Target,
    __in DEVICE_POWER_STATE      State
    )
{
    KIRQL       Irql;
    BOOLEAN     Changed = FALSE;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->DevicePowerState != State) {
        Verbose("Target[%d] : POWER %s to %s\n", TargetGetTargetId(Target), PowerDeviceStateName(Target->DevicePowerState), PowerDeviceStateName(State));
        Target->DevicePowerState = State;
        Changed = TRUE;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);

    return Changed;
}

VOID
TargetSetMissing(
    IN  PXENVBD_TARGET  Target,
    IN  const CHAR      *Reason
    )
{
    KIRQL               Irql;

    ASSERT3P(Reason, !=, NULL);

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->Missing) {
        Verbose("Target[%d] : Already MISSING (%s) when trying to set (%s)\n",
                TargetGetTargetId(Target),
                Target->Reason,
                Reason);
    } else {
        Verbose("Target[%d] : MISSING %s\n",
                TargetGetTargetId(Target),
                Reason);
        Target->Missing = TRUE;
        Target->Reason = Reason;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);
}

VOID
TargetSetDevicePnpState(
    IN  PXENVBD_TARGET      Target,
    IN  DEVICE_PNP_STATE    State
    )
{
    Verbose("Target[%d] : PNP %s to %s\n",
            TargetGetTargetId(Target),
            __PnpStateName(Target->DevicePnpState),
            __PnpStateName(State));

    if (Target->DevicePnpState == Deleted)
        return;

    Target->PrevPnpState = Target->DevicePnpState;
    Target->DevicePnpState = State;
}

static FORCEINLINE VOID
__TargetRestoreDevicePnpState(
    __in PXENVBD_TARGET             Target,
    __in DEVICE_PNP_STATE        State
    )
{
    if (Target->DevicePnpState == State) {
        Verbose("Target[%d] : PNP %s to %s\n", TargetGetTargetId(Target), __PnpStateName(Target->DevicePnpState), __PnpStateName(Target->PrevPnpState));
        Target->DevicePnpState = Target->PrevPnpState;
    }
}

VOID
TargetSetDeviceObject(
    IN  PXENVBD_TARGET  Target,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    Verbose("Target[%d] : Setting DeviceObject = 0x%p\n",
            TargetGetTargetId(Target),
            DeviceObject);

    ASSERT3P(Target->DeviceObject, ==, NULL);
    Target->DeviceObject = DeviceObject;
}

static DECLSPEC_NOINLINE BOOLEAN
TargetReadWrite(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT          SrbExt = Srb->SrbExtension;
    PXENVBD_FRONTEND        Frontend = Target->Frontend;
    PXENVBD_RING            Ring = FrontendGetRing(Frontend);
    ULONG64                 SectorCount;
    ULONG64                 SectorStart;
    ULONG                   NumSectors;

    Srb->SrbStatus = SRB_STATUS_ERROR;
    if (!FrontendGetConnected(Frontend))
        goto fail1;

    // disallow writes to read-only disks
    if (FrontendGetReadOnly(Frontend) &&
        Cdb_OperationEx(Srb) == SCSIOP_WRITE)
        goto fail2;

    // check Sectors requested is on the disk
    SectorCount = FrontendGetDiskInfo(Frontend)->SectorCount;
    SectorStart = Cdb_LogicalBlock(Srb);
    NumSectors = Cdb_TransferBlock(Srb);

    if (SectorStart >= SectorCount)
        goto fail3;
    if ((SectorStart + NumSectors) > SectorCount)
        goto fail4;

    Srb->SrbStatus = SRB_STATUS_PENDING;
    return RingQueueRequest(Ring, SrbExt);

fail4:
     Error("fail4\n");
fail3:
    Error("fail3\n");
fail2:
    Error("fail2\n");
fail1:
    Error("fail1\n");
    return FALSE; // not-queued
}

static DECLSPEC_NOINLINE BOOLEAN
TargetSyncCache(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT          SrbExt = Srb->SrbExtension;
    PXENVBD_FRONTEND        Frontend = Target->Frontend;
    PXENVBD_RING            Ring = FrontendGetRing(Frontend);

    Srb->SrbStatus = SRB_STATUS_ERROR;
    if (!FrontendGetConnected(Frontend))
        goto fail1;

    if (FrontendGetReadOnly(Frontend))
        goto fail2;

    // If neither FLUSH or BARRIER is supported, just succceed the SRB
    if (!(FrontendGetFlushCache(Frontend) ||
          FrontendGetBarrier(Frontend)))
        goto succeed;

    Srb->SrbStatus = SRB_STATUS_PENDING;
    return RingQueueRequest(Ring, SrbExt);

succeed:
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    return FALSE; // not-queued

fail2:
    Error("fail2\n");
fail1:
    Error("fail1\n");
    return FALSE; // not-queued
}

static DECLSPEC_NOINLINE BOOLEAN
TargetUnmap(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_SRBEXT          SrbExt = Srb->SrbExtension;
    PXENVBD_FRONTEND        Frontend = Target->Frontend;
    PXENVBD_RING            Ring = FrontendGetRing(Frontend);

    Srb->SrbStatus = SRB_STATUS_ERROR;
    if (!FrontendGetConnected(Frontend))
        goto fail1;

    if (FrontendGetReadOnly(Frontend))
        goto fail2;

    if (!FrontendGetDiscard(Frontend))
        goto succeed;

    Srb->SrbStatus = SRB_STATUS_PENDING;
    return RingQueueRequest(Ring, SrbExt);

succeed:
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    return FALSE; // not-queued

fail2:
    Error("fail2\n");
fail1:
    Error("fail1\n");
    return FALSE; // not-queued
}

static FORCEINLINE VOID
__TargetModeSense(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb,
    IN  PVOID               Data,
    IN  ULONG               Length,
    OUT PULONG              Size,
    OUT PULONG              ModeDataLength,
    OUT PULONG              BlockDescrLength
    )
{
    const UCHAR             PageCode = Cdb_PageCode(Srb);

    // Fill in Block Parameters (if Specified and space)
    // when the DBD (Disable Block Descriptor) is set, ignore the block page
    if (Cdb_Dbd(Srb) == 0 &&
        Length - *Size >= sizeof(MODE_PARAMETER_BLOCK)) {
        // PMODE_PARAMETER_BLOCK Block = (PMODE_PARAMETER_BLOCK)((PUCHAR)Data + *Size);

        // Fill in BlockParams - All Zeroes

        *BlockDescrLength   = sizeof(MODE_PARAMETER_BLOCK);
        *ModeDataLength     += sizeof(MODE_PARAMETER_BLOCK);
        *Size               += sizeof(MODE_PARAMETER_BLOCK);
    }

    // Fill in Cache Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_CACHING || PageCode == MODE_SENSE_RETURN_ALL) &&
        Length - *Size >= sizeof(MODE_CACHING_PAGE)) {
        PMODE_CACHING_PAGE Caching = (PMODE_CACHING_PAGE)((PUCHAR)Data + *Size);

        // Fill in CachingParams
        Caching->PageCode           = MODE_PAGE_CACHING;
        Caching->PageLength         = sizeof(MODE_CACHING_PAGE);
        Caching->WriteCacheEnable   = FrontendGetFlushCache(Target->Frontend) ? 1 : 0;

        *ModeDataLength += sizeof(MODE_CACHING_PAGE);
        *Size           += sizeof(MODE_CACHING_PAGE);
    }

    // Fill in Informational Exception Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_FAULT_REPORTING || PageCode == MODE_SENSE_RETURN_ALL) &&
        Length - *Size >= sizeof(MODE_INFO_EXCEPTIONS)) {
        PMODE_INFO_EXCEPTIONS Exceptions = (PMODE_INFO_EXCEPTIONS)((PUCHAR)Data + *Size);

        // Fill in Exceptions
        Exceptions->PageCode    = MODE_PAGE_FAULT_REPORTING;
        Exceptions->PageLength  = sizeof(MODE_INFO_EXCEPTIONS);
        Exceptions->Dexcpt      = 1; // disabled

        *ModeDataLength += sizeof(MODE_INFO_EXCEPTIONS);
        *Size           += sizeof(MODE_INFO_EXCEPTIONS);
    }
}

static DECLSPEC_NOINLINE VOID
TargetModeSense(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PMODE_PARAMETER_HEADER  Data  = Srb->DataBuffer;
    ULONG                   Length = Srb->DataTransferLength;
    ULONG                   BlockDescrLength = 0;
    ULONG                   ModeDataLength = 0;
    ULONG                   Size;

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < sizeof(MODE_PARAMETER_HEADER))
        return;

    // Header
    Data->MediumType                = 0;
    Data->DeviceSpecificParameter   = FrontendGetReadOnly(Target->Frontend) ? 
                                                    MODE_DSP_WRITE_PROTECT : 0;
    Size = sizeof(MODE_PARAMETER_HEADER);

    __TargetModeSense(Target,
                      Srb,
                      Data,
                      Length,
                      &Size,
                      &ModeDataLength,
                      &BlockDescrLength);
    ASSERT3U(ModeDataLength, <=, 255 - (sizeof(MODE_PARAMETER_HEADER) - 1));
    ASSERT3U(BlockDescrLength, <=, 255);

    Data->ModeDataLength = (UCHAR)(ModeDataLength + sizeof(MODE_PARAMETER_HEADER) - 1);
    Data->BlockDescriptorLength = (UCHAR)BlockDescrLength;

    ASSERT3U(Size, <=, Length);
    Srb->DataTransferLength = Size;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetModeSense10(
    IN  PXENVBD_TARGET          Target,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PMODE_PARAMETER_HEADER10    Data  = Srb->DataBuffer;
    ULONG                       Length = Srb->DataTransferLength;
    ULONG                       BlockDescrLength = 0;
    ULONG                       ModeDataLength = 0;
    ULONG                       Size;

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < sizeof(MODE_PARAMETER_HEADER10))
        return;

    // Header
    Data->MediumType                = 0;
    Data->DeviceSpecificParameter   = FrontendGetReadOnly(Target->Frontend) ? 
                                                    MODE_DSP_WRITE_PROTECT : 0;
    Size = sizeof(MODE_PARAMETER_HEADER10);

    __TargetModeSense(Target,
                      Srb,
                      Data,
                      Length,
                      &Size,
                      &ModeDataLength,
                      &BlockDescrLength);
    ASSERT3U(ModeDataLength, <=, 65535 - (sizeof(MODE_PARAMETER_HEADER10) - 2));
    ASSERT3U(BlockDescrLength, <=, 65535);

    *(PUSHORT)Data->ModeDataLength = _byteswap_ushort((USHORT)ModeDataLength + 
                                                      sizeof(MODE_PARAMETER_HEADER10) - 2);
    *(PUSHORT)Data->BlockDescriptorLength = _byteswap_ushort((USHORT)BlockDescrLength);

    ASSERT3U(Size, <=, Length);
    Srb->DataTransferLength = Size;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetRequestSense(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PSENSE_DATA             Data = Srb->DataBuffer;
    ULONG                   Length = Srb->DataTransferLength;

    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < sizeof(SENSE_DATA))
        return;

    Data->ErrorCode            = 0x70;
    Data->Valid                = 1;
    Data->AdditionalSenseCodeQualifier = 0;
    Data->SenseKey             = SCSI_SENSE_NO_SENSE;
    Data->AdditionalSenseCode  = SCSI_ADSENSE_NO_SENSE;

    Srb->DataTransferLength     = sizeof(SENSE_DATA);
    Srb->SrbStatus              = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReportLuns(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PLUN_LIST               Data = Srb->DataBuffer;
    ULONG                   Length = Srb->DataTransferLength;

    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < 16)
        return;

    // UCHAR[4] @ Data
    *(PULONG)Data->LunListLength = _byteswap_ulong(8);
    // UCHAR[8] @ Data + 8
    *(PULONG64)Data->Lun[0] = _byteswap_uint64(XENVBD_MAX_TARGETS);

    Srb->DataTransferLength = 16;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReadCapacity(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PREAD_CAPACITY_DATA     Data = Srb->DataBuffer;
    ULONG                   Length = Srb->DataTransferLength;
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   LastBlock;

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < sizeof(READ_CAPACITY_DATA))
        return;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0)
        return;

    SectorCount = DiskInfo->SectorCount;
    SectorSize = DiskInfo->SectorSize;

    if (SectorCount == (ULONG)SectorCount)
        LastBlock = (ULONG)SectorCount - 1;
    else
        LastBlock = ~(ULONG)0;

    Data->LogicalBlockAddress = _byteswap_ulong(LastBlock);
    Data->BytesPerBlock = _byteswap_ulong(SectorSize);

    Srb->DataTransferLength = sizeof(READ_CAPACITY_DATA);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReadCapacity16(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PREAD_CAPACITY16_DATA   Data = Srb->DataBuffer;
    ULONG                   Length = Srb->DataTransferLength;
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   PhysSectorSize;
    ULONG                   LogicalPerPhysical;
    ULONG                   LogicalPerPhysicalExponent;

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < sizeof(READ_CAPACITY16_DATA))
        return;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0)
        return;

    SectorCount = DiskInfo->SectorCount;
    SectorSize = DiskInfo->SectorSize;
    PhysSectorSize = DiskInfo->PhysSectorSize;

    LogicalPerPhysical = PhysSectorSize / SectorSize;

    if (!_BitScanReverse(&LogicalPerPhysicalExponent, LogicalPerPhysical))
        LogicalPerPhysicalExponent = 0;

    Data->LogicalBlockAddress.QuadPart = _byteswap_uint64(SectorCount - 1);
    Data->BytesPerBlock = _byteswap_ulong(SectorSize);
    Data->LogicalPerPhysicalExponent = (UCHAR)LogicalPerPhysicalExponent;

    Srb->DataTransferLength = sizeof(READ_CAPACITY16_DATA);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiryStd(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PINQUIRYDATA            Data = Srb->DataBuffer;
    ULONG                   Length = Srb->DataTransferLength;

    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < INQUIRYDATABUFFERSIZE)
        return;

    RtlZeroMemory(Data, Length);
    Data->DeviceType            = DIRECT_ACCESS_DEVICE;
    Data->DeviceTypeQualifier   = DEVICE_CONNECTED;
    Data->Versions              = 4;
    Data->ResponseDataFormat    = 2;
    Data->AdditionalLength      = INQUIRYDATABUFFERSIZE - 4;
    Data->CommandQueue          = 1;
    RtlCopyMemory(Data->VendorId,               "XENSRC  ", 8);
    RtlCopyMemory(Data->ProductId,              "PVDISK          ", 16);
    RtlCopyMemory(Data->ProductRevisionLevel,   "2.0 ", 4);

    Srb->DataTransferLength = INQUIRYDATABUFFERSIZE;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiry00(
    IN  PXENVBD_TARGET          Target,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PVPD_SUPPORTED_PAGES_PAGE   Data = Srb->DataBuffer;
    ULONG                       Length = Srb->DataTransferLength;

    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < 8)
        return;

    Data->PageLength = 4;
    Data->SupportedPageList[0] = 0x00;
    Data->SupportedPageList[1] = 0x80;
    Data->SupportedPageList[2] = 0x83;
    Data->SupportedPageList[3] = 0xB0;

    Srb->DataTransferLength = 8;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiry80(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PVPD_SERIAL_NUMBER_PAGE Data = Srb->DataBuffer;
    ULONG                   Length = Srb->DataTransferLength;
    PVOID                   Page;
    ULONG                   Size;

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    Page = FrontendGetInquiryOverride(Target->Frontend, 0x80, &Size);
    if (Page && Size) {
        if (Length < Size)
            return;

        RtlCopyMemory(Data, Page, Size);
    } else {
        CHAR                Serial[5];

        if (Length < sizeof(VPD_SERIAL_NUMBER_PAGE) + 4)
            return;

        Data->PageCode      = 0x80;
        Data->PageLength    = 4;
        (VOID) RtlStringCbPrintfA(Serial,
                                  sizeof(Serial),
                                  "%04u",
                                  TargetGetTargetId(Target));
        RtlCopyMemory(Data->SerialNumber, Serial, 4);

        Size = sizeof(VPD_SERIAL_NUMBER_PAGE) + 4;
    }

    Srb->DataTransferLength = Size;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiry83(
    IN  PXENVBD_TARGET          Target,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    PVPD_IDENTIFICATION_PAGE    Data = Srb->DataBuffer;
    ULONG                       Length = Srb->DataTransferLength;
    PVOID                       Page;
    ULONG                       Size;

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    Page = FrontendGetInquiryOverride(Target->Frontend, 0x83, &Size);
    if (Page && Size) {
        if (Length < Size)
            return;

        RtlCopyMemory(Data, Page, Size);
    } else {
        PVPD_IDENTIFICATION_DESCRIPTOR  Id = (PVPD_IDENTIFICATION_DESCRIPTOR)&Data->Descriptors[0];
        CHAR                            Identifier[17];

        if (Length < sizeof(VPD_IDENTIFICATION_PAGE) +
                     sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + 16)
            return;

        Data->PageCode = 0x83;
        Data->PageLength = sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + 16;

        Id->CodeSet         = VpdCodeSetAscii;
        Id->IdentifierType  = VpdIdentifierTypeVendorId;
        Id->IdentifierLength = 16;
        (VOID) RtlStringCbPrintfA(Identifier,
                                  sizeof(Identifier),
                                  "XENSRC  %08u",
                                  TargetGetTargetId(Target));
        RtlCopyMemory(Id->Identifier, Identifier, 16);

        Size = sizeof(VPD_IDENTIFICATION_PAGE) +
               sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + 16;
    }

    Srb->DataTransferLength = Size;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiryB0(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    PVPD_BLOCK_LIMITS_PAGE  Data = Srb->DataBuffer;
    ULONG                   Length = Srb->DataTransferLength;

    Srb->SrbStatus = SRB_STATUS_ERROR;

    if (Data == NULL)
        return;
    RtlZeroMemory(Data, Length);

    if (Length < sizeof(VPD_BLOCK_LIMITS_PAGE))
        return;

    Data->PageCode = 0xB0;
    Data->PageLength[1] = 0x3C; // as per spec

    *(PULONG)Data->OptimalUnmapGranularity = _byteswap_ulong(DiskInfo->DiscardGranularity);
    *(PULONG)Data->UnmapGranularityAlignment = _byteswap_ulong(DiskInfo->DiscardAlignment);
    // alignment is only valid if a granularity has been set
    Data->UGAValid = (DiskInfo->DiscardGranularity != 0) ? 1 : 0;

    Srb->DataTransferLength = sizeof(VPD_BLOCK_LIMITS_PAGE);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetInquiry(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    if (Cdb_EVPD(Srb)) {
        switch (Cdb_PageCode(Srb)) {
        case 0x00:  TargetInquiry00(Target, Srb);       break;
        case 0x80:  TargetInquiry80(Target, Srb);       break;
        case 0x83:  TargetInquiry83(Target, Srb);       break;
        case 0xB0:  TargetInquiryB0(Target, Srb);       break;
        default:    Srb->SrbStatus = SRB_STATUS_ERROR;  break;
        }
    } else {
        switch (Cdb_PageCode(Srb)) {
        case 0x00:  TargetInquiryStd(Target, Srb);      break;
        default:    Srb->SrbStatus = SRB_STATUS_ERROR;  break;
        }
    }
}

static FORCEINLINE BOOLEAN
__ValidateSrbForTarget(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    const UCHAR             Operation = Cdb_OperationEx(Srb);

    if (Srb->PathId != 0) {
        Error("Target[%d] : Invalid PathId(%d) (%02x:%s)\n",
              TargetGetTargetId(Target),
              Srb->PathId,
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_PATH_ID;
        return FALSE;
    }

    if (Srb->Lun != 0) {
        Error("Target[%d] : Invalid Lun(%d) (%02x:%s)\n",
              TargetGetTargetId(Target),
              Srb->Lun,
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_LUN;
        return FALSE;
    }

    if (TargetGetMissing(Target)) {
        Error("Target[%d] : %s (%s) (%02x:%s)\n",
              TargetGetTargetId(Target),
              Target->Missing ? "MISSING" : "NOT_MISSING",
              Target->Reason,
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        return FALSE;
    }

    return TRUE;
}

VOID
TargetPrepareIo(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

    if (!__ValidateSrbForTarget(Target, Srb))
        return;

    Srb->SrbStatus = SRB_STATUS_PENDING;
}

BOOLEAN
TargetStartIo(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    const UCHAR         Operation = Cdb_OperationEx(Srb);
    BOOLEAN             WasQueued = FALSE;

    ASSERT(__ValidateSrbForTarget(Target, Srb));

    switch (Operation) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        WasQueued = TargetReadWrite(Target, Srb);
        break;

    case SCSIOP_UNMAP:
        WasQueued = TargetUnmap(Target, Srb);
        break;

    case SCSIOP_SYNCHRONIZE_CACHE:
        WasQueued = TargetSyncCache(Target, Srb);
        break;

    case SCSIOP_INQUIRY:
        AdapterSetDeviceQueueDepth(TargetGetAdapter(Target),
                                   TargetGetTargetId(Target));
        TargetInquiry(Target, Srb);
        break;

    case SCSIOP_MODE_SENSE:
        TargetModeSense(Target, Srb);
        break;

    case SCSIOP_MODE_SENSE10:
        TargetModeSense10(Target, Srb);
        break;

    case SCSIOP_REQUEST_SENSE:
        TargetRequestSense(Target, Srb);
        break;

    case SCSIOP_REPORT_LUNS:
        TargetReportLuns(Target, Srb);
        break;

    case SCSIOP_READ_CAPACITY:
        TargetReadCapacity(Target, Srb);
        break;

    case SCSIOP_READ_CAPACITY16:
        TargetReadCapacity16(Target, Srb);
        break;

    case SCSIOP_MEDIUM_REMOVAL:
    case SCSIOP_TEST_UNIT_READY:
    case SCSIOP_RESERVE_UNIT:
    case SCSIOP_RESERVE_UNIT10:
    case SCSIOP_RELEASE_UNIT:
    case SCSIOP_RELEASE_UNIT10:
    case SCSIOP_VERIFY:
    case SCSIOP_VERIFY16:
    case SCSIOP_START_STOP_UNIT:
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    default:
        Trace("Target[%d] : Unsupported CDB (%02x:%s)\n",
              TargetGetTargetId(Target),
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }
    return WasQueued;
}

VOID
TargetReset(
    IN  PXENVBD_TARGET  Target
    )
{
    Verbose("[%u] =====>\n", TargetGetTargetId(Target));

    FrontendReset(Target->Frontend);

    Verbose("[%u] <=====\n", TargetGetTargetId(Target));
}

VOID
TargetFlush(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    RingQueueShutdown(FrontendGetRing(Target->Frontend), SrbExt);
}

VOID
TargetShutdown(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    RingQueueShutdown(FrontendGetRing(Target->Frontend), SrbExt);
}

VOID
TargetIssueDeviceEject(
    IN  PXENVBD_TARGET  Target,
    IN  const CHAR      *Reason
    )
{
    KIRQL               Irql;
    BOOLEAN             DoEject = FALSE;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->DeviceObject) {
        DoEject = TRUE;
        Target->EjectRequested = TRUE;
    } else {
        Target->EjectPending = TRUE;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);

    Verbose("Target[%d] : Ejecting (%s - %s)\n",
            TargetGetTargetId(Target),
            DoEject ? "Now" : "Next PnP IRP",
            Reason);
    if (!Target->WrittenEjected) {
        Target->WrittenEjected = TRUE;
        FrontendSetEjected(Target->Frontend);
    }
    if (DoEject) {
        Verbose("Target[%d] : IoRequestDeviceEject(0x%p)\n",
                TargetGetTargetId(Target),
                Target->DeviceObject);
        IoRequestDeviceEject(Target->DeviceObject);
    } else {
        Verbose("Target[%d] : Triggering BusChangeDetected to detect device\n",
                TargetGetTargetId(Target));
        AdapterTargetListChanged(TargetGetAdapter(Target));
    }
}

static FORCEINLINE VOID
__TargetDeviceUsageNotification(
    IN  PXENVBD_TARGET              Target,
    IN  PIRP                        Irp
    )
{
    PIO_STACK_LOCATION              StackLocation;
    BOOLEAN                         Value;
    DEVICE_USAGE_NOTIFICATION_TYPE  Type;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Value = StackLocation->Parameters.UsageNotification.InPath;
    Type  = StackLocation->Parameters.UsageNotification.Type;

    FrontendSetDeviceUsage(Target->Frontend,
                           Type,
                           Value);
}

static FORCEINLINE VOID
__TargetCheckEjectPending(
    IN  PXENVBD_TARGET  Target
    )
{
    KIRQL               Irql;
    BOOLEAN             EjectPending = FALSE;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->EjectPending) {
        EjectPending = TRUE;
        Target->EjectPending = FALSE;
        Target->EjectRequested = TRUE;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);

    if (EjectPending) {
        Verbose("Target[%d] : IoRequestDeviceEject(0x%p)\n",
                TargetGetTargetId(Target),
                Target->DeviceObject);
        IoRequestDeviceEject(Target->DeviceObject);
    }
}

static FORCEINLINE VOID
__TargetCheckEjectFailed(
    IN  PXENVBD_TARGET  Target
    )
{
    KIRQL               Irql;
    BOOLEAN             EjectFailed = FALSE;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    if (Target->EjectRequested) {
        EjectFailed = TRUE;
        Target->EjectRequested = FALSE;
    }
    KeReleaseSpinLock(&Target->Lock, Irql);

    if (EjectFailed) {
        Error("Target[%d] : Unplug failed due to open handle(s)!\n",
              TargetGetTargetId(Target));
        FrontendSetEjectFailed(Target->Frontend);
    }
}

static FORCEINLINE VOID
__TargetRemoveDevice(
    IN  PXENVBD_TARGET  Target
    )
{
    TargetD0ToD3(Target);

    switch (TargetGetDevicePnpState(Target)) {
    case SurpriseRemovePending:
        TargetSetMissing(Target, "Surprise Remove");
        break;

    default:
        TargetSetMissing(Target, "Removed");
        break;
    }

    TargetSetDevicePnpState(Target, Deleted);
    AdapterTargetListChanged(TargetGetAdapter(Target));
}

static FORCEINLINE VOID
__TargetEject(
    IN  PXENVBD_TARGET  Target
    )
{
    TargetSetMissing(Target, "Ejected");
    TargetSetDevicePnpState(Target, Deleted);
    AdapterTargetListChanged(TargetGetAdapter(Target));
}

NTSTATUS
TargetDispatchPnp(
    IN  PXENVBD_TARGET  Target,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    __TargetCheckEjectPending(Target);

    switch (StackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
        (VOID) TargetD3ToD0(Target);
        TargetSetDevicePnpState(Target, Started);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        TargetSetDevicePnpState(Target, StopPending);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        __TargetRestoreDevicePnpState(Target, StopPending);
        break;

    case IRP_MN_STOP_DEVICE:
        TargetD0ToD3(Target);
        TargetSetDevicePnpState(Target, Stopped);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        TargetSetDevicePnpState(Target, RemovePending);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        __TargetCheckEjectFailed(Target);
        __TargetRestoreDevicePnpState(Target, RemovePending);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        TargetSetDevicePnpState(Target, SurpriseRemovePending);
        break;

    case IRP_MN_REMOVE_DEVICE:
        __TargetRemoveDevice(Target);
        break;

    case IRP_MN_EJECT:
        __TargetEject(Target);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        __TargetDeviceUsageNotification(Target, Irp);
        break;

    default:
        break;
    }
    return DriverDispatchPnp(DeviceObject, Irp);
}

static DECLSPEC_NOINLINE VOID
TargetDebugCallback(
    IN  PVOID       Argument,
    IN  BOOLEAN     Crashing
    )
{
    PXENVBD_TARGET  Target = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "TARGET: Adapter 0x%p DeviceObject 0x%p\n",
                 Target->Adapter,
                 Target->DeviceObject);
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "TARGET: DevicePnpState %s (%s)\n",
                 __PnpStateName(Target->DevicePnpState),
                 __PnpStateName(Target->PrevPnpState));
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "TARGET: DevicePowerState %s\n",
                 PowerDeviceStateName(Target->DevicePowerState));
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "TARGET: %s\n",
                 Target->Missing ? Target->Reason : "Not Missing");
}

NTSTATUS
TargetD3ToD0(
    IN  PXENVBD_TARGET  Target
    )
{
    NTSTATUS            status;
    const ULONG         TargetId = TargetGetTargetId(Target);

    if (!TargetSetDevicePowerState(Target, PowerDeviceD0))
        return STATUS_SUCCESS;

    Verbose("Target[%d] : D3->D0\n", TargetId);

    AdapterGetDebugInterface(TargetGetAdapter(Target),
                             &Target->DebugInterface);

    status = XENBUS_DEBUG(Acquire, &Target->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Register,
                          &Target->DebugInterface,
                          __MODULE__,
                          TargetDebugCallback,
                          Target,
                          &Target->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = FrontendD3ToD0(Target->Frontend);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = FrontendSetState(Target->Frontend, XENVBD_ENABLED);
    if (!NT_SUCCESS(status))
        goto fail4;

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");
    FrontendD0ToD3(Target->Frontend);

fail3:
    Error("fail3\n");
    XENBUS_DEBUG(Deregister,
                 &Target->DebugInterface,
                 Target->DebugCallback);
    Target->DebugCallback = NULL;

fail2:
    Error("Fail2\n");
    XENBUS_DEBUG(Release,
                 &Target->DebugInterface);

fail1:
    Error("Fail1 (%08x)\n", status);

    RtlZeroMemory(&Target->DebugInterface,
                  sizeof(XENBUS_DEBUG_INTERFACE));
    Target->DevicePowerState = PowerDeviceD3;

    return status;
}

VOID
TargetD0ToD3(
    IN  PXENVBD_TARGET  Target
    )
{
    const ULONG         TargetId = TargetGetTargetId(Target);

    if (!TargetSetDevicePowerState(Target, PowerDeviceD3))
        return;

    Verbose("Target[%d] : D0->D3\n", TargetId);

    (VOID) FrontendSetState(Target->Frontend, XENVBD_CLOSED);

    FrontendD0ToD3(Target->Frontend);

    XENBUS_DEBUG(Deregister,
                 &Target->DebugInterface,
                 Target->DebugCallback);
    Target->DebugCallback = NULL;

    XENBUS_DEBUG(Release,
                 &Target->DebugInterface);

    RtlZeroMemory(&Target->DebugInterface,
                  sizeof(XENBUS_DEBUG_INTERFACE));
}

static FORCEINLINE ULONG
__ParseVbd(
    IN  PCHAR   DeviceIdStr
    )
{
    ULONG       DeviceId = strtoul(DeviceIdStr, NULL, 10);

    ASSERT3U((DeviceId & ~((1 << 29) - 1)), ==, 0);

    if (DeviceId & (1 << 28))
        return (DeviceId & ((1 << 20) - 1)) >> 8;       /* xvd    */

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
    default:    return 0xFFFFFFFF;                      /* ERROR  */
    }
}

NTSTATUS
TargetCreate(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PCHAR           DeviceId,
    OUT PXENVBD_TARGET* _Target
    )
{
    NTSTATUS            status;
    PXENVBD_TARGET      Target;
    ULONG               TargetId;

    TargetId = __ParseVbd(DeviceId);
    if (TargetId >= XENVBD_MAX_TARGETS)
        return STATUS_RETRY;

    if (AdapterIsTargetEmulated(Adapter, TargetId))
        return STATUS_RETRY;

    status = STATUS_INSUFFICIENT_RESOURCES;
#pragma warning(suppress: 6014)
    Target = __TargetAlloc(sizeof(XENVBD_TARGET));
    if (!Target)
        goto fail1;

    Verbose("Target[%d] : Creating\n", TargetId);
    Target->Adapter         = Adapter;
    Target->DeviceObject    = NULL; // filled in later
    Target->DevicePnpState  = Present;
    Target->DevicePowerState = PowerDeviceD3;

    KeInitializeSpinLock(&Target->Lock);

    status = FrontendCreate(Target, DeviceId, TargetId, &Target->Frontend);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = TargetD3ToD0(Target);
    if (!NT_SUCCESS(status))
        goto fail3;

    *_Target = Target;

    Verbose("Target[%d] : Created (%p)\n", TargetId, Target);
    return STATUS_SUCCESS;

fail3:
    Error("Fail3\n");
    FrontendDestroy(Target->Frontend);
    Target->Frontend = NULL;

fail2:
    Error("Fail2\n");
    __TargetFree(Target);

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

VOID
TargetDestroy(
    IN  PXENVBD_TARGET  Target
    )
{
    const ULONG         TargetId = TargetGetTargetId(Target);

    Verbose("Target[%d] : Destroying\n", TargetId);

    TargetD0ToD3(Target);

    ASSERT3U(TargetGetDevicePnpState(Target), ==, Deleted);

    FrontendDestroy(Target->Frontend);
    Target->Frontend = NULL;

    RtlZeroMemory(Target, sizeof(XENVBD_TARGET));
    __TargetFree(Target);

    Verbose("Target[%d] : Destroyed\n", TargetId);
}

#define TARGET_GET_PROPERTY(_name, _type)       \
_type                                           \
TargetGet ## _name ## (                         \
    IN  PXENVBD_TARGET  Target                  \
    )                                           \
{                                               \
    return Target-> ## _name ## ;               \
}

TARGET_GET_PROPERTY(Adapter, PXENVBD_ADAPTER)
TARGET_GET_PROPERTY(DeviceObject, PDEVICE_OBJECT)

//TARGET_GET_PROPERTY(TargetId, ULONG)
ULONG
TargetGetTargetId(
    IN  PXENVBD_TARGET  Target
    )
{
    return FrontendGetTargetId(Target->Frontend);
}
//TARGET_GET_PROPERTY(DeviceId, ULONG)
ULONG
TargetGetDeviceId(
    IN  PXENVBD_TARGET  Target
    )
{
    return FrontendGetDeviceId(Target->Frontend);
}

//TARGET_GET_PROPERTY(Removable, BOOLEAN)
BOOLEAN
TargetGetRemovable(
    IN  PXENVBD_TARGET  Target
    )
{
    return FrontendGetCaps(Target->Frontend)->Removable;
}

//TARGET_GET_PROPERTY(SurpriseRemovable, BOOLEAN)
BOOLEAN
TargetGetSurpriseRemovable(
    IN  PXENVBD_TARGET  Target
    )
{
    return FrontendGetCaps(Target->Frontend)->SurpriseRemovable;
}

TARGET_GET_PROPERTY(DevicePnpState, DEVICE_PNP_STATE)
//TARGET_GET_PROPERTY(Missing, BOOLEAN)

BOOLEAN
TargetGetMissing(
    IN  PXENVBD_TARGET  Target
    )
{
    KIRQL               Irql;
    BOOLEAN             Missing;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    Missing = Target->Missing;
    KeReleaseSpinLock(&Target->Lock, Irql);

    return Missing;
}

#undef TARGET_GET_PROPERTY
