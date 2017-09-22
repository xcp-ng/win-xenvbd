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

#include "target.h"
#include "driver.h"
#include "adapter.h"
#include "frontend.h"
#include "queue.h"
#include "srbext.h"
#include "buffer.h"
#include "pdoinquiry.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <stdlib.h>

#define TARGET_SIGNATURE           'odpX'

struct _XENVBD_TARGET {
    ULONG                       Signature;
    PXENVBD_ADAPTER                 Adapter;
    PDEVICE_OBJECT              DeviceObject;
    DEVICE_PNP_STATE            DevicePnpState;
    DEVICE_PNP_STATE            PrevPnpState;
    DEVICE_POWER_STATE          DevicePowerState;
    KSPIN_LOCK                  Lock;

    // Frontend (Ring, includes XenBus interfaces)
    PXENVBD_FRONTEND            Frontend;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallback;

    // Eject
    BOOLEAN                     WrittenEjected;
    BOOLEAN                     EjectRequested;
    BOOLEAN                     EjectPending;
    BOOLEAN                     Missing;
    const CHAR*                 Reason;
};

//=============================================================================
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

//=============================================================================
// Debug
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

//=============================================================================
// SRBs
__checkReturn
static FORCEINLINE BOOLEAN
__ValidateSectors(
    __in ULONG64                 SectorCount,
    __in ULONG64                 Start,
    __in ULONG                   Length
    )
{
    // Deal with overflow
    return (Start < SectorCount) && ((Start + Length) <= SectorCount);
}

__checkReturn
static FORCEINLINE BOOLEAN
__ValidateSrbBuffer(
    __in PCHAR                  Caller,
    __in PSCSI_REQUEST_BLOCK    Srb,
    __in ULONG                  MinLength
    )
{
    if (Srb->DataBuffer == NULL) {
        Error("%s: Srb[0x%p].DataBuffer = NULL\n", Caller, Srb);
        return FALSE;
    }
    if (MinLength) {
        if (Srb->DataTransferLength < MinLength) {
            Error("%s: Srb[0x%p].DataTransferLength < %d\n", Caller, Srb, MinLength);
            return FALSE;
        }
    } else {
        if (Srb->DataTransferLength == 0) {
            Error("%s: Srb[0x%p].DataTransferLength = 0\n", Caller, Srb);
            return FALSE;
        }
    }

    return TRUE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
TargetReadWrite(
    __in PXENVBD_TARGET            Target,
    __in PSCSI_REQUEST_BLOCK    Srb
    )
{
    PXENVBD_DISKINFO    DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_RING        Ring = FrontendGetRing(Target->Frontend);

    if (FrontendGetCaps(Target->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    // check valid sectors
    if (!__ValidateSectors(DiskInfo->SectorCount, Cdb_LogicalBlock(Srb), Cdb_TransferBlock(Srb))) {
        Trace("Target[%d] : Invalid Sector (%d @ %lld < %lld)\n", TargetGetTargetId(Target), Cdb_TransferBlock(Srb), Cdb_LogicalBlock(Srb), DiskInfo->SectorCount);
        Srb->ScsiStatus = 0x40; // SCSI_ABORT
        return TRUE; // Complete now
    }

    RingQueueRequest(Ring, SrbExt);
    return FALSE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
TargetSyncCache(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_RING        Ring = FrontendGetRing(Target->Frontend);

    if (FrontendGetCaps(Target->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    if (FrontendGetDiskInfo(Target->Frontend)->FlushCache == FALSE &&
        FrontendGetDiskInfo(Target->Frontend)->Barrier == FALSE) {
        Trace("Target[%d] : FLUSH and BARRIER not supported, suppressing\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x00; // SCSI_GOOD
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        return TRUE;
    }

    RingQueueRequest(Ring, SrbExt);
    return FALSE;
}

__checkReturn
static DECLSPEC_NOINLINE BOOLEAN
TargetUnmap(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PXENVBD_SRBEXT      SrbExt = GetSrbExt(Srb);
    PXENVBD_RING        Ring = FrontendGetRing(Target->Frontend);

    if (FrontendGetCaps(Target->Frontend)->Connected == FALSE) {
        Trace("Target[%d] : Not Ready, fail SRB\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x40; // SCSI_ABORT;
        return TRUE;
    }

    if (FrontendGetDiskInfo(Target->Frontend)->Discard == FALSE) {
        Trace("Target[%d] : DISCARD not supported, suppressing\n", TargetGetTargetId(Target));
        Srb->ScsiStatus = 0x00; // SCSI_GOOD
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        return TRUE;
    }

    RingQueueRequest(Ring, SrbExt);
    return FALSE;
}

#define MODE_CACHING_PAGE_LENGTH 20
static DECLSPEC_NOINLINE VOID
TargetModeSense(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PMODE_PARAMETER_HEADER  Header  = Srb->DataBuffer;
    const UCHAR PageCode            = Cdb_PageCode(Srb);
    ULONG LengthLeft                = Cdb_AllocationLength(Srb);
    PVOID CurrentPage               = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, (ULONG)sizeof(struct _MODE_SENSE))) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

    // TODO : CDROM requires more ModePage entries
    // Header
    Header->ModeDataLength  = sizeof(MODE_PARAMETER_HEADER) - 1;
    Header->MediumType      = 0;
    Header->DeviceSpecificParameter = 0;
    Header->BlockDescriptorLength   = 0;
    LengthLeft -= sizeof(MODE_PARAMETER_HEADER);
    CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_PARAMETER_HEADER));

    // Fill in Block Parameters (if Specified and space)
    // when the DBD (Disable Block Descriptor) is set, ignore the block page
    if (Cdb_Dbd(Srb) == 0 &&
        LengthLeft >= sizeof(MODE_PARAMETER_BLOCK)) {
        PMODE_PARAMETER_BLOCK Block = (PMODE_PARAMETER_BLOCK)CurrentPage;
        // Fill in BlockParams
        Block->DensityCode                  =   0;
        Block->NumberOfBlocks[0]            =   0;
        Block->NumberOfBlocks[1]            =   0;
        Block->NumberOfBlocks[2]            =   0;
        Block->BlockLength[0]               =   0;
        Block->BlockLength[1]               =   0;
        Block->BlockLength[2]               =   0;

        Header->BlockDescriptorLength = sizeof(MODE_PARAMETER_BLOCK);
        Header->ModeDataLength += sizeof(MODE_PARAMETER_BLOCK);
        LengthLeft -= sizeof(MODE_PARAMETER_BLOCK);
        CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_PARAMETER_BLOCK));
    }

    // Fill in Cache Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_CACHING || PageCode == MODE_SENSE_RETURN_ALL) &&
        LengthLeft >= MODE_CACHING_PAGE_LENGTH) {
        PMODE_CACHING_PAGE Caching = (PMODE_CACHING_PAGE)CurrentPage;
        // Fill in CachingParams
        Caching->PageCode                   = MODE_PAGE_CACHING;
        Caching->PageSavable                = 0;
        Caching->PageLength                 = MODE_CACHING_PAGE_LENGTH;
        Caching->ReadDisableCache           = 0;
        Caching->MultiplicationFactor       = 0;
        Caching->WriteCacheEnable           = FrontendGetDiskInfo(Target->Frontend)->FlushCache ? 1 : 0;
        Caching->WriteRetensionPriority     = 0;
        Caching->ReadRetensionPriority      = 0;
        Caching->DisablePrefetchTransfer[0] = 0;
        Caching->DisablePrefetchTransfer[1] = 0;
        Caching->MinimumPrefetch[0]         = 0;
        Caching->MinimumPrefetch[1]         = 0;
        Caching->MaximumPrefetch[0]         = 0;
        Caching->MaximumPrefetch[1]         = 0;
        Caching->MaximumPrefetchCeiling[0]  = 0;
        Caching->MaximumPrefetchCeiling[1]  = 0;

        Header->ModeDataLength += MODE_CACHING_PAGE_LENGTH;
        LengthLeft -= MODE_CACHING_PAGE_LENGTH;
        CurrentPage = ((PUCHAR)CurrentPage + MODE_CACHING_PAGE_LENGTH);
    }

    // Fill in Informational Exception Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_FAULT_REPORTING || PageCode == MODE_SENSE_RETURN_ALL) &&
        LengthLeft >= sizeof(MODE_INFO_EXCEPTIONS)) {
        PMODE_INFO_EXCEPTIONS Exceptions = (PMODE_INFO_EXCEPTIONS)CurrentPage;
        // Fill in Exceptions
        Exceptions->PageCode                = MODE_PAGE_FAULT_REPORTING;
        Exceptions->PSBit                   = 0;
        Exceptions->PageLength              = sizeof(MODE_INFO_EXCEPTIONS);
        Exceptions->Flags                   = 0;
        Exceptions->Dexcpt                  = 1; // disabled
        Exceptions->ReportMethod            = 0;
        Exceptions->IntervalTimer[0]        = 0;
        Exceptions->IntervalTimer[1]        = 0;
        Exceptions->IntervalTimer[2]        = 0;
        Exceptions->IntervalTimer[3]        = 0;
        Exceptions->ReportCount[0]          = 0;
        Exceptions->ReportCount[1]          = 0;
        Exceptions->ReportCount[2]          = 0;
        Exceptions->ReportCount[3]          = 0;

        Header->ModeDataLength += sizeof(MODE_INFO_EXCEPTIONS);
        LengthLeft -= sizeof(MODE_INFO_EXCEPTIONS);
        CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_INFO_EXCEPTIONS));
    }

    // Finish this SRB
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    Srb->DataTransferLength = __min(Cdb_AllocationLength(Srb), (ULONG)(Header->ModeDataLength + 1));
}

static DECLSPEC_NOINLINE VOID
TargetRequestSense(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PSENSE_DATA         Sense = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, (ULONG)sizeof(SENSE_DATA))) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        return;
    }

    RtlZeroMemory(Sense, sizeof(SENSE_DATA));

    Sense->ErrorCode            = 0x70;
    Sense->Valid                = 1;
    Sense->AdditionalSenseCodeQualifier = 0;
    Sense->SenseKey             = SCSI_SENSE_NO_SENSE;
    Sense->AdditionalSenseCode  = SCSI_ADSENSE_NO_SENSE;
    Srb->DataTransferLength     = sizeof(SENSE_DATA);
    Srb->SrbStatus              = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReportLuns(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    ULONG           Length;
    ULONG           Offset;
    ULONG           AllocLength = Cdb_AllocationLength(Srb);
    PUCHAR          Buffer = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, 8)) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

    RtlZeroMemory(Buffer, AllocLength);

    Length = 0;
    Offset = 8;

    if (Offset + 8 <= AllocLength) {
        Buffer[Offset] = 0;
        Offset += 8;
        Length += 8;
    }

    if (Offset + 8 <= AllocLength) {
        Buffer[Offset] = XENVBD_MAX_TARGETS;
        Offset += 8;
        Length += 8;
    }

    REVERSE_BYTES(Buffer, &Length);

    Srb->DataTransferLength = __min(Length, AllocLength);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReadCapacity(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PREAD_CAPACITY_DATA     Capacity = Srb->DataBuffer;
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   LastBlock;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0) {
        Srb->ScsiStatus = 0x02; // CHECK_CONDITION
        return;
    }

    SectorCount = DiskInfo->SectorCount;
    SectorSize = DiskInfo->SectorSize;

    if (SectorCount == (ULONG)SectorCount)
        LastBlock = (ULONG)SectorCount - 1;
    else
        LastBlock = ~(ULONG)0;

    if (Capacity) {
        Capacity->LogicalBlockAddress = _byteswap_ulong(LastBlock);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReadCapacity16(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    )
{
    PREAD_CAPACITY16_DATA   Capacity = Srb->DataBuffer;
    PXENVBD_DISKINFO        DiskInfo = FrontendGetDiskInfo(Target->Frontend);
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   PhysSectorSize;
    ULONG                   LogicalPerPhysical;
    ULONG                   LogicalPerPhysicalExponent;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0) {
        Srb->ScsiStatus = 0x02; // CHECK_CONDITION
        return;
    }

    SectorCount = DiskInfo->SectorCount;
    SectorSize = DiskInfo->SectorSize;
    PhysSectorSize = DiskInfo->PhysSectorSize;

    LogicalPerPhysical = PhysSectorSize / SectorSize;

    if (!_BitScanReverse(&LogicalPerPhysicalExponent, LogicalPerPhysical))
        LogicalPerPhysicalExponent = 0;

    if (Capacity) {
        Capacity->LogicalBlockAddress.QuadPart = _byteswap_uint64(SectorCount - 1);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
        Capacity->LogicalPerPhysicalExponent = (UCHAR)LogicalPerPhysicalExponent;
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE BOOLEAN
__ValidateSrbForTarget(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    const UCHAR             Operation = Cdb_OperationEx(Srb);

    if (Target == NULL) {
        Error("Invalid Target(NULL) (%02x:%s)\n",
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_TARGET_ID;
        return FALSE;
    }

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
        if (!TargetReadWrite(Target, Srb))
            WasQueued = TRUE;
        break;

    case SCSIOP_UNMAP:
        if (!TargetUnmap(Target, Srb))
            WasQueued = TRUE;
        break;

    case SCSIOP_SYNCHRONIZE_CACHE:
        if (!TargetSyncCache(Target, Srb))
            WasQueued = TRUE;
        break;

    case SCSIOP_INQUIRY:
        AdapterSetDeviceQueueDepth(TargetGetAdapter(Target),
                                   TargetGetTargetId(Target));
        PdoInquiry(TargetGetTargetId(Target),
                   FrontendGetInquiry(Target->Frontend),
                   Srb);
        break;

    case SCSIOP_MODE_SENSE:
        TargetModeSense(Target, Srb);
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
        FrontendStoreWriteFrontend(Target->Frontend,
                                   "ejected",
                                   "1");
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
    PXENVBD_CAPS                    Caps = FrontendGetCaps(Target->Frontend);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Value = StackLocation->Parameters.UsageNotification.InPath;
    Type  = StackLocation->Parameters.UsageNotification.Type;

    switch (Type) {
    case DeviceUsageTypePaging:
        if (Caps->Paging == Value)
            return;
        Caps->Paging = Value;
        break;

    case DeviceUsageTypeHibernation:
        if (Caps->Hibernation == Value)
            return;
        Caps->Hibernation = Value;
        break;

    case DeviceUsageTypeDumpFile:
        if (Caps->DumpFile == Value)
            return;
        Caps->DumpFile = Value;
        break;

    default:
        return;
    }
    FrontendWriteUsage(Target->Frontend);
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
        FrontendStoreWriteFrontend(Target->Frontend,
                                   "error",
                                   "Unplug failed due to open handle(s)!");
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

    FrontendDebugCallback(Target->Frontend,
                          &Target->DebugInterface);
}

static DECLSPEC_NOINLINE VOID
TargetSuspendCallback(
    IN  PVOID       Argument
    )
{
    PXENVBD_TARGET  Target = Argument;

    RingReQueueRequests(FrontendGetRing(Target->Frontend));

    Verbose("Target[%d] : %s (%s)\n",
            TargetGetTargetId(Target),
            Target->Missing ? "MISSING" : "NOT_MISSING",
            Target->Reason);
    Target->Missing = FALSE;
    Target->Reason = NULL;
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
    AdapterGetSuspendInterface(TargetGetAdapter(Target),
                               &Target->SuspendInterface);

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

    status = XENBUS_SUSPEND(Acquire, &Target->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_SUSPEND(Register,
                            &Target->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            TargetSuspendCallback,
                            Target,
                            &Target->SuspendCallback);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = FrontendD3ToD0(Target->Frontend);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = FrontendSetState(Target->Frontend, XENVBD_ENABLED);
    if (!NT_SUCCESS(status))
        goto fail6;

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");
    FrontendD0ToD3(Target->Frontend);

fail5:
    Error("fail5\n");
    XENBUS_SUSPEND(Deregister,
                   &Target->SuspendInterface,
                   Target->SuspendCallback);
    Target->SuspendCallback = NULL;

fail4:
    Error("fail4\n");
    XENBUS_SUSPEND(Release,
                   &Target->SuspendInterface);

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

    RtlZeroMemory(&Target->SuspendInterface,
                  sizeof(XENBUS_SUSPEND_INTERFACE));
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

    XENBUS_SUSPEND(Deregister,
                   &Target->SuspendInterface,
                   Target->SuspendCallback);
    Target->SuspendCallback = NULL;

    XENBUS_SUSPEND(Release,
                   &Target->SuspendInterface);

    XENBUS_DEBUG(Deregister,
                 &Target->DebugInterface,
                 Target->DebugCallback);
    Target->DebugCallback = NULL;

    XENBUS_DEBUG(Release,
                 &Target->DebugInterface);

    RtlZeroMemory(&Target->SuspendInterface,
                  sizeof(XENBUS_SUSPEND_INTERFACE));
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
    Target->Signature       = TARGET_SIGNATURE;
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

    Verbose("Target[%d] : Created (%s)\n", TargetId, Target);
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
