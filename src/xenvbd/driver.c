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

#include "driver.h"
#include "fdo.h"
#include "pdo.h"
#include "srbext.h"
#include "buffer.h"
#include "debug.h"
#include "assert.h"
#include "util.h"
#include <version.h>
#include <names.h>
#include <xencrsh_interface.h>
#include <xenvbd-ntstrsafe.h>

typedef struct _XENVBD_DRIVER {
    HANDLE              StatusKey;
    PDRIVER_DISPATCH    StorPortDispatchPnp;
    PDRIVER_DISPATCH    StorPortDispatchPower;
    PDRIVER_UNLOAD      StorPortDriverUnload;
    PXENVBD_FDO         Fdo;
    KSPIN_LOCK          Lock;
} XENVBD_DRIVER;

static XENVBD_DRIVER Driver;

XENVBD_PARAMETERS   DriverParameters;

#define XENVBD_POOL_TAG     'dbvX'

static FORCEINLINE BOOLEAN
__IsValid(
    __in WCHAR                  Char
    )
{
    return !(Char == 0 || Char == L' ' || Char == L'\t' || Char == L'\n' || Char == L'\r');
}
static DECLSPEC_NOINLINE BOOLEAN
__DriverGetOption(
    __in PWCHAR                 Options,
    __in PWCHAR                 Parameter,
    __out PWCHAR*               Value
    )
{
    PWCHAR  Ptr;
    PWCHAR  Buffer;
    ULONG   Index;
    ULONG   Length;

    *Value = NULL;
    Ptr = wcsstr(Options, Parameter);
    if (Ptr == NULL)
        return FALSE; // option not present

    // skip Parameter
    while (*Parameter) {
        ++Ptr;
        ++Parameter;
    }

    // find length of Value, up to next NULL or whitespace
    for (Length = 0; __IsValid(Ptr[Length]); ++Length) 
        ;
    if (Length == 0)
        return TRUE; // found the option, it had no value so *Value == NULL!

    Buffer = (PWCHAR)__AllocateNonPagedPoolWithTag(__FUNCTION__, __LINE__, (Length + 1) * sizeof(WCHAR), XENVBD_POOL_TAG);
    if (Buffer == NULL)
        return FALSE; // memory allocation failure, ignore option

    // copy Value
    for (Index = 0; Index < Length; ++Index)
        Buffer[Index] = Ptr[Index];
    Buffer[Length] = L'\0';

    *Value = Buffer;
    return TRUE;
}
static DECLSPEC_NOINLINE NTSTATUS
__DriverGetSystemStartParams(
    __out PWCHAR*               Options
    )
{
    UNICODE_STRING      Unicode;
    OBJECT_ATTRIBUTES   Attributes;
    HANDLE              Key;
    PKEY_VALUE_PARTIAL_INFORMATION  Value;
    ULONG               Size;
    NTSTATUS            Status;

    RtlInitUnicodeString(&Unicode, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control");
    InitializeObjectAttributes(&Attributes, &Unicode, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwOpenKey(&Key, KEY_READ, &Attributes);
    if (!NT_SUCCESS(Status))
        goto fail1;

    RtlInitUnicodeString(&Unicode, L"SystemStartOptions");
    Status = ZwQueryValueKey(Key, &Unicode, KeyValuePartialInformation, NULL, 0, &Size);
    if (Status != STATUS_BUFFER_TOO_SMALL &&
        Status != STATUS_BUFFER_OVERFLOW)
        goto fail2;

    Status = STATUS_NO_MEMORY;
#pragma prefast(suppress:6102)
    Value = (PKEY_VALUE_PARTIAL_INFORMATION)__AllocateNonPagedPoolWithTag(__FUNCTION__, __LINE__, Size, XENVBD_POOL_TAG);
    if (Value == NULL)
        goto fail3;

    Status = ZwQueryValueKey(Key, &Unicode, KeyValuePartialInformation, Value, Size, &Size);
    if (!NT_SUCCESS(Status))
        goto fail4;

    Status = STATUS_INVALID_PARAMETER;
    if (Value->Type != REG_SZ)
        goto fail5;

    Status = STATUS_NO_MEMORY;
    *Options = (PWCHAR)__AllocateNonPagedPoolWithTag(__FUNCTION__, __LINE__, Value->DataLength + sizeof(WCHAR), XENVBD_POOL_TAG);
    if (*Options == NULL)
        goto fail6;

    RtlCopyMemory(*Options, Value->Data, Value->DataLength);

    __FreePoolWithTag(Value, XENVBD_POOL_TAG);

    ZwClose(Key);
    return STATUS_SUCCESS;

fail6:
fail5:
fail4:
    __FreePoolWithTag(Value, XENVBD_POOL_TAG);
fail3:
fail2:
    ZwClose(Key);
fail1:
    *Options = NULL;
    return Status;
}
static DECLSPEC_NOINLINE VOID
__DriverParseParameterKey(
    )
{
    NTSTATUS    Status;
    PWCHAR      Options;
    PWCHAR      Value;

    // Set default parameters
    DriverParameters.SynthesizeInquiry = FALSE;
    DriverParameters.PVCDRom           = FALSE;

    // attempt to read registry for system start parameters
    Status = __DriverGetSystemStartParams(&Options);
    if (NT_SUCCESS(Status)) {
        Trace("Options = \"%ws\"\n", Options);

        // check each option
        if (__DriverGetOption(Options, L"XENVBD:SYNTH_INQ=", &Value)) {
            // Value may be NULL (it shouldnt be though!)
            if (Value) {
                if (wcscmp(Value, L"ON") == 0) {
                    DriverParameters.SynthesizeInquiry = TRUE;
                }
                __FreePoolWithTag(Value, XENVBD_POOL_TAG);
            }
        }

        if (__DriverGetOption(Options, L"XENVBD:PVCDROM=", &Value)) {
            // Value may be NULL (it shouldnt be though!)
            if (Value) {
                if (wcscmp(Value, L"ON") == 0) {
                    DriverParameters.PVCDRom = TRUE;
                }
                __FreePoolWithTag(Value, XENVBD_POOL_TAG);
            }
        }

        __FreePoolWithTag(Options, XENVBD_POOL_TAG);
    }

    Verbose("DriverParameters: %s%s\n", 
            DriverParameters.SynthesizeInquiry ? "SYNTH_INQ " : "",
            DriverParameters.PVCDRom ? "PV_CDROM " : "");
}

NTSTATUS
DriverDispatchPnp(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
{
    return Driver.StorPortDispatchPnp(DeviceObject, Irp);
}

NTSTATUS
DriverDispatchPower(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
{
    return Driver.StorPortDispatchPower(DeviceObject, Irp);
}

VOID
DriverLinkFdo(
    __in PXENVBD_FDO             Fdo
    )
{
    KIRQL       Irql;

    KeAcquireSpinLock(&Driver.Lock, &Irql);
    Driver.Fdo = Fdo;
    KeReleaseSpinLock(&Driver.Lock, Irql);
}

VOID
DriverUnlinkFdo(
    __in PXENVBD_FDO             Fdo
    )
{
    KIRQL       Irql;

    UNREFERENCED_PARAMETER(Fdo);

    KeAcquireSpinLock(&Driver.Lock, &Irql);
    Driver.Fdo = NULL;
    KeReleaseSpinLock(&Driver.Lock, Irql);
}

static FORCEINLINE BOOLEAN
__DriverGetFdo(
    IN  PDEVICE_OBJECT      DeviceObject,
    OUT PXENVBD_FDO         *Fdo
    )
{
    KIRQL       Irql;
    BOOLEAN     IsFdo = FALSE;

    KeAcquireSpinLock(&Driver.Lock, &Irql);
    *Fdo = Driver.Fdo;
    if (*Fdo) {
        FdoReference(*Fdo);
        if (FdoGetDeviceObject(*Fdo) == DeviceObject) {
            IsFdo = TRUE;
        }
    }
    KeReleaseSpinLock(&Driver.Lock, Irql);

    return IsFdo;
}

#define SERVICES_PATH "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services"

#define SERVICE_KEY(_Name) \
        SERVICES_PATH ## "\\" ## #_Name

#define REQUEST_KEY \
        SERVICE_KEY(XENBUS_MONITOR) ## "\\Request"

VOID
DriverRequestReboot(
    VOID
    )
{
    ANSI_STRING                     Ansi;
    UNICODE_STRING                  KeyName;
    UNICODE_STRING                  ValueName;
    WCHAR                           Value[] = L"XENVBD";
    OBJECT_ATTRIBUTES               Attributes;
    HANDLE                          Key;
    NTSTATUS                        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    RtlInitAnsiString(&Ansi, REQUEST_KEY);

    status = RtlAnsiStringToUnicodeString(&KeyName, &Ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = ZwOpenKey(&Key,
                       KEY_ALL_ACCESS,
                       &Attributes);
    if (!NT_SUCCESS(status))
        goto fail2;

    RtlInitUnicodeString(&ValueName, L"Reboot");

    status = ZwSetValueKey(Key,
                           &ValueName,
                           0,
                           REG_SZ,
                           Value,
                           sizeof(Value));
    if (!NT_SUCCESS(status))
        goto fail3;

    ZwClose(Key);

    RtlFreeUnicodeString(&KeyName);

    return;

fail3:
    Error("fail3\n");

    ZwClose(Key);

fail2:
    Error("fail2\n");

    RtlFreeUnicodeString(&KeyName);

fail1:
    Error("fail1 (%08x)\n", status);
}

__checkReturn
__drv_allocatesMem(mem)
static FORCEINLINE PCHAR
#pragma warning(suppress: 28195)
__DriverFormatV(
    __in PCHAR       Fmt,
    __in va_list     Args
    )
{
    NTSTATUS    Status;
    PCHAR       Str;
    ULONG       Size = 32;

    for (;;) {
        Str = (PCHAR)__AllocateNonPagedPoolWithTag(__FUNCTION__, __LINE__, Size, XENVBD_POOL_TAG);
        if (!Str) {
            return NULL;
        }

        Status = RtlStringCchVPrintfA(Str, Size - 1, Fmt, Args);

        if (Status == STATUS_SUCCESS) {
            Str[Size - 1] = '\0';
            return Str;
        } 
        
        __FreePoolWithTag(Str, XENVBD_POOL_TAG);
        if (Status == STATUS_BUFFER_OVERFLOW) {
            Size *= 2;
        } else {
            return NULL;
        }
    }
}

__checkReturn
__drv_allocatesMem(mem)
PCHAR
DriverFormat(
    __in PCHAR       Format,
    ...
    )
{
    va_list Args;
    PCHAR   Str;

    va_start(Args, Format);
    Str = __DriverFormatV(Format, Args);
    va_end(Args);
    return Str;
}

VOID
#pragma warning(suppress: 28197)
DriverFormatFree(
    __in __drv_freesMem(mem) PCHAR  Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, XENVBD_POOL_TAG);
}

HW_INITIALIZE       HwInitialize;

BOOLEAN 
HwInitialize(
    __in PVOID   HwDeviceExtension
    )
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    return TRUE;
}

HW_INTERRUPT        HwInterrupt;

BOOLEAN 
HwInterrupt(
    __in PVOID   HwDeviceExtension
    )
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    return TRUE;
}

HW_ADAPTER_CONTROL  HwAdapterControl;

SCSI_ADAPTER_CONTROL_STATUS
HwAdapterControl(
    __in PVOID                       HwDeviceExtension,
    __in SCSI_ADAPTER_CONTROL_TYPE   ControlType,
    __in PVOID                       Parameters
    )
{
    PSCSI_SUPPORTED_CONTROL_TYPE_LIST   List;
    ULONG                               Index;

    UNREFERENCED_PARAMETER(HwDeviceExtension);

    switch (ControlType) {
    case ScsiQuerySupportedControlTypes:
        List = Parameters;
        for (Index = 0; Index < List->MaxControlType; ++Index)
            List->SupportedTypeList[Index] = TRUE;
        break;

    case ScsiStopAdapter:
    case ScsiRestartAdapter:
    case ScsiSetBootConfig:
    case ScsiSetRunningConfig:
    default:
        break;
    }
    return ScsiAdapterControlSuccess;
}

HW_RESET_BUS        HwResetBus;

BOOLEAN
HwResetBus(
    __in PVOID   HwDeviceExtension,
    __in ULONG   PathId
    )
{
    UNREFERENCED_PARAMETER(PathId);

    return FdoResetBus((PXENVBD_FDO)HwDeviceExtension);
}

HW_FIND_ADAPTER     HwFindAdapter;

ULONG
HwFindAdapter(
    IN PVOID                               HwDeviceExtension,
    IN PVOID                               Context,
    IN PVOID                               BusInformation,
    IN PCHAR                               ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN                           Again
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);
    UNREFERENCED_PARAMETER(Again);

    return FdoFindAdapter((PXENVBD_FDO)HwDeviceExtension, ConfigInfo);
}

static FORCEINLINE BOOLEAN
__FailStorageRequest(
    __in PVOID               HwDeviceExtension,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    if (Srb->Function == SRB_FUNCTION_STORAGE_REQUEST_BLOCK) {
        // Win8 and above storport request. not supported
        // complete the request (with fail code)
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        StorPortNotification(RequestComplete, HwDeviceExtension, Srb);
        Error("(0x%p) STORAGE_REQUEST_BLOCK not supported\n", HwDeviceExtension);
        return TRUE;
    }

    return FALSE;
}

HW_BUILDIO          HwBuildIo;

BOOLEAN 
HwBuildIo(
    __in PVOID               HwDeviceExtension,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    if (__FailStorageRequest(HwDeviceExtension, Srb))
        return FALSE; // dont pass to HwStartIo

    return FdoBuildIo((PXENVBD_FDO)HwDeviceExtension, Srb);
}

HW_STARTIO          HwStartIo;

BOOLEAN 
HwStartIo(
    __in PVOID               HwDeviceExtension,
    __in PSCSI_REQUEST_BLOCK Srb
    )
{
    if (__FailStorageRequest(HwDeviceExtension, Srb))
        return TRUE; // acknowledge the srb

    return FdoStartIo((PXENVBD_FDO)HwDeviceExtension, Srb);
}

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH             DispatchPnp;

NTSTATUS 
DispatchPnp(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PXENVBD_FDO         Fdo;

    if (__DriverGetFdo(DeviceObject, &Fdo))
        return FdoDispatchPnp(Fdo, DeviceObject, Irp);

    if (Fdo != NULL)
        return FdoForwardPnp(Fdo, DeviceObject, Irp);

    return DriverDispatchPnp(DeviceObject, Irp);
}

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH             DispatchPower;

NTSTATUS 
DispatchPower(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PXENVBD_FDO         Fdo;

    if (__DriverGetFdo(DeviceObject, &Fdo))
        return FdoDispatchPower(Fdo, DeviceObject, Irp);

    if (Fdo != NULL)
        FdoDereference(Fdo);

    return DriverDispatchPower(DeviceObject, Irp);
}

DRIVER_UNLOAD               DriverUnload;

VOID
DriverUnload(
    IN PDRIVER_OBJECT  _DriverObject
    )
{
    Trace("===> (Irql=%d)\n", KeGetCurrentIrql());
    Verbose("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    Driver.StorPortDriverUnload(_DriverObject);
    BufferTerminate();
    ZwClose(Driver.StatusKey);

    Trace("<=== (Irql=%d)\n", KeGetCurrentIrql());
}

DRIVER_INITIALIZE           DriverEntry;

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  _DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS                Status;
    OBJECT_ATTRIBUTES       Attributes;
    UNICODE_STRING          Unicode;
    HW_INITIALIZATION_DATA  InitData;
    HANDLE                  ServiceKey;

    // RegistryPath == NULL if crashing!
    if (RegistryPath == NULL) {
        return XencrshEntryPoint(_DriverObject);
    }

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    
    Trace("===> (Irql=%d)\n", KeGetCurrentIrql());
    Verbose("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    InitializeObjectAttributes(&Attributes,
                               RegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    Status = ZwOpenKey(&ServiceKey,
                       KEY_ALL_ACCESS,
                       &Attributes);
    if (!NT_SUCCESS(Status))
        goto done;

    RtlInitUnicodeString(&Unicode, L"Status");

    InitializeObjectAttributes(&Attributes,
                               &Unicode,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               ServiceKey,
                               NULL);

    Status = ZwCreateKey(&Driver.StatusKey,
                         KEY_ALL_ACCESS,
                         &Attributes,
                         0,
                         NULL,
                         REG_OPTION_VOLATILE,
                         NULL
                         );

    ZwClose(ServiceKey);

    if (!NT_SUCCESS(Status))
        goto done;

    KeInitializeSpinLock(&Driver.Lock);
    Driver.Fdo = NULL;
    BufferInitialize();
    __DriverParseParameterKey();

    RtlZeroMemory(&InitData, sizeof(InitData));

    InitData.HwInitializationDataSize   =   sizeof(InitData);
    InitData.AdapterInterfaceType       =   Internal;
    InitData.HwInitialize               =   HwInitialize;
    InitData.HwStartIo                  =   HwStartIo;
    InitData.HwInterrupt                =   HwInterrupt;
#pragma warning(suppress : 4152)
    InitData.HwFindAdapter              =   HwFindAdapter;
    InitData.HwResetBus                 =   HwResetBus;
    InitData.HwDmaStarted               =   NULL;
    InitData.HwAdapterState             =   NULL;
    InitData.DeviceExtensionSize        =   FdoSizeofXenvbdFdo();
    InitData.SpecificLuExtensionSize    =   sizeof (ULONG); // not actually used
    InitData.SrbExtensionSize           =   sizeof(XENVBD_SRBEXT);
    InitData.NumberOfAccessRanges       =   2;
    InitData.MapBuffers                 =   STOR_MAP_NON_READ_WRITE_BUFFERS;
    InitData.NeedPhysicalAddresses      =   TRUE;
    InitData.TaggedQueuing              =   TRUE;
    InitData.AutoRequestSense           =   TRUE;
    InitData.MultipleRequestPerLu       =   TRUE;
    InitData.HwAdapterControl           =   HwAdapterControl;
    InitData.HwBuildIo                  =   HwBuildIo;

    Status = StorPortInitialize(_DriverObject, RegistryPath, &InitData, NULL);
    if (NT_SUCCESS(Status)) {
        Driver.StorPortDispatchPnp     = _DriverObject->MajorFunction[IRP_MJ_PNP];
        Driver.StorPortDispatchPower   = _DriverObject->MajorFunction[IRP_MJ_POWER];
        Driver.StorPortDriverUnload    = _DriverObject->DriverUnload;

        _DriverObject->MajorFunction[IRP_MJ_PNP]    = DispatchPnp;
        _DriverObject->MajorFunction[IRP_MJ_POWER]  = DispatchPower;
        _DriverObject->DriverUnload                 = DriverUnload;
    }

done:
    Trace("<=== (%08x) (Irql=%d)\n", Status, KeGetCurrentIrql());
    return Status;
}
