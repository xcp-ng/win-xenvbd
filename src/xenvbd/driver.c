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
#include "adapter.h"
#include "pdo.h"
#include "registry.h"
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
    HANDLE              ParametersKey;
    PDRIVER_DISPATCH    StorPortDispatchPnp;
    PDRIVER_DISPATCH    StorPortDispatchPower;
    PDRIVER_UNLOAD      StorPortDriverUnload;
    PXENVBD_ADAPTER         Adapter;
    KSPIN_LOCK          Lock;
} XENVBD_DRIVER;

static XENVBD_DRIVER Driver;

XENVBD_PARAMETERS   DriverParameters;

#define XENVBD_POOL_TAG     'dbvX'

static DECLSPEC_NOINLINE VOID
__DriverParseOption(
    IN  const CHAR  *Key,
    OUT PBOOLEAN    Flag
    )
{
    PANSI_STRING    Option;
    PCHAR           Value;
    NTSTATUS        status;

    *Flag = FALSE;

    status = RegistryQuerySystemStartOption(Key, &Option);
    if (!NT_SUCCESS(status))
        return;

    Value = Option->Buffer + strlen(Key);

    if (strcmp(Value, "ON") == 0)
        *Flag = TRUE;

    RegistryFreeSzValue(Option);
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
DriverLinkAdapter(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    KIRQL       Irql;

    KeAcquireSpinLock(&Driver.Lock, &Irql);
    Driver.Adapter = Adapter;
    KeReleaseSpinLock(&Driver.Lock, Irql);
}

VOID
DriverUnlinkAdapter(
    __in PXENVBD_ADAPTER             Adapter
    )
{
    KIRQL       Irql;

    UNREFERENCED_PARAMETER(Adapter);

    KeAcquireSpinLock(&Driver.Lock, &Irql);
    Driver.Adapter = NULL;
    KeReleaseSpinLock(&Driver.Lock, Irql);
}

static FORCEINLINE BOOLEAN
__DriverGetAdapter(
    IN  PDEVICE_OBJECT      DeviceObject,
    OUT PXENVBD_ADAPTER         *Adapter
    )
{
    KIRQL       Irql;
    BOOLEAN     IsAdapter = FALSE;

    KeAcquireSpinLock(&Driver.Lock, &Irql);
    *Adapter = Driver.Adapter;
    if (*Adapter) {
        if (AdapterGetDeviceObject(*Adapter) == DeviceObject) {
            IsAdapter = TRUE;
        }
    }
    KeReleaseSpinLock(&Driver.Lock, Irql);

    return IsAdapter;
}

#define MAXNAMELEN  256

VOID
DriverRequestReboot(
    VOID
    )
{
    PANSI_STRING    Ansi;
    CHAR            RequestKeyName[MAXNAMELEN];
    HANDLE          RequestKey;
    HANDLE          SubKey;
    NTSTATUS        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    status = RegistryQuerySzValue(Driver.ParametersKey,
                                  "RequestKey",
                                  NULL,
                                  &Ansi);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RtlStringCbPrintfA(RequestKeyName,
                                MAXNAMELEN,
                                "\\Registry\\Machine\\%Z",
                                &Ansi[0]);
    ASSERT(NT_SUCCESS(status));

    status = RegistryCreateSubKey(NULL,
                                  RequestKeyName,
                                  REG_OPTION_NON_VOLATILE,
                                  &RequestKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryCreateSubKey(RequestKey,
                                  __MODULE__,
                                  REG_OPTION_VOLATILE,
                                  &SubKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryUpdateDwordValue(SubKey,
                                      "Reboot",
                                      1);
    if (!NT_SUCCESS(status))
        goto fail4;

    RegistryCloseKey(SubKey);

    RegistryCloseKey(RequestKey);

    RegistryFreeSzValue(Ansi);

    return;

fail4:
    Error("fail4\n");

    RegistryCloseKey(SubKey);

fail3:
    Error("fail3\n");

    RegistryCloseKey(RequestKey);

fail2:
    Error("fail2\n");

    RegistryFreeSzValue(Ansi);

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
        Str = (PCHAR)__AllocatePoolWithTag(NonPagedPool, Size,
                                           XENVBD_POOL_TAG);
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

    return AdapterResetBus((PXENVBD_ADAPTER)HwDeviceExtension);
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

    return AdapterFindAdapter((PXENVBD_ADAPTER)HwDeviceExtension, ConfigInfo);
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

    return AdapterBuildIo((PXENVBD_ADAPTER)HwDeviceExtension, Srb);
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

    return AdapterStartIo((PXENVBD_ADAPTER)HwDeviceExtension, Srb);
}

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH             DispatchPnp;

NTSTATUS 
DispatchPnp(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PXENVBD_ADAPTER         Adapter;

    if (__DriverGetAdapter(DeviceObject, &Adapter))
        return AdapterDispatchPnp(Adapter, DeviceObject, Irp);

    if (Adapter != NULL)
        return AdapterForwardPnp(Adapter, DeviceObject, Irp);

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
    PXENVBD_ADAPTER         Adapter;

    if (__DriverGetAdapter(DeviceObject, &Adapter))
        return AdapterDispatchPower(Adapter, DeviceObject, Irp);

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
    RegistryCloseKey(Driver.ParametersKey);
    RegistryTeardown();

    Trace("<=== (Irql=%d)\n", KeGetCurrentIrql());
}

DRIVER_INITIALIZE           DriverEntry;

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT       _DriverObject,
    IN PUNICODE_STRING      RegistryPath
    )
{
    HW_INITIALIZATION_DATA  InitData;
    HANDLE                  ServiceKey;
    HANDLE                  ParametersKey;
    NTSTATUS                status;

    // RegistryPath == NULL if crashing!
    if (RegistryPath == NULL) {
        return XencrshEntryPoint(_DriverObject);
    }

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    
    Trace("===> (Irql=%d)\n", KeGetCurrentIrql());
    Verbose("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    status = RegistryInitialize(RegistryPath);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenServiceKey(KEY_ALL_ACCESS, &ServiceKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryOpenSubKey(ServiceKey,
                                "Parameters",
                                KEY_READ,
                                &ParametersKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    Driver.ParametersKey = ParametersKey;

    RegistryCloseKey(ServiceKey);
    ServiceKey = NULL;

    KeInitializeSpinLock(&Driver.Lock);
    Driver.Adapter = NULL;
    BufferInitialize();

    __DriverParseOption("XENVBD:SYNTH_INQ=",
                        &DriverParameters.SynthesizeInquiry);
    __DriverParseOption("XENVBD:PVCDROM=",
                        &DriverParameters.PVCDRom);

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
    InitData.DeviceExtensionSize        =   AdapterSizeofXenvbdAdapter();
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

    status = StorPortInitialize(_DriverObject,
                                RegistryPath,
                                &InitData,
                                NULL);
    if (!NT_SUCCESS(status))
        goto fail4;

    Driver.StorPortDispatchPnp     = _DriverObject->MajorFunction[IRP_MJ_PNP];
    Driver.StorPortDispatchPower   = _DriverObject->MajorFunction[IRP_MJ_POWER];
    Driver.StorPortDriverUnload    = _DriverObject->DriverUnload;

    _DriverObject->MajorFunction[IRP_MJ_PNP]    = DispatchPnp;
    _DriverObject->MajorFunction[IRP_MJ_POWER]  = DispatchPower;
    _DriverObject->DriverUnload                 = DriverUnload;

    Trace("<=== (%08x) (Irql=%d)\n", STATUS_SUCCESS, KeGetCurrentIrql());
    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    BufferTerminate();
    RegistryCloseKey(Driver.ParametersKey);
    Driver.ParametersKey = NULL;

fail3:
    Error("fail3\n");

    if (ServiceKey)
        RegistryCloseKey(ServiceKey);

fail2:
    Error("fail2\n");

    RegistryTeardown();

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
