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
#include <storport.h>
#include <ntstrsafe.h>

#include <version.h>
#include <names.h>
#include <xencrsh_interface.h>

#include "driver.h"
#include "adapter.h"
#include "registry.h"
#include "srbext.h"
#include "buffer.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

typedef struct _XENVBD_DRIVER {
    PXENVBD_ADAPTER     Adapter;
    HANDLE              ParametersKey;
    PDRIVER_DISPATCH    StorPortDispatchPnp;
    PDRIVER_DISPATCH    StorPortDispatchPower;
    PDRIVER_UNLOAD      StorPortDriverUnload;
} XENVBD_DRIVER;

static XENVBD_DRIVER Driver;

#define XENVBD_POOL_TAG     'dbvX'

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

HW_INITIALIZE   HwInitialize;

BOOLEAN 
HwInitialize(
    IN  PVOID   DevExt
    )
{
    UNREFERENCED_PARAMETER(DevExt);
    return TRUE;
}

HW_INTERRUPT    HwInterrupt;

BOOLEAN 
HwInterrupt(
    IN  PVOID   DevExt
    )
{
    UNREFERENCED_PARAMETER(DevExt);
    return TRUE;
}

HW_ADAPTER_CONTROL  HwAdapterControl;

SCSI_ADAPTER_CONTROL_STATUS
HwAdapterControl(
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
    IN  PVOID   DevExt,
    IN  ULONG   PathId
    )
{
    UNREFERENCED_PARAMETER(PathId);

    return AdapterResetBus(DevExt);
}

HW_FIND_ADAPTER     HwFindAdapter;

ULONG
HwFindAdapter(
    IN  PVOID                               DevExt,
    IN  PVOID                               Context,
    IN  PVOID                               BusInformation,
    IN  PCHAR                               ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION  ConfigInfo,
    OUT PBOOLEAN                            Again
    )
{
    ULONG                                   Return;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);
    UNREFERENCED_PARAMETER(Again);

    Return = AdapterFindAdapter(DevExt, ConfigInfo);
    if (Return == SP_RETURN_FOUND)
        Driver.Adapter = DevExt;
    return Return;
}

static FORCEINLINE BOOLEAN
__FailStorageRequest(
    IN  PVOID               DevExt,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    if (Srb->Function == SRB_FUNCTION_STORAGE_REQUEST_BLOCK) {
        // Win8 and above storport request. not supported
        // complete the request (with fail code)
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        StorPortNotification(RequestComplete, DevExt, Srb);
        Error("(0x%p) STORAGE_REQUEST_BLOCK not supported\n", DevExt);
        return TRUE;
    }

    return FALSE;
}

HW_BUILDIO          HwBuildIo;

BOOLEAN 
HwBuildIo(
    IN  PVOID               DevExt,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    if (__FailStorageRequest(DevExt, Srb))
        return FALSE; // dont pass to HwStartIo

    return AdapterBuildIo(DevExt, Srb);
}

HW_STARTIO          HwStartIo;

BOOLEAN 
HwStartIo(
    IN  PVOID               DevExt,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    if (__FailStorageRequest(DevExt, Srb))
        return TRUE; // acknowledge the srb

    return AdapterStartIo(DevExt, Srb);
}

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH             DispatchPnp;

NTSTATUS 
DispatchPnp(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    if (Driver.Adapter == NULL)
        return DriverDispatchPnp(DeviceObject, Irp);

    if (AdapterGetDeviceObject(Driver.Adapter) == DeviceObject)
        return AdapterDispatchPnp(Driver.Adapter, DeviceObject, Irp);

    return AdapterForwardPnp(Driver.Adapter, DeviceObject, Irp);
}

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH             DispatchPower;

NTSTATUS 
DispatchPower(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    if (Driver.Adapter == NULL)
        return DriverDispatchPower(DeviceObject, Irp);

    if (AdapterGetDeviceObject(Driver.Adapter) == DeviceObject)
        return AdapterDispatchPower(Driver.Adapter, DeviceObject, Irp);

    return DriverDispatchPower(DeviceObject, Irp);
}

DRIVER_UNLOAD           DriverUnload;

VOID
DriverUnload(
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    Verbose("%u.%u.%u.%u (%02u/%02u/%04u)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

    Driver.Adapter = NULL;

    Driver.StorPortDriverUnload(DriverObject);
    Driver.StorPortDriverUnload = NULL;
    Driver.StorPortDispatchPnp = NULL;
    Driver.StorPortDispatchPower = NULL;

    BufferTerminate();

    RegistryCloseKey(Driver.ParametersKey);
    Driver.ParametersKey = NULL;

    RegistryTeardown();
}

DRIVER_INITIALIZE           DriverEntry;

NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT      DriverObject,
    IN  PUNICODE_STRING     RegistryPath
    )
{
    HW_INITIALIZATION_DATA  InitData;
    HANDLE                  ServiceKey;
    HANDLE                  ParametersKey;
    NTSTATUS                status;

    // RegistryPath == NULL if crashing!
    if (RegistryPath == NULL) {
        return XencrshEntryPoint(DriverObject);
    }

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    
    Verbose("%u.%u.%u.%u (%02u/%02u/%04u)\n",
         MAJOR_VERSION,
         MINOR_VERSION,
         MICRO_VERSION,
         BUILD_NUMBER,
         DAY,
         MONTH,
         YEAR);

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
    Driver.Adapter = NULL;
    BufferInitialize();

    RtlZeroMemory(&InitData, sizeof(InitData));
    InitData.HwInitializationDataSize   = sizeof(InitData);
    InitData.AdapterInterfaceType       = Internal;
    InitData.HwInitialize               = HwInitialize;
    InitData.HwStartIo                  = HwStartIo;
    InitData.HwInterrupt                = HwInterrupt;
#pragma warning(suppress : 4152)
    InitData.HwFindAdapter              = HwFindAdapter;
    InitData.HwResetBus                 = HwResetBus;
    InitData.HwDmaStarted               = NULL;
    InitData.HwAdapterState             = NULL;
    InitData.DeviceExtensionSize        = AdapterSizeofXenvbdAdapter();
    InitData.SpecificLuExtensionSize    = sizeof(ULONG); // not actually used
    InitData.SrbExtensionSize           = sizeof(XENVBD_SRBEXT);
    InitData.NumberOfAccessRanges       = 2;
    InitData.MapBuffers                 = STOR_MAP_NON_READ_WRITE_BUFFERS;
    InitData.NeedPhysicalAddresses      = TRUE;
    InitData.TaggedQueuing              = TRUE;
    InitData.AutoRequestSense           = TRUE;
    InitData.MultipleRequestPerLu       = TRUE;
    InitData.HwAdapterControl           = HwAdapterControl;
    InitData.HwBuildIo                  = HwBuildIo;

    status = StorPortInitialize(DriverObject,
                                RegistryPath,
                                &InitData,
                                NULL);
    if (!NT_SUCCESS(status))
        goto fail4;

    Driver.StorPortDispatchPnp   = DriverObject->MajorFunction[IRP_MJ_PNP];
    Driver.StorPortDispatchPower = DriverObject->MajorFunction[IRP_MJ_POWER];
    Driver.StorPortDriverUnload  = DriverObject->DriverUnload;

    DriverObject->MajorFunction[IRP_MJ_PNP]   = DispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = DispatchPower;
    DriverObject->DriverUnload                = DriverUnload;

    RegistryCloseKey(ServiceKey);
    ServiceKey = NULL;

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    BufferTerminate();

    RegistryCloseKey(Driver.ParametersKey);
    Driver.ParametersKey = NULL;

fail3:
    Error("fail3\n");

    RegistryCloseKey(ServiceKey);
    ServiceKey = NULL;

fail2:
    Error("fail2\n");

    RegistryTeardown();

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
