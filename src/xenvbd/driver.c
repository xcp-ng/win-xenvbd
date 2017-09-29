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

#include "util.h"
#include "debug.h"
#include "assert.h"

// Feature Overrides From Registry Values
typedef struct _XENVBD_FEATURE_OVERRIDE {
    const CHAR                  *Name;
    ULONG                       Value;
    BOOLEAN                     Present;
} XENVBD_FEATURE_OVERRIDE, *PXENVBD_FEATURE_OVERRIDE;

typedef struct _XENVBD_DRIVER {
    PXENVBD_ADAPTER             Adapter;
    HANDLE                      ParametersKey;
    PDRIVER_DISPATCH            StorPortDispatchPnp;
    PDRIVER_DISPATCH            StorPortDispatchPower;
    PDRIVER_UNLOAD              StorPortDriverUnload;
    XENVBD_FEATURE_OVERRIDE     FeatureOverride[NumberOfFeatures];
} XENVBD_DRIVER;

static XENVBD_DRIVER Driver;

#define XENVBD_POOL_TAG     'dbvX'

VOID
DriverSetAdapter(
    IN  PVOID   Adapter
    )
{
    ASSERT3P(Driver.Adapter, ==, NULL);
    ASSERT3P(Adapter, !=, NULL);
    Driver.Adapter = Adapter;
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

#define MAXNAMELEN  256

__drv_requiresIRQL(PASSIVE_LEVEL)
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

    return AdapterDispatchPnp(Driver.Adapter, DeviceObject, Irp);
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

    return AdapterDispatchPower(Driver.Adapter, DeviceObject, Irp);
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

    RegistryCloseKey(Driver.ParametersKey);
    Driver.ParametersKey = NULL;

    RegistryTeardown();
}

__drv_requiresIRQL(PASSIVE_LEVEL)
static FORCEINLINE VOID
__DriverInitializeOverrides(
    VOID
    )
{
    ULONG           Index;
    struct {
        const CHAR      *Name;
        XENVBD_FEATURE  Feature;
    } Mapping[] =
          {
              { "removable" , FeatureRemovable },
              { "feature-persistent", FeaturePersistent },
              { "feature-max-indirect-segments", FeatureMaxIndirectSegments },
              { "feature-barrier", FeatureBarrier },
              { "feature-flush-cache", FeatureFlushCache },
              { "feature-discard", FeatureDiscard },
              { "discard-enable", FeatureDiscardEnable },
              { "discard-secure", FeatureDiscardSecure },
              { "discard-alignment", FeatureDiscardAlignment },
              { "discard-granularity", FeatureDiscardGranularity }
          };

    for (Index = 0; Index < ARRAYSIZE(Mapping); Index++) {
        XENVBD_FEATURE  Feature = Mapping[Index].Feature;
        const CHAR      *Name = Mapping[Index].Name;
        ULONG           Value;
        NTSTATUS        status;

        Driver.FeatureOverride[Feature].Name = Name;

        status = RegistryQueryDwordValue(__DriverGetParametersKey(),
                                         (PCHAR)Name,
                                         &Value);

        if (!NT_SUCCESS(status))
            continue;

        Driver.FeatureOverride[Feature].Present = TRUE;
        Driver.FeatureOverride[Feature].Value = Value;
    }
}

__checkReturn
_Success_(return)
BOOLEAN
DriverGetFeatureOverride(
    IN  XENVBD_FEATURE   Feature,
    OUT PULONG           Value
    )
{
    BOOLEAN              Present = FALSE;

    if (Feature < ARRAYSIZE(Driver.FeatureOverride)) {
        Present = Driver.FeatureOverride[Feature].Present;
        *Value = Driver.FeatureOverride[Feature].Value;
    }

    return Present;
}

__checkReturn
const CHAR *
DriverGetFeatureName(
    IN  XENVBD_FEATURE  Feature
    )
{
    return (Feature < ARRAYSIZE(Driver.FeatureOverride)) ?
           Driver.FeatureOverride[Feature].Name :
           NULL;
}

DRIVER_INITIALIZE   DriverEntry;

NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT      DriverObject,
    IN  PUNICODE_STRING     RegistryPath
    )
{
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

    __DriverInitializeOverrides();

    status = AdapterDriverEntry(RegistryPath,
                                DriverObject);
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
