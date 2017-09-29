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

#ifndef _XENVBD_DRIVER_H
#define _XENVBD_DRIVER_H

#include <ntddk.h>

#define XENVBD_MAX_TARGETS              (255)
#define XENVBD_MAX_PAGES_PER_SRB        (1024)
#define XENVBD_MAX_TRANSFER_LENGTH      (XENVBD_MAX_PAGES_PER_SRB * PAGE_SIZE)
#define XENVBD_MAX_PHYSICAL_BREAKS      (XENVBD_MAX_PAGES_PER_SRB - 1)

extern VOID
DriverSetAdapter(
    IN  PVOID   Adapter
    );

extern HANDLE
DriverGetParametersKey(
    VOID
    );

extern NTSTATUS
DriverDispatchPnp(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    );

extern NTSTATUS
DriverDispatchPower(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern VOID
DriverRequestReboot(
    VOID
    );

// Registry overrides for driver features
typedef enum _XENVBD_FEATURE {
    FeatureRemovable = 0,
    FeaturePersistent,
    FeatureMaxIndirectSegments,
    FeatureBarrier,
    FeatureFlushCache,
    FeatureDiscard,
    FeatureDiscardEnable,
    FeatureDiscardSecure,
    FeatureDiscardAlignment,
    FeatureDiscardGranularity,
    FeatureMaxRingPageOrder,

    // Add any new features before this enum
    NumberOfFeatures
} XENVBD_FEATURE, *PXENVBD_FEATURE;

__checkReturn
_Success_(return)
extern BOOLEAN
DriverGetFeatureOverride(
    IN  XENVBD_FEATURE   Feature,
    OUT PULONG           Value
    );

__checkReturn
extern const CHAR *
DriverGetFeatureName(
    IN  XENVBD_FEATURE  Feature
    );

#endif // _XENVBD_DRIVER_H
