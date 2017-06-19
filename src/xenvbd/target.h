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

#ifndef _XENVBD_TARGET_H
#define _XENVBD_TARGET_H

typedef struct _XENVBD_TARGET XENVBD_TARGET, *PXENVBD_TARGET;

#include <ntddk.h>
#include <ntstrsafe.h>
#include <xenvbd-storport.h>
#include "adapter.h"
#include "srbext.h"
#include "types.h"
#include <debug_interface.h>

extern VOID
TargetDebugCallback(
    __in PXENVBD_TARGET             Target,
    __in PXENBUS_DEBUG_INTERFACE Debug
    );

// Creation/Deletion
__checkReturn
extern NTSTATUS
TargetCreate(
    __in PXENVBD_ADAPTER             Adapter,
    __in __nullterminated PCHAR  DeviceId,
    OUT PXENVBD_TARGET*         _Target
    );

extern VOID
TargetDestroy(
    __in PXENVBD_TARGET             Target
    );

__checkReturn
extern NTSTATUS
TargetD3ToD0(
    __in PXENVBD_TARGET             Target
    );

extern VOID
TargetD0ToD3(
    __in PXENVBD_TARGET             Target
    );

// PnP States
extern VOID
TargetSetMissing(
    __in PXENVBD_TARGET             Target,
    __in __nullterminated const CHAR* Reason
    );

__checkReturn
extern BOOLEAN
TargetIsMissing(
    __in PXENVBD_TARGET             Target
    );

extern VOID
TargetSetDevicePnpState(
    __in PXENVBD_TARGET             Target,
    __in DEVICE_PNP_STATE        State
    );

__checkReturn
extern DEVICE_PNP_STATE
TargetGetDevicePnpState(
    __in PXENVBD_TARGET             Target
    );

// Query Methods
extern ULONG
TargetGetTargetId(
    __in PXENVBD_TARGET             Target
    );

extern ULONG
TargetGetDeviceId(
    __in PXENVBD_TARGET             Target
    );

__checkReturn
extern PDEVICE_OBJECT
TargetGetDeviceObject(
    __in PXENVBD_TARGET             Target
    );

extern VOID
TargetSetDeviceObject(
    __in PXENVBD_TARGET             Target,
    __in PDEVICE_OBJECT          DeviceObject
    );

__checkReturn
extern BOOLEAN
TargetIsPaused(
    __in PXENVBD_TARGET             Target
    );

__checkReturn
extern PXENVBD_ADAPTER
TargetGetAdapter(
    __in PXENVBD_TARGET             Target
    );

// Queue-Related
extern VOID
TargetSubmitRequests(
    __in PXENVBD_TARGET             Target
    );

extern VOID
TargetCompleteResponse(
    __in PXENVBD_TARGET             Target,
    __in ULONG                   Tag,
    __in SHORT                   Status
    );

extern VOID
TargetPreResume(
    __in PXENVBD_TARGET             Target
    );

extern VOID
TargetPostResume(
    __in PXENVBD_TARGET             Target
    );

// StorPort Methods
extern VOID
TargetReset(
    __in PXENVBD_TARGET             Target
    );

__checkReturn
extern BOOLEAN
TargetStartIo(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_REQUEST_BLOCK     Srb
    );

extern VOID
TargetSrbPnp(
    __in PXENVBD_TARGET             Target,
    __in PSCSI_PNP_REQUEST_BLOCK Srb
    );

// PnP Handler
__checkReturn
extern NTSTATUS
TargetDispatchPnp(
    __in PXENVBD_TARGET             Target,
    __in PDEVICE_OBJECT          DeviceObject,
    __in PIRP                    Irp
    );

__drv_maxIRQL(DISPATCH_LEVEL)
extern VOID
TargetIssueDeviceEject(
    __in PXENVBD_TARGET             Target,
    __in __nullterminated const CHAR* Reason
    );

#endif // _XENVBD_TARGET_H
