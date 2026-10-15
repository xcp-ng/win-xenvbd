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

#ifndef _XENVBD_TARGET_H
#define _XENVBD_TARGET_H

#include <ntddk.h>

typedef struct _XENVBD_TARGET XENVBD_TARGET, *PXENVBD_TARGET;

#include "adapter.h"
#include "srbext.h"
#include "types.h"

extern NTSTATUS
TargetCreate(
    _In_ PXENVBD_ADAPTER    Adapter,
    _In_ PSTR               DeviceId,
    _Outptr_ PXENVBD_TARGET *_Target
    );

extern VOID
TargetDestroy(
    _Inout_ PXENVBD_TARGET  Target
    );

extern NTSTATUS
TargetD3ToD0(
    _Inout_ PXENVBD_TARGET  Target
    );

extern VOID
TargetD0ToD3(
    _Inout_ PXENVBD_TARGET  Target
    );

extern NTSTATUS
TargetDispatchPnp(
    _Inout_ PXENVBD_TARGET  Target,
    _In_ PDEVICE_OBJECT     DeviceObject,
    _In_ PIRP               Irp
    );

extern VOID
TargetIssueDeviceEject(
    _Inout_ PXENVBD_TARGET  Target,
    _In_ PCSTR              Reason
    );

extern VOID
TargetSetMissing(
    _Inout_ PXENVBD_TARGET  Target,
    _In_ PCSTR              Reason
    );

extern VOID
TargetSetDevicePnpState(
    _Inout_ PXENVBD_TARGET  Target,
    _In_ DEVICE_PNP_STATE   State
    );

extern VOID
TargetSetDeviceObject(
    _Inout_ PXENVBD_TARGET  Target,
    _In_ PDEVICE_OBJECT     DeviceObject
    );

extern VOID
TargetPrepareIo(
    _In_ PXENVBD_TARGET Target,
    _In_ PXENVBD_SRBEXT SrbExt
    );

extern BOOLEAN
TargetStartIo(
    _In_ PXENVBD_TARGET Target,
    _In_ PXENVBD_SRBEXT SrbExt
    );

extern VOID
TargetReset(
    _In_ PXENVBD_TARGET Target
    );

extern BOOLEAN
TargetFlush(
    _In_ PXENVBD_TARGET Target,
    _In_ PXENVBD_SRBEXT SrbExt
    );

extern BOOLEAN
TargetShutdown(
    _In_ PXENVBD_TARGET Target,
    _In_ PXENVBD_SRBEXT SrbExt
    );

#define TARGET_GET_PROPERTY(_name, _type)       \
extern _type                                    \
TargetGet ## _name ## (                         \
    IN  PXENVBD_TARGET  Target                  \
    );

TARGET_GET_PROPERTY(Adapter, PXENVBD_ADAPTER)
TARGET_GET_PROPERTY(DeviceObject, PDEVICE_OBJECT)
TARGET_GET_PROPERTY(TargetId, ULONG)
TARGET_GET_PROPERTY(DeviceId, ULONG)
TARGET_GET_PROPERTY(Removable, BOOLEAN)
TARGET_GET_PROPERTY(DevicePnpState, DEVICE_PNP_STATE)
TARGET_GET_PROPERTY(Missing, BOOLEAN)

#undef TARGET_GET_PROPERTY

#endif // _XENVBD_TARGET_H
