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

#ifndef _XENVBD_ADAPTER_H
#define _XENVBD_ADAPTER_H

#include <ntddk.h>

typedef struct _XENVBD_ADAPTER XENVBD_ADAPTER, *PXENVBD_ADAPTER;

#include <cache_interface.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>

#include "srbext.h"

#define ADAPTER_GET_INTERFACE(_name, _type)     \
extern VOID                                     \
AdapterGet ## _name ## Interface(               \
    IN  PXENVBD_ADAPTER Adapter,                \
    OUT _type           _name ## Interface      \
    );

ADAPTER_GET_INTERFACE(Cache, PXENBUS_CACHE_INTERFACE)
ADAPTER_GET_INTERFACE(Store, PXENBUS_STORE_INTERFACE)
ADAPTER_GET_INTERFACE(Debug, PXENBUS_DEBUG_INTERFACE)
ADAPTER_GET_INTERFACE(Evtchn, PXENBUS_EVTCHN_INTERFACE)
ADAPTER_GET_INTERFACE(Gnttab, PXENBUS_GNTTAB_INTERFACE)
ADAPTER_GET_INTERFACE(Suspend, PXENBUS_SUSPEND_INTERFACE)

#undef ADAPTER_GET_INTERFACE

extern BOOLEAN
AdapterIsTargetEmulated(
    IN  PXENVBD_ADAPTER Adapter,
    IN  ULONG           TargetId
    );

extern VOID
AdapterCompleteSrb(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PXENVBD_SRBEXT  SrbExt
    );

extern VOID
AdapterTargetListChanged(
    IN  PXENVBD_ADAPTER Adapter
    );

extern VOID
AdapterSetDeviceQueueDepth(
    IN  PXENVBD_ADAPTER Adapter,
    IN  ULONG           TargetId
    );

extern PFN_NUMBER
AdapterGetNextSGEntry(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PXENVBD_SRBEXT  SrbExt,
    IN  ULONG           Existing,
    OUT PULONG          Offset,
    OUT PULONG          Length
    );

extern PXENVBD_BOUNCE
AdapterGetBounce(
    IN  PXENVBD_ADAPTER Adapter
    );

extern VOID
AdapterPutBounce(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PXENVBD_BOUNCE  Bounce
    );

extern NTSTATUS
AdapterDispatchPnp(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    );

extern NTSTATUS
AdapterDispatchPower(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    );

extern NTSTATUS
AdapterDriverEntry(
    IN  PUNICODE_STRING RegistryPath,
    IN  PDRIVER_OBJECT  DriverObject
    );

#endif // _XENVBD_ADAPTER_H
