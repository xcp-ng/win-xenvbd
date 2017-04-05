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

#include <storport.h>
#include "pdo.h"
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>
#include <unplug_interface.h>

// Link PDOs
extern BOOLEAN
AdapterLinkPdo(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PXENVBD_PDO                 Pdo
    );

extern BOOLEAN
AdapterUnlinkPdo(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PXENVBD_PDO                 Pdo
    );
// Query Methods
__checkReturn
extern PDEVICE_OBJECT
AdapterGetDeviceObject(
    __in PXENVBD_ADAPTER                 Adapter
    );

extern ULONG
AdapterSizeofXenvbdAdapter(
    );

extern PCHAR
AdapterEnum(
    __in PXENVBD_ADAPTER                 Adapter
    );

// SRB Methods
extern VOID
AdapterStartSrb(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_REQUEST_BLOCK         Srb
    );

extern VOID
AdapterCompleteSrb(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_REQUEST_BLOCK         Srb
    );

// StorPort Methods
extern BOOLEAN
AdapterResetBus(
    __in PXENVBD_ADAPTER                 Adapter
    );

extern ULONG
AdapterFindAdapter(
    __in PXENVBD_ADAPTER                 Adapter,
    __inout PPORT_CONFIGURATION_INFORMATION  ConfigInfo
    );

extern BOOLEAN
AdapterBuildIo(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_REQUEST_BLOCK         Srb
    );

extern BOOLEAN
AdapterStartIo(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PSCSI_REQUEST_BLOCK         Srb
    );

__checkReturn
extern NTSTATUS
AdapterForwardPnp(
    __in PXENVBD_ADAPTER                Adapter,
    __in PDEVICE_OBJECT             DeviceObject,
    __in PIRP                       Irp
    );

__checkReturn
extern NTSTATUS
AdapterDispatchPnp(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    );

__checkReturn
extern NTSTATUS
AdapterDispatchPower(
    __in PXENVBD_ADAPTER                 Adapter,
    __in PDEVICE_OBJECT              DeviceObject,
    __in PIRP                        Irp
    );

extern PXENBUS_STORE_INTERFACE
AdapterAcquireStore(
    __in PXENVBD_ADAPTER                 Adapter
    );

extern PXENBUS_EVTCHN_INTERFACE
AdapterAcquireEvtchn(
    __in PXENVBD_ADAPTER                 Adapter
    );

extern PXENBUS_GNTTAB_INTERFACE
AdapterAcquireGnttab(
    __in PXENVBD_ADAPTER                 Adapter
    );

extern PXENBUS_DEBUG_INTERFACE
AdapterAcquireDebug(
    __in PXENVBD_ADAPTER                 Adapter
    );

extern PXENBUS_SUSPEND_INTERFACE
AdapterAcquireSuspend(
    __in PXENVBD_ADAPTER                 Adapter
    );

#endif // _XENVBD_ADAPTER_H
