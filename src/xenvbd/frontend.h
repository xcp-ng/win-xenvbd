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

#ifndef _XENVBD_FRONTEND_H
#define _XENVBD_FRONTEND_H

#include <ntddk.h>

typedef enum _XENVBD_STATE {
    XENVBD_STATE_INVALID,
    XENVBD_INITIALIZED, // -> { CLOSED }
    XENVBD_CLOSING,     // -> { CLOSED }
    XENVBD_CLOSED,      // -> { PREPARED }
    XENVBD_PREPARED,    // -> { CLOSING, CONNECTED }
    XENVBD_CONNECTED,   // -> { ENABLED, CLOSING }
    XENVBD_ENABLED      // -> { CLOSING }
} XENVBD_STATE, *PXENVBD_STATE;

typedef struct _XENVBD_CAPS {
    BOOLEAN                     Connected;
    BOOLEAN                     Removable;
    BOOLEAN                     SurpriseRemovable;
    BOOLEAN                     Paging;
    BOOLEAN                     Hibernation;
    BOOLEAN                     DumpFile;
} XENVBD_CAPS, *PXENVBD_CAPS;

typedef struct _XENVBD_FEATURES {
    ULONG                       Indirect;
    BOOLEAN                     Persistent;
} XENVBD_FEATURES, *PXENVBD_FEATURES;

typedef struct _XENVBD_DISKINFO {
    ULONG64                     SectorCount;
    ULONG                       SectorSize;
    ULONG                       PhysSectorSize;
    ULONG                       DiskInfo;
    BOOLEAN                     Barrier;
    BOOLEAN                     FlushCache;
    BOOLEAN                     Discard;
    BOOLEAN                     DiscardSecure;
    ULONG                       DiscardAlignment;
    ULONG                       DiscardGranularity;
} XENVBD_DISKINFO, *PXENVBD_DISKINFO;

typedef struct _XENVBD_FRONTEND XENVBD_FRONTEND, *PXENVBD_FRONTEND;

#include "target.h"

extern VOID
FrontendRemoveFeature(
    IN  PXENVBD_FRONTEND        Frontend,
    IN  UCHAR                   BlkifOperation
    );

extern PVOID
FrontendGetInquiryOverride(
    IN  PXENVBD_FRONTEND    Frontend,
    IN  UCHAR               PageCode,
    OUT PULONG              Length
    );

extern VOID
FrontendSetEjected(
    IN  PXENVBD_FRONTEND    Frontend
    );

extern VOID
FrontendSetEjectFailed(
    IN  PXENVBD_FRONTEND    Frontend
    );

extern VOID
FrontendSetDeviceUsage(
    IN  PXENVBD_FRONTEND                Frontend,
    IN  DEVICE_USAGE_NOTIFICATION_TYPE  Type,
    IN  BOOLEAN                         Value
    );

__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
extern NTSTATUS
FrontendD3ToD0(
    IN  PXENVBD_FRONTEND    Frontend
    );

__drv_maxIRQL(DISPATCH_LEVEL)
extern VOID
FrontendD0ToD3(
    IN  PXENVBD_FRONTEND    Frontend
    );

__checkReturn
extern NTSTATUS
FrontendSetState(
    IN  PXENVBD_FRONTEND    Frontend,
    IN  XENVBD_STATE        State
    );

extern NTSTATUS
FrontendReset(
    IN  PXENVBD_FRONTEND    Frontend
    );

extern NTSTATUS
FrontendCreate(
    IN  PXENVBD_TARGET      Target,
    IN  PCHAR               DeviceId,
    IN  ULONG               TargetId,
    OUT PXENVBD_FRONTEND*   _Frontend
    );

extern VOID
FrontendDestroy(
    IN  PXENVBD_FRONTEND    Frontend
    );

#define FRONTEND_GET_PROPERTY(_name, _type)     \
extern _type                                    \
FrontendGet ## _name ## (                       \
    IN  PXENVBD_FRONTEND    Frontend            \
    );

FRONTEND_GET_PROPERTY(Target, PXENVBD_TARGET)
#include "ring.h"
FRONTEND_GET_PROPERTY(Ring, PXENVBD_RING)
#include "granter.h"
FRONTEND_GET_PROPERTY(Granter, PXENVBD_GRANTER)
FRONTEND_GET_PROPERTY(TargetId, ULONG)
FRONTEND_GET_PROPERTY(DeviceId, ULONG)
FRONTEND_GET_PROPERTY(BackendDomain, ULONG)
FRONTEND_GET_PROPERTY(BackendPath, PCHAR)
FRONTEND_GET_PROPERTY(FrontendPath, PCHAR)
FRONTEND_GET_PROPERTY(Caps, PXENVBD_CAPS)
FRONTEND_GET_PROPERTY(Features, PXENVBD_FEATURES)
FRONTEND_GET_PROPERTY(DiskInfo, PXENVBD_DISKINFO)
FRONTEND_GET_PROPERTY(Connected, BOOLEAN)
FRONTEND_GET_PROPERTY(ReadOnly, BOOLEAN)
FRONTEND_GET_PROPERTY(Discard, BOOLEAN)
FRONTEND_GET_PROPERTY(FlushCache, BOOLEAN)
FRONTEND_GET_PROPERTY(Barrier, BOOLEAN)
FRONTEND_GET_PROPERTY(MaxQueues, ULONG)
FRONTEND_GET_PROPERTY(NumQueues, ULONG)

#undef FRONTEND_GET_PROPERTY

#endif // _XENVBD_FRONTEND_H
