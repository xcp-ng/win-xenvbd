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

#ifndef _XENVBD_GRANTER_H
#define _XENVBD_GRANTER_H

#include <ntddk.h>

typedef struct _XENVBD_GRANTER XENVBD_GRANTER, *PXENVBD_GRANTER;

#include "frontend.h"

extern NTSTATUS
GranterCreate(
    _In_ PXENVBD_FRONTEND       Frontend,
    _Outptr_ PXENVBD_GRANTER    *Granter
    );

extern VOID
GranterDestroy(
    _Inout_ PXENVBD_GRANTER Granter
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
GranterD3ToD0(
    _Inout_ PXENVBD_GRANTER Granter
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
GranterD0ToD3(
    _Inout_ PXENVBD_GRANTER Granter
    );

extern NTSTATUS
GranterConnect(
    _Inout_ PXENVBD_GRANTER Granter
    );

extern NTSTATUS
GranterStoreWrite(
    _In_ PXENVBD_GRANTER    Granter,
    _In_ PVOID              Transaction
    );

extern VOID
GranterEnable(
    _Inout_ PXENVBD_GRANTER Granter
    );

extern VOID
GranterDisable(
    _Inout_ PXENVBD_GRANTER Granter
    );

extern VOID
GranterDisconnect(
    _Inout_ PXENVBD_GRANTER Granter
    );

extern NTSTATUS
GranterGet(
    _Inout_ PXENVBD_GRANTER Granter,
    _In_ PFN_NUMBER         Pfn,
    _In_ BOOLEAN            ReadOnly,
    _Outptr_ PVOID          *Handle
    );

_Check_return_
extern NTSTATUS
GranterTryPut(
    _Inout_ PXENVBD_GRANTER Granter,
    _In_ PVOID              Handle
    );

extern ULONG
GranterReference(
    _In_ PXENVBD_GRANTER    Granter,
    _In_ PVOID              Handle
    );

#endif // _XENVBD_GRANTER_H
