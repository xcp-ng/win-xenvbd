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

#ifndef _XENVBD_GRANTER_H
#define _XENVBD_GRANTER_H

#include <ntddk.h>

typedef struct _XENVBD_GRANTER XENVBD_GRANTER, *PXENVBD_GRANTER;

#include "frontend.h"

extern NTSTATUS
GranterCreate(
    IN  PXENVBD_FRONTEND    Frontend,
    OUT PXENVBD_GRANTER     *Granter
    );

extern VOID
GranterDestroy(
    IN  PXENVBD_GRANTER     Granter
    );

extern NTSTATUS
GranterConnect(
    IN  PXENVBD_GRANTER     Granter
    );

extern NTSTATUS
GranterStoreWrite(
    IN  PXENVBD_GRANTER Granter,
    IN  PVOID           Transaction
    );

extern VOID
GranterEnable(
    IN  PXENVBD_GRANTER Granter
    );

extern VOID
GranterDisable(
    IN  PXENVBD_GRANTER Granter
    );

extern VOID
GranterDisconnect(
    IN  PXENVBD_GRANTER Granter
    );

extern NTSTATUS
GranterGet(
    IN  PXENVBD_GRANTER Granter,
    IN  PFN_NUMBER      Pfn,
    IN  BOOLEAN         ReadOnly,
    OUT PVOID           *Handle
    );

extern VOID
GranterPut(
    IN  PXENVBD_GRANTER Granter,
    IN  PVOID           Handle
    );

extern ULONG
GranterReference(
    IN  PXENVBD_GRANTER Granter,
    IN  PVOID           Handle
    );

#endif // _XENVBD_GRANTER_H
