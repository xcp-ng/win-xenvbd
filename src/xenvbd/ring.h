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

#ifndef _XENVBD_RING_H
#define _XENVBD_RING_H

typedef struct _XENVBD_RING XENVBD_RING, *PXENVBD_RING;

#include "frontend.h"
#include "srbext.h"

extern NTSTATUS
RingCreate(
    _In_ PXENVBD_FRONTEND   Frontend,
    _Outptr_ PXENVBD_RING   *Ring
    );

extern VOID
RingDestroy(
    _In_ PXENVBD_RING   Ring
    );

extern NTSTATUS
RingConnect(
    _In_ PXENVBD_RING   Ring
    );

extern NTSTATUS
RingStoreWrite(
    _In_ PXENVBD_RING   Ring,
    _In_ PVOID          Transaction
    );

extern VOID
RingEnable(
    _In_ PXENVBD_RING   Ring
    );

extern VOID
RingDisable(
    _In_ PXENVBD_RING   Ring
    );

extern VOID
RingDisconnect(
    _In_ PXENVBD_RING   Ring
    );

extern BOOLEAN
RingIsPoisoned(
    _In_ PXENVBD_RING   Ring
    );

extern BOOLEAN
RingQueueRequest(
    _In_ PXENVBD_RING   Ring,
    _In_ PXENVBD_SRBEXT SrbExt
    );

extern BOOLEAN
RingQueueShutdown(
    _In_ PXENVBD_RING   Ring,
    _In_ PXENVBD_SRBEXT SrbExt
    );

#endif // _XENVBD_RING_H
