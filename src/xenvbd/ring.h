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

#ifndef _XENVBD_RING_H
#define _XENVBD_RING_H

typedef struct _XENVBD_RING XENVBD_RING, *PXENVBD_RING;

#include "frontend.h"
#include "srbext.h"

extern NTSTATUS
RingCreate(
    IN  PXENVBD_FRONTEND    Frontend,
    OUT PXENVBD_RING*       Ring
    );

extern VOID
RingDestroy(
    IN  PXENVBD_RING    Ring
    );

extern NTSTATUS
RingConnect(
    IN  PXENVBD_RING    Ring
    );

extern NTSTATUS
RingStoreWrite(
    IN  PXENVBD_RING    Ring,
    IN  PVOID           Transaction
    );

extern VOID
RingEnable(
    IN  PXENVBD_RING    Ring
    );

extern VOID
RingDisable(
    IN  PXENVBD_RING    Ring
    );

extern VOID
RingDisconnect(
    IN  PXENVBD_RING    Ring
    );

extern VOID
RingTrigger(
    IN  PXENVBD_RING    Ring
    );

extern VOID
RingQueueRequest(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    );

extern VOID
RingQueueShutdown(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    );

#endif // _XENVBD_RING_H
