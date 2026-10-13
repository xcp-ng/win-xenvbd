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

#ifndef _XENVBD_PDO_H
#define _XENVBD_PDO_H

#include <wdm.h>
#include <xenvbd-storport.h>


typedef struct _XENVBD_PDO XENVBD_PDO, *PXENVBD_PDO;

#include "fdo.h"
#include "ring.h"

// Creation/Deletion
extern NTSTATUS
PdoCreate(
    _In_ PXENVBD_FDO        Fdo,
    _In_ PSTR               DeviceId,
    _In_ ULONG              TargetId,
    _Outptr_ PXENVBD_PDO    *_Pdo
    );

extern VOID
PdoDestroy(
    _In_ PXENVBD_PDO    Pdo
    );

extern VOID
PdoD3ToD0(
    _In_ PXENVBD_PDO    Pdo
    );

extern VOID
PdoD0ToD3(
    _In_ PXENVBD_PDO    Pdo
    );

// Reference Counting
extern VOID
PdoReference(
    _In_ PXENVBD_PDO    Pdo
    );

extern VOID
PdoDereference(
    _In_ PXENVBD_PDO    Pdo
    );

// Query Methods
extern ULONG
PdoSectorSize(
    _In_ PXENVBD_PDO    Pdo
    );

// Queue-Related
extern VOID
PdoPrepareFresh(
    _In_ PXENVBD_PDO    Pdo
    );

extern VOID
PdoSubmitPrepared(
    _In_ PXENVBD_PDO    Pdo
    );

extern VOID
PdoCompleteShutdown(
    _In_ PXENVBD_PDO    Pdo
    );

extern VOID
PdoCompleteSubmittedRequest(
    _In_ PXENVBD_PDO        Pdo,
    _In_ PXENVBD_REQUEST    Request,
    _In_ SHORT              Status
    );

// StorPort Methods
extern VOID
PdoReset(
    _In_ PXENVBD_PDO    Pdo
    );

extern BOOLEAN
PdoStartIo(
    _In_ PXENVBD_PDO            Pdo,
    _In_ PSCSI_REQUEST_BLOCK    Srb
    );

extern VOID
PdoAbortAllSrbs(
    _In_ PXENVBD_PDO    Pdo
    );

extern VOID
PdoEvtchnInterruptHandler(
    _In_ PXENVBD_PDO    Pdo
    );

#endif // _XENVBD_PDO_H
