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

#ifndef _XENVBD_THREAD_H
#define _XENVBD_THREAD_H

#include <ntddk.h>

typedef struct _XENVBD_THREAD XENVBD_THREAD, *PXENVBD_THREAD;

typedef NTSTATUS (*XENVBD_THREAD_FUNCTION)(PXENVBD_THREAD, PVOID);

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
_ThreadCreate(
    _In_ PSTR                   Name,
    _In_ XENVBD_THREAD_FUNCTION Function,
    _In_opt_ PVOID              Context,
    _Outptr_ PXENVBD_THREAD     *Thread
    );

#define ThreadCreate(_f, _c, _t)    \
            _ThreadCreate(#_f, _f, _c, _t)

extern PKEVENT
ThreadGetEvent(
    _In_ PXENVBD_THREAD Self
    );

_Check_return_
extern BOOLEAN
ThreadIsAlerted(
    _In_ PXENVBD_THREAD Self
    );

extern VOID
ThreadWake(
    _Inout_ PXENVBD_THREAD  Thread
    );

extern VOID
ThreadAlert(
    _Inout_ PXENVBD_THREAD  Thread
    );

_Check_return_
_IRQL_requires_max_(PASSIVE_LEVEL)
extern BOOLEAN
ThreadWait(
    _Inout_ PXENVBD_THREAD  Thread
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
extern VOID
ThreadJoin(
    _Inout_ PXENVBD_THREAD  Thread
    );

#endif  // _XENVBD_THREAD_H
