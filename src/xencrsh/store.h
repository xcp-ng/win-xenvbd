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

#ifndef _XENVBD_STORE_H
#define _XENVBD_STORE_H

#include "driver.h"

NTSTATUS
StoreInitialize();

VOID
StoreTerminate();

NTSTATUS
StoreRead(
    _In_opt_ PVOID  Transaction,
    _In_opt_ PCHAR  Prefix,
    _In_ PCHAR      Node,
    _Outptr_ PCHAR  *Value
    );

NTSTATUS
StoreWrite(
    _In_opt_ PVOID  Transaction,
    _In_opt_ PCHAR  Prefix,
    _In_ PCHAR      Node,
    _In_ PCHAR      Value
    );

NTSTATUS
StorePrintf(
    _In_opt_ PVOID  Transaction,
    _In_opt_ PCHAR  Prefix,
    _In_ PCHAR      Node,
    _In_ const CHAR *Format,
    ...                                                   
    );

NTSTATUS
StoreRemove(                                                     
    _In_opt_ PVOID  Transaction,
    _In_opt_ PCHAR  Prefix,
    _In_ PCHAR      Node
    );

NTSTATUS
StoreDirectory(                                                     
    _In_opt_ PVOID  Transaction,
    _In_opt_ PCHAR  Prefix,
    _In_ PCHAR      Node,
    _Outptr_ PCHAR  *Value
    );

NTSTATUS
StoreTransactionStart(                                                     
    _Outptr_ PVOID  *Transaction
    );

NTSTATUS
StoreTransactionEnd(                                                     
    _In_ PVOID      Transaction,
    _In_ BOOLEAN    Commit
    );

#endif // _XENVBD_STORE_H
