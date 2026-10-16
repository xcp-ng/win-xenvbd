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

#ifndef _XENVBD_REGISTRY_H
#define _XENVBD_REGISTRY_H

#include <ntddk.h>

extern NTSTATUS
RegistryInitialize(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    Path
    );

extern VOID
RegistryTeardown(
    VOID
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenKey(
    _In_ HANDLE             Parent,
    _In_ PUNICODE_STRING    Path,
    _In_ ACCESS_MASK        DesiredAccess,
    _Out_ PHANDLE           Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryCreateKey(
    _In_ HANDLE             Parent,
    _In_ PUNICODE_STRING    Path,
    _In_ ULONG              Options,
    _Out_ PHANDLE           Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenServiceKey(
    _In_ ACCESS_MASK    DesiredAccess,
    _Out_ PHANDLE       Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryCreateServiceKey(
    _Out_ PHANDLE   Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenParametersKey(
    _In_ ACCESS_MASK    DesiredAccess,
    _Out_ PHANDLE       Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenSoftwareKey(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ACCESS_MASK    DesiredAccess,
    _Out_ PHANDLE       Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenHardwareKey(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ACCESS_MASK    DesiredAccess,
    _Out_ PHANDLE       Key
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenSubKey(
    _In_ HANDLE         Key,
    _In_ PCHAR          Name,
    _In_ ACCESS_MASK    DesiredAccess,
    _Out_ PHANDLE       SubKey
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryCreateSubKey(
    _In_ HANDLE     Key,
    _In_ PCHAR      Name,
    _In_ ULONG      Options,
    _Out_ PHANDLE   SubKey
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryDeleteSubKey(
    _In_ HANDLE Key,
    _In_ PCHAR  Name
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryEnumerateSubKeys(
    _In_ HANDLE     Key,
    _In_ NTSTATUS   (*Callback)(PVOID, HANDLE, PANSI_STRING),
    _In_ PVOID      Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryEnumerateValues(
    _In_ HANDLE     Key,
    _In_ NTSTATUS   (*Callback)(PVOID, HANDLE, PANSI_STRING, ULONG),
    _In_ PVOID      Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryDeleteValue(
    _In_ HANDLE Key,
    _In_ PCHAR  Name
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQueryDwordValue(
    _In_ HANDLE     Key,
    _In_ PCHAR      Name,
    _Out_ PULONG    Value
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryUpdateDwordValue(
    _In_ HANDLE Key,
    _In_ PCHAR  Name,
    _In_ ULONG  Value
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQuerySzValue(
    _In_ HANDLE             Key,
    _In_ PCHAR              Name,
    _Out_opt_ PULONG        Type,
    _Outptr_ PANSI_STRING   *Array
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQueryBinaryValue(
    _In_ HANDLE     Key,
    _In_ PCHAR      Name,
    _Outptr_ PVOID  *Buffer,
    _Out_ PULONG    Length
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryUpdateBinaryValue(
    _In_ HANDLE Key,
    _In_ PCHAR  Name,
    _In_ PVOID  Buffer,
    _In_ ULONG  Length
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQueryKeyName(
    _In_ HANDLE             Key,
    _Outptr_ PANSI_STRING   *Array
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQuerySystemStartOption(
    _In_ const CHAR         *Prefix,
    _Outptr_ PANSI_STRING   *Option
    );

extern VOID
RegistryFreeSzValue(
    _In_ PANSI_STRING   Array
    );

extern VOID
RegistryFreeBinaryValue(
    _In_ PVOID  Buffer
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern NTSTATUS
RegistryUpdateSzValue(
    _In_ HANDLE         Key,
    _In_ PCHAR          Name,
    _In_ ULONG          Type,
    _In_ PANSI_STRING   Array
    );

_IRQL_requires_(PASSIVE_LEVEL)
extern VOID
RegistryCloseKey(
    _In_ HANDLE Key
    );

#endif  // _XENVBD_REGISTRY_H
