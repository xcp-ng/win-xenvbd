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
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PUNICODE_STRING Path
    );

extern VOID
RegistryTeardown(
    VOID
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenKey(
    IN  HANDLE          Parent,
    IN  PUNICODE_STRING Path,
    IN  ACCESS_MASK     DesiredAccess,
    OUT PHANDLE         Key
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryCreateKey(
    IN  HANDLE          Parent,
    IN  PUNICODE_STRING Path,
    IN  ULONG           Options,
    OUT PHANDLE         Key
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenServiceKey(
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     Key
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryCreateServiceKey(
    OUT PHANDLE     Key
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenParametersKey(
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     Key
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenSoftwareKey(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  ACCESS_MASK     DesiredAccess,
    OUT PHANDLE         Key
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenHardwareKey(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  ACCESS_MASK     DesiredAccess,
    OUT PHANDLE         Key
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryOpenSubKey(
    IN  HANDLE      Key,
    IN  PCHAR       Name,
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     SubKey
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryCreateSubKey(
    IN  HANDLE      Key,
    IN  PCHAR       Name,
    IN  ULONG       Options,
    OUT PHANDLE     SubKey
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryDeleteSubKey(
    IN  HANDLE      Key,
    IN  PCHAR       Name
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryEnumerateSubKeys(
    IN  HANDLE      Key,
    IN  NTSTATUS    (*Callback)(PVOID, HANDLE, PANSI_STRING),
    IN  PVOID       Context
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryEnumerateValues(
    IN  HANDLE      Key,
    IN  NTSTATUS    (*Callback)(PVOID, HANDLE, PANSI_STRING, ULONG),
    IN  PVOID       Context
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryDeleteValue(
    IN  HANDLE      Key,
    IN  PCHAR       Name
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQueryDwordValue(
    IN  HANDLE          Key,
    IN  PCHAR           Name,
    OUT PULONG          Value
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryUpdateDwordValue(
    IN  HANDLE          Key,
    IN  PCHAR           Name,
    IN  ULONG           Value
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQuerySzValue(
    IN  HANDLE          Key,
    IN  PCHAR           Name,
    OUT PULONG          Type OPTIONAL,
    OUT PANSI_STRING    *Array
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQueryBinaryValue(
    IN  HANDLE          Key,
    IN  PCHAR           Name,
    OUT PVOID           *Buffer,
    OUT PULONG          Length
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryUpdateBinaryValue(
    IN  HANDLE          Key,
    IN  PCHAR           Name,
    IN  PVOID           Buffer,
    IN  ULONG           Length
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQueryKeyName(
    IN  HANDLE              Key,
    OUT PANSI_STRING        *Array
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryQuerySystemStartOption(
    IN  const CHAR      *Prefix,
    OUT PANSI_STRING    *Option
    );

extern VOID
RegistryFreeSzValue(
    IN  PANSI_STRING    Array
    );

extern VOID
RegistryFreeBinaryValue(
    IN  PVOID           Buffer
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern NTSTATUS
RegistryUpdateSzValue(
    IN  HANDLE          Key,
    IN  PCHAR           Name,
    IN  ULONG           Type,
    IN  PANSI_STRING    Array
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
extern VOID
RegistryCloseKey(
    IN  HANDLE  Key
    );

#endif  // _XENVBD_REGISTRY_H
