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

#include <ntddk.h>

#include "base64.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

#define BASE64_POOL_TAG '46BX'

static FORCEINLINE PVOID
Base64Allocate(
    IN  ULONG   Size
    )
{
    PVOID       Buffer;

    Buffer = ALLOCATE_POOL(NonPagedPool,
                                   Size,
                                   BASE64_POOL_TAG);
    if (Buffer)
        RtlZeroMemory(Buffer, Size);

    return Buffer;
}

VOID
Base64Free(
    IN  PVOID   Buffer
    )
{
    if (Buffer)
        ExFreePoolWithTag(Buffer, BASE64_POOL_TAG);
}

static FORCEINLINE UCHAR
__DecodeChar(
    IN  CHAR    Char
    )
{
    if (Char >= 'A' && Char <= 'Z') return Char - 'A';
    if (Char >= 'a' && Char <= 'z') return Char - 'a' + 26;
    if (Char >= '0' && Char <= '9') return Char - '0' + 52;
    if (Char == '+')                return 62;
    if (Char == '/')                return 63;
    if (Char == '=')                return 0;
    return 0xFF;
}

static DECLSPEC_NOINLINE CHAR
__Decode(
    IN  PUCHAR  Dst,
    IN  PCHAR   Src,
    IN  ULONG   Left
    )
{
    UCHAR   Values[4];

    if (Left < 4)
        return -1;

    // take 4 Src chars -> 1, 2, or 3 Dest bytes
    Values[0] = __DecodeChar(Src[0]);
    Values[1] = __DecodeChar(Src[1]);
    Values[2] = __DecodeChar(Src[2]);
    Values[3] = __DecodeChar(Src[3]);

    // sanity checks
    if ((Src[0] == '=' || Src[1] == '=') ||
        (Src[2] == '=' && Src[3] != '='))
        return -2;
    if (Values[0] == 0xFF || Values[1] == 0xFF ||
        Values[2] == 0xFF || Values[3] == 0xFF)
        return -3;

    // convert
    Dst[0] = (Values[1] >> 4) | (Values[0] << 2);
    if (Src[2] == '=')
        return 2;

    Dst[1] = (Values[2] >> 2) | (Values[1] << 4);
    if (Src[3] == '=')
        return 1;

    Dst[2] = (Values[3]     ) | (Values[2] << 6);
    return 0;
}

NTSTATUS
Base64Decode(
    IN  PCHAR   String,
    OUT PVOID   *Binary,
    OUT PULONG  Length
    )
{
    ULONG       StringLength;
    ULONG       BlockCount;
    ULONG       Index;
    PUCHAR      Buffer;
    CHAR        Padding;
    NTSTATUS    status;

    StringLength = (ULONG)strlen(String);

    status = STATUS_INVALID_PARAMETER;
    if (StringLength % 4 != 0)
        goto fail1;

    BlockCount = StringLength / 4;
    Buffer = Base64Allocate(BlockCount * 3);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail2;

    Padding = 0;
    status = STATUS_INVALID_PARAMETER;
    for (Index = 0; Index < BlockCount; ++Index) {
        if (Padding != 0)
            goto fail3;
        Padding = __Decode(&Buffer[Index * 3],
                           &String[Index * 4],
                           StringLength - (Index * 4));
        if (Padding < 0 || Padding > 2)
            goto fail4;
    }

    *Length = (BlockCount * 3) - Padding;
    *Binary = Buffer;
    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
fail2:
    Error("fail2\n");
    Base64Free(Buffer);
fail1:
    Error("fail1 %08x\n", status);
    *Binary = NULL;
    *Length = 0;
    return status;
}
