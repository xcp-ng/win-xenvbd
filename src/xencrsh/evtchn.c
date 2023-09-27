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

#include <wdm.h>
#include <xenvbd-storport.h>
         
         
#include <xen-version.h>
#include <xen\xen-compat.h>
         
#include <xen-types.h>
#include <xen-warnings.h>
#include <xen-errno.h>
#include <xen\memory.h>
#include <xen\event_channel.h>
#include <xen\grant_table.h>
#include <xen\hvm\params.h>
#include <xen\io\xs_wire.h>

#include "evtchn.h"
#include "hypercall.h"

#include "log.h"
#include "assert.h"

static FORCEINLINE LONG_PTR
EventChannelOp(
    IN  ULONG   Command,
    IN  PVOID   Argument
    )
{
    return Hypercall2(LONG_PTR, event_channel_op, Command, Argument);
}

NTSTATUS
EventChannelSend(
    IN  ULONG           LocalPort
    )
{
    struct evtchn_send  op;
    LONG_PTR            rc;
    NTSTATUS            status;

    op.port = LocalPort;

    rc = EventChannelOp(EVTCHNOP_send, &op);
    
    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
EventChannelReset(
    VOID
    )
{
    struct evtchn_reset op;
    LONG_PTR            rc;
    NTSTATUS            status;

    op.dom = DOMID_SELF;

    rc = EventChannelOp(EVTCHNOP_reset, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
EventChannelBindInterDomain(
    IN  USHORT                      RemoteDomain,
    IN  ULONG                       RemotePort,
    OUT PULONG                      LocalPort
    )
{
    struct evtchn_bind_interdomain  op;
    LONG_PTR                        rc;
    NTSTATUS                        status;

    op.remote_dom = RemoteDomain,
    op.remote_port = RemotePort;

    rc = EventChannelOp(EVTCHNOP_bind_interdomain, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    *LocalPort = op.local_port;

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
EventChannelQueryInterDomain(
    IN  ULONG               LocalPort,
    OUT PUSHORT             RemoteDomain,
    OUT PULONG              RemotePort
    )
{
    struct evtchn_status    op;
    LONG_PTR                rc;
    NTSTATUS                status;

    op.dom = DOMID_SELF;
    op.port = LocalPort;

    rc = EventChannelOp(EVTCHNOP_status, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    status = STATUS_INVALID_PARAMETER;
    if (op.status != EVTCHNSTAT_interdomain)
        goto fail2;

    *RemoteDomain = op.u.interdomain.dom;
    *RemotePort = op.u.interdomain.port;

    return STATUS_SUCCESS;

fail2:
    LogError("fail2\n");

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
EventChannelAllocate(
    IN  ULONG           Domain,
    OUT PULONG          LocalPort
    )
{
    struct evtchn_alloc_unbound op;
    LONG_PTR                    rc;
    NTSTATUS                    status;

    op.dom = DOMID_SELF;
    op.remote_dom = (domid_t)Domain;

    rc = EventChannelOp(EVTCHNOP_alloc_unbound, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    *LocalPort = op.port;
    
    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
EventChannelClose(
    IN  ULONG           LocalPort
    )
{
    struct evtchn_close op;
    LONG_PTR            rc;
    NTSTATUS            status;

    op.port = LocalPort;

    rc = EventChannelOp(EVTCHNOP_close, &op);

    if (rc < 0) {
        ERRNO_TO_STATUS(-rc, status);
        goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    LogError("fail1 (%08x)\n", status);

    return status;
}
