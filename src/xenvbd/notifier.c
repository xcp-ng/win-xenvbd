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

#include "notifier.h"
#include "frontend.h"
#include "target.h"
#include "adapter.h"
#include "util.h"
#include "debug.h"
#include <evtchn_interface.h>

struct _XENVBD_NOTIFIER {
    PXENVBD_FRONTEND                Frontend;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;

    XENBUS_STORE_INTERFACE          StoreInterface;
    XENBUS_EVTCHN_INTERFACE         EvtchnInterface;

    PXENBUS_EVTCHN_CHANNEL          Channel;
    ULONG                           Port;
    ULONG                           NumInts;
    ULONG                           NumDpcs;
    KDPC                            Dpc;
    KDPC                            TimerDpc;
    KTIMER                          Timer;
};

#define NOTIFIER_POOL_TAG           'yfNX'

static FORCEINLINE PVOID
__NotifierAllocate(
    IN  ULONG                       Length
    )
{
    return __AllocatePoolWithTag(NonPagedPool, Length, NOTIFIER_POOL_TAG);
}

static FORCEINLINE VOID
__NotifierFree(
    IN  PVOID                       Buffer
    )
{
    if (Buffer)
        __FreePoolWithTag(Buffer, NOTIFIER_POOL_TAG);
}

KSERVICE_ROUTINE NotifierInterrupt;

BOOLEAN
NotifierInterrupt(
    __in  PKINTERRUPT               Interrupt,
    _In_opt_ PVOID                  Context
    )
{
    PXENVBD_NOTIFIER    Notifier = Context;
    
    UNREFERENCED_PARAMETER(Interrupt);

    ASSERT(Notifier != NULL);

	++Notifier->NumInts;
	if (Notifier->Connected) {
		if (KeInsertQueueDpc(&Notifier->Dpc, NULL, NULL)) {
			++Notifier->NumDpcs;
        }
	}

    return TRUE;
}

static FORCEINLINE BOOLEAN
__NotifierDpcTimeout(
    IN  PXENVBD_NOTIFIER        Notifier
    )
{
    KDPC_WATCHDOG_INFORMATION   Watchdog;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Notifier);

    RtlZeroMemory(&Watchdog, sizeof (Watchdog));

    status = KeQueryDpcWatchdogInformation(&Watchdog);
    ASSERT(NT_SUCCESS(status));

    if (Watchdog.DpcTimeLimit == 0 ||
        Watchdog.DpcWatchdogLimit == 0)
        return FALSE;

    if (Watchdog.DpcTimeCount > (Watchdog.DpcTimeLimit / 2) &&
        Watchdog.DpcWatchdogCount > (Watchdog.DpcWatchdogLimit / 2))
        return FALSE;

    return TRUE;
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

KDEFERRED_ROUTINE NotifierDpc;

VOID 
NotifierDpc(
    __in  PKDPC                     Dpc,
    __in_opt PVOID                  Context,
    __in_opt PVOID                  Arg1,
    __in_opt PVOID                  Arg2
    )
{
    PXENVBD_NOTIFIER    Notifier = Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ASSERT(Notifier != NULL);

    if (!Notifier->Connected)
        return;

    for (;;) {
        if (!FrontendNotifyResponses(Notifier->Frontend)) {
            XENBUS_EVTCHN(Unmask,
                          &Notifier->EvtchnInterface,
                          Notifier->Channel,
                          FALSE);
            break;
        }
        if (__NotifierDpcTimeout(Notifier)) {
            LARGE_INTEGER   Delay;

            Delay.QuadPart = TIME_RELATIVE(TIME_US(100));

            KeSetTimer(&Notifier->Timer,
                       Delay,
                       &Notifier->TimerDpc);
            break;
        }
    }
}

NTSTATUS
NotifierCreate(
    IN  PXENVBD_FRONTEND            Frontend,
    OUT PXENVBD_NOTIFIER*           Notifier
    )
{
    *Notifier = __NotifierAllocate(sizeof(XENVBD_NOTIFIER));
    if (*Notifier == NULL)
        goto fail1;

    (*Notifier)->Frontend = Frontend;
    KeInitializeDpc(&(*Notifier)->Dpc, NotifierDpc, *Notifier);
    KeInitializeDpc(&(*Notifier)->TimerDpc, NotifierDpc, *Notifier);
    KeInitializeTimer(&(*Notifier)->Timer);

    return STATUS_SUCCESS;

fail1:
    return STATUS_NO_MEMORY;
}

VOID
NotifierDestroy(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    Notifier->Frontend = NULL;
    RtlZeroMemory(&Notifier->Dpc, sizeof(KDPC));
    RtlZeroMemory(&Notifier->TimerDpc, sizeof(KDPC));
    RtlZeroMemory(&Notifier->Timer, sizeof(KTIMER));

    ASSERT(IsZeroMemory(Notifier, sizeof(XENVBD_NOTIFIER)));
    
    __NotifierFree(Notifier);
}

NTSTATUS
NotifierConnect(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  USHORT                      BackendDomain
    )
{
    PXENVBD_ADAPTER Adapter = TargetGetAdapter(FrontendGetTarget(Notifier->Frontend));
    NTSTATUS    status;

    ASSERT(Notifier->Connected == FALSE);

    AdapterGetStoreInterface(Adapter, &Notifier->StoreInterface);
    AdapterGetEvtchnInterface(Adapter, &Notifier->EvtchnInterface);

    status = XENBUS_STORE(Acquire, &Notifier->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_EVTCHN(Acquire, &Notifier->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    Notifier->Channel = XENBUS_EVTCHN(Open, 
                                      &Notifier->EvtchnInterface,
                                      XENBUS_EVTCHN_TYPE_UNBOUND, 
                                      NotifierInterrupt,
                                      Notifier, 
                                      BackendDomain, 
                                      TRUE);

    status = STATUS_NO_MEMORY;
    if (Notifier->Channel == NULL)
        goto fail3;

    Notifier->Port = XENBUS_EVTCHN(GetPort,
                                   &Notifier->EvtchnInterface,
                                   Notifier->Channel);

    XENBUS_EVTCHN(Unmask,
                  &Notifier->EvtchnInterface,
                  Notifier->Channel,
                  FALSE);

    Notifier->Connected = TRUE;
    return STATUS_SUCCESS;

fail3:
    XENBUS_EVTCHN(Release, &Notifier->EvtchnInterface);
    RtlZeroMemory(&Notifier->EvtchnInterface, sizeof(XENBUS_EVTCHN_INTERFACE));

fail2:
    XENBUS_STORE(Release, &Notifier->StoreInterface);
    RtlZeroMemory(&Notifier->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));

fail1:
    return status;
}

NTSTATUS
NotifierStoreWrite(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  PXENBUS_STORE_TRANSACTION   Transaction,
    IN  PCHAR                       FrontendPath
    )
{
    return XENBUS_STORE(Printf, 
                        &Notifier->StoreInterface,
                        Transaction, 
                        FrontendPath, 
                        "event-channel", 
                        "%u", 
                        Notifier->Port);
}

VOID
NotifierEnable(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    ASSERT(Notifier->Enabled == FALSE);

    XENBUS_EVTCHN(Trigger,
                  &Notifier->EvtchnInterface,
                  Notifier->Channel);

    Notifier->Enabled = TRUE;
}

VOID
NotifierDisable(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    ASSERT(Notifier->Enabled == TRUE);

    Notifier->Enabled = FALSE;

    //
    // No new timers can be scheduled once Enabled goes to FALSE.
    // Cancel any existing ones.
    //
    (VOID) KeCancelTimer(&Notifier->Timer);
}

VOID
NotifierDisconnect(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    ASSERT(Notifier->Connected == TRUE);

    XENBUS_EVTCHN(Close,
                  &Notifier->EvtchnInterface,
                  Notifier->Channel);
    Notifier->Channel = NULL;
    Notifier->Port = 0;

    XENBUS_EVTCHN(Release, &Notifier->EvtchnInterface);
    RtlZeroMemory(&Notifier->EvtchnInterface, sizeof(XENBUS_EVTCHN_INTERFACE));

    XENBUS_STORE(Release, &Notifier->StoreInterface);
    RtlZeroMemory(&Notifier->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));

    Notifier->NumInts = Notifier->NumDpcs = 0;

    Notifier->Connected = FALSE;
}

VOID
NotifierDebugCallback(
    IN  PXENVBD_NOTIFIER            Notifier,
    IN  PXENBUS_DEBUG_INTERFACE     Debug
    )
{
    XENBUS_DEBUG(Printf, Debug,
                 "NOTIFIER: Int / DPC : %d / %d\n",
                 Notifier->NumInts, Notifier->NumDpcs);

    if (Notifier->Channel) {
        XENBUS_DEBUG(Printf, Debug,
                     "NOTIFIER: Channel : %p (%d)\n", 
                     Notifier->Channel, Notifier->Port);
    }

    Notifier->NumInts = 0;
    Notifier->NumDpcs = 0;
}

VOID
NotifierKick(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    if (Notifier->Enabled) {
		if (KeInsertQueueDpc(&Notifier->Dpc, NULL, NULL)) {
			++Notifier->NumDpcs;
        }
    }
}

VOID
NotifierTrigger(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    if (Notifier->Enabled)
        XENBUS_EVTCHN(Trigger,
                      &Notifier->EvtchnInterface,
                      Notifier->Channel);
}

VOID
NotifierSend(
    IN  PXENVBD_NOTIFIER            Notifier
    )
{
    if (Notifier->Enabled)
        XENBUS_EVTCHN(Send,
                      &Notifier->EvtchnInterface,
                      Notifier->Channel);
}

