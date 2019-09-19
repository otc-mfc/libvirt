
/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
 *
 * sre_monitor.c: client for SRE controller monitor
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "sre_monitor.h"
#include "sre_monitor_dispatch.h"

#include "viralloc.h"

#include "virerror.h"
#include "virlog.h"
#include "virthread.h"
#include "rpc/virnetclient.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_SRE

VIR_LOG_INIT("sre.sre_monitor");

struct _virSREMonitor {
    virObjectLockable parent;

    virDomainObjPtr vm;
    virSREMonitorCallbacks cb;

    virNetClientPtr client;
    virNetClientProgramPtr program;
};

static virClassPtr virSREMonitorClass;
static void virSREMonitorDispose(void *obj);

static int
virSREMonitorOnceInit(void)
{
    if (!VIR_CLASS_NEW(virSREMonitor, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virSREMonitor)

     static void
      
         virSREMonitorHandleEventShutdown(virNetClientProgramPtr prog,
                                          virNetClientPtr client,
                                          void *evdata, void *opaque);
     static void
      
         virSREMonitorHandleEventStart(virNetClientProgramPtr prog
                                       ATTRIBUTE_UNUSED,
                                       virNetClientPtr client
                                       ATTRIBUTE_UNUSED, void *evdata,
                                       void *opaque);

     static void
      
         virSREMonitorHandleEventPolicy(virNetClientProgramPtr prog,
                                        virNetClientPtr client,
                                        void *evdata, void *opaque);

     static virNetClientProgramEvent virSREMonitorEvents[] = {
         {VIR_SRE_MONITOR_PROC_SHUTDOWN_EVENT,
          virSREMonitorHandleEventShutdown,
          sizeof(virSREMonitorShutdownEventMsg),
          (xdrproc_t) xdr_virSREMonitorShutdownEventMsg}
         ,
         {VIR_SRE_MONITOR_PROC_START_EVENT,
          virSREMonitorHandleEventStart,
          sizeof(virSREMonitorStartEventMsg),
          (xdrproc_t) xdr_virSREMonitorStartEventMsg}
         ,
         {VIR_SRE_MONITOR_PROC_POLICY_EVENT,
          virSREMonitorHandleEventPolicy,
          sizeof(virSREMonitorPolicyEventMsg),
          (xdrproc_t) xdr_virSREMonitorPolicyEventMsg}
         ,
     };


static void
virSREMonitorHandleEventShutdown(virNetClientProgramPtr prog
                                 ATTRIBUTE_UNUSED,
                                 virNetClientPtr client ATTRIBUTE_UNUSED,
                                 void *evdata, void *opaque)
{
    virSREMonitorPtr mon = opaque;
    virSREMonitorCallbackShutdownNotify shutdownNotify;
    virDomainObjPtr vm;

    virSREMonitorShutdownEventMsg *msg = evdata;

    // VIR_DEBUG("Event exit %d", msg->status);
    // if (mon->cb.shutdownNotify)
    //     mon->cb.shutdownNotify(mon, msg->status, mon->vm);
    // virNetClientSetCloseCallback()


    VIR_DEBUG("Shutdown notify mon=%p", mon);
    virObjectLock(mon);
    shutdownNotify = mon->cb.shutdownNotify;
    vm = mon->vm;
    virObjectUnlock(mon);

    if (shutdownNotify) {
        VIR_DEBUG("Shutdown callback mon=%p vm=%p", mon, vm);
        shutdownNotify(mon, msg->status, vm);
    } else {
        VIR_DEBUG("Shutdown callback end");
    }
}


static void
virSREMonitorHandleEventStart(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                              virNetClientPtr client ATTRIBUTE_UNUSED,
                              void *evdata, void *opaque)
{
    virSREMonitorPtr mon = opaque;
    virSREMonitorStartEventMsg *msg = evdata;

    VIR_DEBUG("Event init %lld", (long long) msg->guest_id);
    if (mon->cb.startNotify)
        mon->cb.startNotify(mon, msg->guest_id, mon->vm);
}

static void
virSREMonitorHandleEventPolicy(virNetClientProgramPtr prog
                               ATTRIBUTE_UNUSED,
                               virNetClientPtr client ATTRIBUTE_UNUSED,
                               void *evdata, void *opaque)
{
    virSREMonitorPtr mon = opaque;
    virSREMonitorPolicyEventMsg *msg = evdata;

    VIR_DEBUG("Event init %lld", (long long) msg->guest_id);
    if (mon->cb.policyNotify)
        mon->cb.policyNotify(mon, msg->guest_id, msg->data, msg->data_len,
                             mon->vm);
}


static void
virSREMonitorEOFNotify(virNetClientPtr client ATTRIBUTE_UNUSED,
                       int reason ATTRIBUTE_UNUSED, void *opaque)
{
    virSREMonitorPtr mon = opaque;
    virSREMonitorCallbackEOFNotify eofNotify;
    virDomainObjPtr vm;

    VIR_DEBUG("EOF notify mon=%p", mon);
    virObjectLock(mon);
    eofNotify = mon->cb.eofNotify;
    vm = mon->vm;
    virObjectUnlock(mon);

    if (eofNotify) {
        VIR_DEBUG("EOF callback mon=%p vm=%p", mon, vm);
        eofNotify(mon, vm);
    } else {
        VIR_DEBUG("No EOF callback");
    }
}


static void
virSREMonitorCloseFreeCallback(void *opaque)
{
    virSREMonitorPtr mon = opaque;

    virObjectUnref(mon);
}


virSREMonitorPtr
virSREMonitorNew(virDomainObjPtr vm,
                 const char *socketdir, virSREMonitorCallbacksPtr cb)
{
    virSREMonitorPtr mon;
    char *sockpath = NULL;

    if (virSREMonitorInitialize() < 0)
        return NULL;

    if (!(mon = virObjectLockableNew(virSREMonitorClass)))
        return NULL;

    if (virAsprintf(&sockpath, "%s/%s.sock", socketdir, vm->def->name) < 0)
        goto error;

    if (!(mon->client = virNetClientNewUNIX(sockpath, false, NULL)))
        goto error;

    if (virNetClientRegisterAsyncIO(mon->client) < 0)
        goto error;

    if (!(mon->program = virNetClientProgramNew(VIR_SRE_MONITOR_PROGRAM,
                                                VIR_SRE_MONITOR_PROGRAM_VERSION,
                                                virSREMonitorEvents,
                                                ARRAY_CARDINALITY
                                                (virSREMonitorEvents),
                                                mon)))
        goto error;

    if (virNetClientAddProgram(mon->client, mon->program) < 0)
        goto error;

    mon->vm = virObjectRef(vm);
    memcpy(&mon->cb, cb, sizeof(mon->cb));

    virObjectRef(mon);
    virNetClientSetCloseCallback(mon->client, virSREMonitorEOFNotify, mon,
                                 virSREMonitorCloseFreeCallback);

  cleanup:
    VIR_FREE(sockpath);
    return mon;

  error:
    virObjectUnref(mon);
    mon = NULL;
    goto cleanup;
}


static void
virSREMonitorDispose(void *opaque)
{
    virSREMonitorPtr mon = opaque;

    VIR_DEBUG("mon=%p", mon);
    if (mon->cb.destroy)
        (mon->cb.destroy) (mon, mon->vm);
    virObjectUnref(mon->program);
    virObjectUnref(mon->vm);
}


void
virSREMonitorClose(virSREMonitorPtr mon)
{
    virDomainObjPtr vm;
    virNetClientPtr client;

    VIR_DEBUG("mon=%p", mon);
    if (mon->client) {
        /* When manually closing the monitor, we don't
         * want to have callbacks back into us, since
         * the caller is not re-entrant safe
         */
        VIR_DEBUG("Clear EOF callback mon=%p", mon);
        vm = mon->vm;
        client = mon->client;
        mon->client = NULL;
        mon->cb.eofNotify = NULL;

        virObjectRef(vm);
        virObjectUnlock(vm);

        virNetClientClose(client);
        virObjectUnref(client);

        virObjectUnref(vm);
    }
}
