
/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
 *
 * sre_monitor.h: client for SRE controller monitor
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

#ifndef __SRE_MONITOR_H__
#define __SRE_MONITOR_H__

#include "virobject.h"
#include "domain_conf.h"
#include "sre_evt_ctl_socket.h"
#include "sre_monitor_protocol.h"

typedef struct _virSREMonitor virSREMonitor;
typedef virSREMonitor *virSREMonitorPtr;

typedef struct _virSREMonitorCallbacks virSREMonitorCallbacks;
typedef virSREMonitorCallbacks *virSREMonitorCallbacksPtr;

typedef void (*virSREMonitorCallbackDestroy) (virSREMonitorPtr mon,
                                              virDomainObjPtr vm);
typedef void (*virSREMonitorCallbackEOFNotify) (virSREMonitorPtr mon,
                                                virDomainObjPtr vm);

typedef void (*virSREMonitorCallbackShutdownNotify) (virSREMonitorPtr mon,
                                                     virSREMonitorShutdownStatus
                                                     status,
                                                     virDomainObjPtr vm);

typedef void (*virSREMonitorCallbackStartNotify) (virSREMonitorPtr mon,
                                                  int domain_id,
                                                  virDomainObjPtr vm);

typedef void (*virSREMonitorCallbackPolicyNotify) (virSREMonitorPtr mon,
                                                   int domain_id,
                                                   char *message,
                                                   int message_len,
                                                   virDomainObjPtr vm);

struct _virSREMonitorCallbacks {
    virSREMonitorCallbackDestroy destroy;
    virSREMonitorCallbackEOFNotify eofNotify;
    virSREMonitorCallbackShutdownNotify shutdownNotify;
    virSREMonitorCallbackStartNotify startNotify;
    virSREMonitorCallbackPolicyNotify policyNotify;
};

virSREMonitorPtr virSREMonitorNew(virDomainObjPtr vm,
                                  const char *socketdir,
                                  virSREMonitorCallbacksPtr cb);

void virSREMonitorClose(virSREMonitorPtr mon);

void virSREMonitorLock(virSREMonitorPtr mon);
void virSREMonitorUnlock(virSREMonitorPtr mon);

#endif /* __SRE_MONITOR_H__ */
