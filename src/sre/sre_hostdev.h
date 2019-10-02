/*
 * Copyright(c) 2019 Lockheed Martin Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and 
 * to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of 
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 */

/*
 * sre_conf.h: SRE configuration management
 *
 */

#ifndef __SRE_HOSTDEV_H
#define __SRE_HOSTDEV_H

#include <unistd.h>

#include "internal.h"
#include "capabilities.h"
#include "network_conf.h"
#include "domain_conf.h"
#include "snapshot_conf.h"
#include "domain_event.h"
#include "virthread.h"
#include "security/security_manager.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsi.h"
#include "cpu_conf.h"
#include "driver.h"
#include "virportallocator.h"
#include "vircommand.h"
#include "virthreadpool.h"
#include "locking/lock_manager.h"
#include "virclosecallbacks.h"
#include "virhostdev.h"
#include "virfile.h"
#include "virfirmware.h"
#include "interface_conf.h"
#include "virpci.h"


#define SRE_PCI_VENDID                 "0x003d"
#define RHEL_PCI_VENDID                "0x1af4"
#define SRE_PCI_NET_PORTAL_DEVID          "0x015f"
#define SRE_PCI_LEGACY_NET_PORTAL_DEVID   "0x0152"
#define RHEL_PCI_VIRTIO_NET_PORTAL_DEVID  "0x1000"


typedef enum {
    SRE_PORTAL_INIT = 0,
    SRE_PORTAL_NET,
    SRE_LEGACY_NET,
    SRE_VIRTIO_NET,
} sre_pcidev_nic_t;

#define PCI_INFO_LEN 7

typedef struct sre_host_netdev_struct_t {
    sre_pcidev_nic_t type;
    int channel;
    volatile int in_use_flag;
    char *netdev_name;
    char *transient_name;
    char *config_path;

} sre_host_netdev_t;

typedef sre_host_netdev_t *virSRENetDevicePtr;

typedef struct _virSRENetDeviceList virSRENetDeviceList;
typedef virSRENetDeviceList *virSRENetDeviceListPtr;

struct _virSRENetDeviceList {
    virObjectLockable parent;

    size_t count;
    virSRENetDevicePtr *devs;
};


virSRENetDeviceListPtr virSRENetDeviceListNew(void);
virSRENetDevicePtr virSRENetDeviceCopy(virSRENetDevicePtr dev);
virSRENetDevicePtr virSRENetDeviceListFind(virSRENetDeviceListPtr list,
                                           virSRENetDevicePtr dev);
int virSRENetDeviceListFindIndex(virSRENetDeviceListPtr list,
                                 virSRENetDevicePtr dev);
int virSRENetDeviceListAdd(virSRENetDeviceListPtr list,
                           virSRENetDevicePtr dev);
int virSRENetDeviceListAddCopy(virSRENetDeviceListPtr list,
                               virSRENetDevicePtr dev);
virSRENetDevicePtr virSRENetDeviceListGet(virSRENetDeviceListPtr list,
                                          int idx);
virSRENetDevicePtr virSRENetDeviceListFind(virSRENetDeviceListPtr list,
                                           virSRENetDevicePtr dev);
int virSRENetDeviceListFindIndex(virSRENetDeviceListPtr list,
                                 virSRENetDevicePtr dev);
int virSRENetDeviceListAdd(virSRENetDeviceListPtr list,
                           virSRENetDevicePtr dev);
virSRENetDeviceListPtr sreProbeNetDevices(void);
int virSRENetDeviceListAddCopy(virSRENetDeviceListPtr list,
                               virSRENetDevicePtr dev);
virSRENetDevicePtr virSRENetDeviceListGet(virSRENetDeviceListPtr list,
                                          int idx);
size_t virSRENetDeviceListCount(virSRENetDeviceListPtr list);
virSRENetDevicePtr virSRENetDeviceListStealIndex(virSRENetDeviceListPtr
                                                 list, int idx);
virSRENetDevicePtr virSRENetDeviceListSteal(virSRENetDeviceListPtr list,
                                            virSRENetDevicePtr dev);
void virSRENetDeviceListDel(virSRENetDeviceListPtr list,
                            virSRENetDevicePtr dev);
void virSRENetDeviceFree(sre_host_netdev_t * dev);


#endif /* __SRE_HOSTDEV_H */
