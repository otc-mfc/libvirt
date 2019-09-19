
/*
 * sre_conf.c: SRE configuration management
 *
 */

#include <config.h>

#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "virerror.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virconf.h"
#include "viralloc.h"
#include "datatypes.h"
#include "virxml.h"
#include "virlog.h"
#include "cpu/cpu.h"
#include "virfile.h"
#include "virstring.h"
#include "viratomic.h"
#include "storage_conf.h"
#include "sre_hostdev.h"
#include "virhostdev.h"
#include "virpci.h"
#include "virnetdev.h"


#define VIR_FROM_THIS VIR_FROM_SRE

VIR_LOG_INIT("sre.sre_hostdev");

static virClassPtr virSRENetDeviceListClass;
static void virSRENetDeviceListDispose(void *obj);

static int
virSRENetOnceInit(void)
{
    if (!
        (virSRENetDeviceListClass =
         virClassNew(virClassForObjectLockable(), "virSRENetDeviceList",
                     sizeof(virSRENetDeviceList),
                     virSRENetDeviceListDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virSRENet);
static void
virSRENetDeviceListDispose(void *obj)
{
    virSRENetDeviceListPtr list = obj;
    size_t i;

    for (i = 0; i < list->count; i++) {
        virSRENetDeviceFree(list->devs[i]);
        list->devs[i] = NULL;
    }

    list->count = 0;
    VIR_FREE(list->devs);
}


void
virSRENetDeviceFree(sre_host_netdev_t * dev)
{
    if (!dev)
        return;
    VIR_DEBUG("%s %s: freeing sre netdev", dev->config_path,
              dev->netdev_name);
    VIR_FREE(dev->config_path);
    VIR_FREE(dev->netdev_name);
    VIR_FREE(dev->transient_name);
    VIR_FREE(dev);
}

virSRENetDeviceListPtr
virSRENetDeviceListNew(void)
{
    virSRENetDeviceListPtr list;

    if (virSRENetInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virSRENetDeviceListClass)))
        return NULL;

    return list;
}

virSRENetDevicePtr
virSRENetDeviceCopy(virSRENetDevicePtr dev)
{
    virSRENetDevicePtr copy;

    if (VIR_ALLOC(copy) < 0)
        return NULL;

    /* shallow copy to take care of most attributes */
    *copy = *dev;
    copy->config_path = NULL;
    copy->netdev_name = NULL;
    if (VIR_STRDUP(copy->config_path, dev->config_path) < 0 ||
        VIR_STRDUP(copy->netdev_name, dev->netdev_name) < 0) {
        goto error;
    }
    return copy;

  error:
    virSRENetDeviceFree(copy);
    return NULL;
}


virSRENetDevicePtr
virSRENetDeviceListFind(virSRENetDeviceListPtr list,
                        virSRENetDevicePtr dev)
{
    int idx;

    if ((idx = virSRENetDeviceListFindIndex(list, dev)) >= 0)
        return list->devs[idx];
    else
        return NULL;
}


int
virSRENetDeviceListFindIndex(virSRENetDeviceListPtr list,
                             virSRENetDevicePtr dev)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        virSRENetDevicePtr other = list->devs[i];

        if (other->type == dev->type && other->channel == dev->channel)
            return i;
    }
    return -1;
}

int
virSRENetDeviceListAdd(virSRENetDeviceListPtr list, virSRENetDevicePtr dev)
{
    if (virSRENetDeviceListFind(list, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %s is already in list"),
                       dev->netdev_name);
        return -1;
    }
    return VIR_APPEND_ELEMENT(list->devs, list->count, dev);
}

/* virSRENetDeviceListAddCopy - add a *copy* of the device to this list */
int
virSRENetDeviceListAddCopy(virSRENetDeviceListPtr list,
                           virSRENetDevicePtr dev)
{
    virSRENetDevicePtr copy = virSRENetDeviceCopy(dev);

    if (!copy)
        return -1;
    if (virSRENetDeviceListAdd(list, copy) < 0) {
        virSRENetDeviceFree(copy);
        return -1;
    }
    return 0;
}


virSRENetDevicePtr
virSRENetDeviceListGet(virSRENetDeviceListPtr list, int idx)
{
    if (idx >= list->count)
        return NULL;
    if (idx < 0)
        return NULL;

    return list->devs[idx];
}

size_t
virSRENetDeviceListCount(virSRENetDeviceListPtr list)
{
    if (list) {
        return list->count;
    } else {
        VIR_ERROR("List is null!!");
        return 0;
    }
}

virSRENetDevicePtr
virSRENetDeviceListStealIndex(virSRENetDeviceListPtr list, int idx)
{
    virSRENetDevicePtr ret;

    if (idx < 0 || idx >= list->count)
        return NULL;

    ret = list->devs[idx];
    VIR_DELETE_ELEMENT(list->devs, idx, list->count);
    return ret;
}

virSRENetDevicePtr
virSRENetDeviceListSteal(virSRENetDeviceListPtr list,
                         virSRENetDevicePtr dev)
{
    return virSRENetDeviceListStealIndex(list,
                                         virSRENetDeviceListFindIndex(list,
                                                                      dev));
}

void
virSRENetDeviceListDel(virSRENetDeviceListPtr list, virSRENetDevicePtr dev)
{
    virSRENetDevicePtr ret = virSRENetDeviceListSteal(list, dev);

    virSRENetDeviceFree(ret);
}

sre_host_netdev_t *sreNetDevReserve(char *cfg_vendor, char *cfg_device,
                                    char *cfg_svendor,
                                    const char *config_path,
                                    char *netdev_name);



sre_host_netdev_t *
sreNetDevReserve(char *cfg_vendor, char *cfg_device, char *cfg_svendor,
                 const char *config_path, char *netdev_name)
{
    sre_host_netdev_t *new_device;

    if (VIR_ALLOC(new_device)) {
        VIR_ERROR("sre dev alloc failed");
    }

    int found = 0;
    char *sre_managed_name = NULL;

    //TODO make some way to have hostdevMgr show these devices in use (either by some fake sre net driver initially then by the current guest).
    if (strncmp(cfg_vendor, SRE_PCI_VENDID, PCI_INFO_LEN) == 0) {
        if (strncmp(cfg_device, SRE_PCI_NET_PORTAL_DEVID, PCI_INFO_LEN) ==
            0) {
            new_device->type = SRE_PORTAL_NET;
            ignore_value(VIR_STRDUP(sre_managed_name, "srePtl"));
            found = 1;
        } else
            if (strncmp
                (cfg_device, SRE_PCI_LEGACY_NET_PORTAL_DEVID,
                 PCI_INFO_LEN) == 0) {
            new_device->type = SRE_LEGACY_NET;
            ignore_value(VIR_STRDUP(sre_managed_name, "sreLegacyPtl"));
            found = 1;
        }
    } else if (strncmp(cfg_vendor, RHEL_PCI_VENDID, PCI_INFO_LEN) == 0) {
        if (strncmp
            (cfg_device, RHEL_PCI_VIRTIO_NET_PORTAL_DEVID,
             PCI_INFO_LEN) == 0) {
            new_device->type = SRE_VIRTIO_NET;
            ignore_value(VIR_STRDUP(sre_managed_name, "sreVirtioPtl"));
            found = 1;
        }
    }
    if (found) {
        char *new_netdev_name = NULL;

        ignore_value(VIR_STRDUP(new_device->config_path, config_path));
        /* subsystem vendor id indicates portal channel */
        if (virStrToLong_i(cfg_svendor, NULL, 16, &new_device->channel) <
            0) {
            VIR_WARN("invalid portal channel");
            VIR_FREE(new_device);
            return NULL;
        }
        ignore_value(virAsprintf
                     (&new_netdev_name, "%s%d", sre_managed_name,
                      new_device->channel));
        VIR_FREE(sre_managed_name);

        bool online = false;

        if (virNetDevGetOnline(netdev_name, &online)) {
            VIR_ERROR("Error getting nic status");
            VIR_FREE(new_netdev_name);
            VIR_FREE(new_device);
            return NULL;
        }
        if (online) {
            if (virNetDevSetOnline(netdev_name, false)) {
                VIR_ERROR("Error setting nic status");
                VIR_FREE(new_netdev_name);
                VIR_FREE(new_device);
                return NULL;
            }
        }

        if (virNetDevSetName(netdev_name, new_netdev_name)) {
            VIR_FREE(new_netdev_name);
            VIR_ERROR("ERROR renaming net device");
        }

        ignore_value(VIR_STRDUP(new_device->netdev_name, new_netdev_name));
        VIR_FREE(new_netdev_name);
        return new_device;
    } else {
        VIR_FREE(new_device);
        return NULL;
    }
}

virSRENetDeviceListPtr
sreProbeNetDevices(void)
{
    virPCIDeviceListPtr list = virPCIDeviceCreateListScanHostPCI();
    virSRENetDeviceListPtr sre_device_list = virSRENetDeviceListNew();
    int i = 0;
    int dev_count = virPCIDeviceListCount(list);

    for (i = 0; i < dev_count; i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(list, i);

        //config_path (dev->path) is the dir of the pci config space file, use files for values needed for host probe because they exist
        //TODO move these attributes to internal dev so they are populated and similar accessors before upstreaming, leave in the driver for now.
        const char *cfg_path = virPCIDeviceGetConfigPath(dev);
        char *cfg_vendor_path = NULL;
        char *cfg_device_path = NULL;
        char *cfg_svendor_path = NULL;

        cfg_vendor_path = virStringReplace(cfg_path, "config", "vendor");
        cfg_device_path = virStringReplace(cfg_path, "config", "device");
        cfg_svendor_path =
            virStringReplace(cfg_path, "config", "subsystem_vendor");

        //0xXXXX + \0
        //We only need the vendor device to find host portals
        //and  subsys vendor for channel
        char cfg_vendor[PCI_INFO_LEN];
        char cfg_device[PCI_INFO_LEN];
        char cfg_svendor[PCI_INFO_LEN];

        if (virFileReadBufQuiet(cfg_vendor_path, cfg_vendor, PCI_INFO_LEN)
            > 0
            && virFileReadBufQuiet(cfg_device_path, cfg_device,
                                   PCI_INFO_LEN) > 0
            && virFileReadBufQuiet(cfg_svendor_path, cfg_svendor,
                                   PCI_INFO_LEN) > 0) {

            char *dev_fs_file = NULL;
            char *dev_fs_file_append = NULL;
            char *net_name = NULL;
            char *temp_name = NULL;
            const char *name = virPCIDeviceGetName(dev);

            ignore_value(VIR_STRDUP(temp_name, name));
            if (virPCIGetSysfsFile(temp_name, &dev_fs_file)) {
                VIR_ERROR("ERROR opening device sysfs file");
                VIR_FREE(temp_name);
            } else {
                VIR_FREE(temp_name);
                if (strncmp(cfg_vendor, RHEL_PCI_VENDID, PCI_INFO_LEN) ==
                    0) {
                    if (strncmp
                        (cfg_device, RHEL_PCI_VIRTIO_NET_PORTAL_DEVID,
                         PCI_INFO_LEN) == 0) {
                        int vidx = 0;

                        for (vidx = 0; vidx < 512; vidx++) {
                            ignore_value(virAsprintf
                                         (&dev_fs_file_append, "%s/%s%d",
                                          dev_fs_file, "virtio", vidx));
                            if (virFileExists(dev_fs_file_append)) {
                                break;
                            } else {
                                VIR_FREE(dev_fs_file_append);
                            }
                        }
                    } else {
                        dev_fs_file_append = dev_fs_file;
                    }
                } else {
                    dev_fs_file_append = dev_fs_file;
                }

                if (virPCIGetNetName
                    (dev_fs_file_append, 0, NULL, &net_name)) {
                    VIR_ERROR("ERROR getting net device name");
                } else if (net_name != NULL) {
                    VIR_DEBUG
                        ("found netdev %s file %s, vend:dev%s:%s path %s",
                         net_name, dev_fs_file_append, cfg_vendor,
                         cfg_device, cfg_path);
                    sre_host_netdev_t *temp_dev = NULL;

                    if ((temp_dev =
                         sreNetDevReserve(cfg_vendor, cfg_device,
                                          cfg_svendor, cfg_path,
                                          net_name))) {
                        VIR_DEBUG("found SRE %d", temp_dev->channel);
                        virSRENetDeviceListAdd(sre_device_list, temp_dev);
                    }
                    VIR_FREE(net_name);
                } else {
                    VIR_DEBUG
                        ("found netdev %s file %s, vend:dev%s:%s path %s",
                         net_name, dev_fs_file, cfg_vendor, cfg_device,
                         cfg_path);
                }
                VIR_FREE(dev_fs_file);
                if (strncmp(cfg_vendor, RHEL_PCI_VENDID, PCI_INFO_LEN) ==
                    0) {
                    if (strncmp
                        (cfg_device, RHEL_PCI_VIRTIO_NET_PORTAL_DEVID,
                         PCI_INFO_LEN) == 0) {
                        VIR_FREE(dev_fs_file_append);
                    }
                }
            }
        }
        VIR_FREE(cfg_vendor_path);
        VIR_FREE(cfg_device_path);
        VIR_FREE(cfg_svendor_path);
    }
    if (list) {

        while (virPCIDeviceListCount(list) > 0) {
            virPCIDeviceListDel(list, virPCIDeviceListGet(list, 0));

        }
        VIR_FREE(list);
    }
    return sre_device_list;
}
