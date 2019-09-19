
/*
 * sre_driver.h: A test-bed for the SRE driver
 *
 */

#ifndef __VIR_SRE_INTERNAL_H__
#define __VIR_SRE_INTERNAL_H__

#include "internal.h"
#include "virstring.h"
#include "virutil.h"
#include "virfile.h"
#include "vircgroup.h"
#include "virbuffer.h"
#include "virerror.h"
#include "datatypes.h"
#include "sre_driver.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "capabilities.h"
#include "configmake.h"
#include "viralloc.h"
#include "network_conf.h"
#include "interface_conf.h"
#include "virnetworkobj.h"
#include "domain_conf.h"
#include "driver.h"
#include "domain_event.h"
#include "network_event.h"
#include "snapshot_conf.h"
#include "storage_conf.h"
#include "storage_event.h"
#include "node_device_conf.h"
#include "virxml.h"
#include "virthread.h"
#include "virlog.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virrandom.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "virauth.h"
#include "viratomic.h"
#include "virdomainobjlist.h"
#include "access/viraccessapicheck.h"
#include "locking/lock_manager.h"
#include "virclosecallbacks.h"
#include "virhostdev.h"
#include "security/security_manager.h"
#include "virportallocator.h"
#include "virinterfaceobj.h"
#include "virstorageobj.h"
#include "virnodedeviceobj.h"
#include "sre_hostdev.h"
#include "sre_internal_types.h"

#define SRE_PROGRAM_SENTINEL ((char *)0x1)

typedef struct _virSREDriverConfig virSREDriverConfig;
typedef virSREDriverConfig *virSREDriverConfigPtr;


int sreRegister(void);

//TODO look up what this value is
#define NUM_CPU_FEATURES

#define MAX_VNIC 32
typedef struct _sreDomainNamespaceDef sreDomainNamespaceDef;
typedef sreDomainNamespaceDef *sreDomainNamespaceDefPtr;

typedef struct portal_policy_info_struct_t {
    char *unit;
    char *name;
    unsigned int size;
    int32_t portal_interface_id;
    int32_t portal_channel;
} portal_policy_info_t;

typedef struct vub_info_struct_t {
    int32_t vub_portval;
    int32_t vub_channel;
} vub_info_t;

//just store values in xml buffer because we are parsing in policy tool
struct _sreDomainNamespaceDef {
    virBuffer data;
    int portal_count;
    portal_policy_info_t portal_info[MAX_VNIC];
    vub_info_t vub_info[MAX_NUM_SERIAL_PORTS];
    int vub_count;
};


#define MAX_CPUS 512

struct _sreCell {
    unsigned long mem;
    int numCpus;
    virCapsHostNUMACellCPU cpus[MAX_CPUS];
};
typedef struct _sreCell sreCell;
typedef struct _sreCell *sreCellPtr;

#define MAX_CELLS 128

struct _sreAuth {
    char *username;
    char *password;
};
typedef struct _sreAuth sreAuth;
typedef struct _sreAuth *sreAuthPtr;

struct _sreDriver {
    virMutex lock;

    virNodeInfo nodeInfo;
    virInterfaceObjListPtr ifaces;
    bool transaction_running;
    virInterfaceObjListPtr backupIfaces;
    virStoragePoolObjListPtr pools;
    virNodeDeviceObjListPtr devs;
    virSRENetDeviceListPtr sre_net_device_list;
    int numCells;
    sreCell cells[MAX_CELLS];
    size_t numAuths;
    sreAuthPtr auths;

    char *sre_run_path;   /**< sre policy tool" **/

    /* Atomic inc/dec only */
    unsigned int nactive;

    /* Immutable pointers. Caller must provide locking */
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    /* virAtomic access only */
    volatile int nextDomID;

    /* immutable pointer, immutable object after being initialized with
     * sreBuildCapabilities */
    virCapsPtr caps;

    /* Immutable value */
    bool privileged;

    /* Immutable pointer. self-locking APIs */
    virSecurityManagerPtr securityManager;

    virHostdevManagerPtr hostdevMgr;

    /* Immutable pointer. Unsafe APIs. XXX */
    virHashTablePtr sharedDevices;
#if 0
    /* Immutable pointer, self-locking APIs */
    virPortAllocatorRangePtr remotePorts;

    /* Immutable pointer, self-locking APIs */
    virPortAllocatorRangePtr webSocketPorts;
#endif
    /* Immutable pointer. lockless access */
    virLockManagerPluginPtr lockManager;

    /* Immutable pointer, self-clocking APIs */
    virCloseCallbacksPtr closeCallbacks;


    virSREDriverConfigPtr config;
    virSysinfoDefPtr hostsysinfo;
    /* immutable pointer, immutable object */
    virDomainXMLOptionPtr xmlopt;

    /* immutable pointer, self-locking APIs */
    virDomainObjListPtr domains;
    virObjectEventStatePtr eventState;
    /* Atomic increment only */
    int lastvmid;

};
typedef struct _sreDriver sreDriver;
typedef sreDriver *sreDriverPtr;

//for moving other callbacks to files


//struct _sreDomainNamespaceDef {
//int cpu_feature_actions[12];
//int hypervisor_feature_actions[4];
//struct sre_pci_details * pcidev_list;
//int num_pcidevs;
//};
//
//VIR_ENUM_DECL(virSREPCIDetails)
//
//#define PCI_DETAILS_LEN 7
//struct sre_pci_details
//{
//  char vendor [PCI_DETAILS_LEN];
//  char device [PCI_DETAILS_LEN];
//  char class [PCI_DETAILS_LEN];
//  char function [PCI_DETAILS_LEN];
//  char instance [PCI_DETAILS_LEN];
//};
#define LM_NUM_PKG 2
#define LM_NUM_PACKAGES_PER_NODE 1
#define LM_NUM_CORES_PER_PKG 24
#define LM_MEM_INFO 384 *1024 *1024
#define LM_SE_CORES 1

#endif /* __VIR_SRE_INTERNAL_H__ */
