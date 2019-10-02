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

#ifndef __SRE_CONF_H
#define __SRE_CONF_H

#include <unistd.h>

#include "virebtables.h"
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
#include "sre_driver.h"
#include "virpci.h"

#define SRE_DRIVER_NAME "SRE"

#ifdef CPU_SETSIZE              /* Linux */
#define SRED_CPUMASK_LEN CPU_SETSIZE
#elif defined(_SC_NPROCESSORS_CONF)     /* Cygwin */
#define SRED_CPUMASK_LEN (sysconf(_SC_NPROCESSORS_CONF))
#else
#error "Port me"
#endif
#define SRE_CONFIG_DIR SYSCONFDIR "/libvirt/sre"
#define SRE_STATE_DIR LOCALSTATEDIR "/run/libvirt/sre"
#define SRE_LOG_DIR LOCALSTATEDIR "/log/libvirt/sre"
#define SRE_AUTOSTART_DIR SRE_CONFIG_DIR "/autostart"
#define SRE_NAMESPACE_HREF "http://libvirt.org/schemas/domain/sre/1.0"

#define SRE_UART_BRIDGE_PATH "/proc/driver/lm_uart_bridge/instr"
#define SRE_EVENT_MON_PATH "/var/run/sre_event_monitor_control.soc"

/* QEMU user account */
#define SRE_USER "root"

/* QEMU group account */
#define SRE_GROUP "root"

/* Main driver config. The data in these object
 * instances is immutable, so can be accessed
 * without locking. Threads must, however, hold
 * a valid reference on the object to prevent it
 * being released while they use it.
 *
 * eg
 *  sreDriverLock(driver);
 *  virSREDriverConfigPtr cfg = virObjectRef(driver->config);
 *  sreDriverUnlock(driver);
 *
 *  ...do stuff with 'cfg'..
 *
 *  virObjectUnref(cfg);
 */

struct _virSREDriverConfig {
    virObject parent;

    const char *uri;

    uid_t user;
    gid_t group;
    bool dynamicOwnership;

    int cgroupControllers;
    char **cgroupDeviceACL;

    /* These five directories are ones libvirtd uses (so must be root:root
     * to avoid security risk from SRE processes */
    char *configBaseDir;
    char *configDir;
    char *autostartDir;
    bool log_libvirtd;

    char *logDir;
    char *stateDir;

    /* Immutable pointer, lockless APIs. Pointless abstraction */
    ebtablesContext *ebtables;

    /* These two directories are ones SRE processes use (so must match
     * the SRE user/group */
    char *libDir;
    char *cacheDir;
    char *saveDir;
    char *snapshotDir;
    char *channelTargetDir;
    char *nvramDir;
    char *memoryBackingDir;

    uint remotePortMin;
    uint remotePortMax;

    uint webSocketPortMin;
    uint webSocketPortMax;

    unsigned long long maxCore;
    bool dumpGuestCore;
    char *bridgeHelperName;
    unsigned int maxQueuedJobs;

    bool macFilter;

    bool relaxedACS;
    bool vncAllowHostAudio;
    bool nogfxAllowHostAudio;
    bool clearEmulatorCapabilities;
    bool allowDiskFormatProbing;
    bool setProcessName;

    int maxProcesses;
    int maxFiles;

    char **securityDriverNames;
    bool securityDefaultConfined;
    bool securityRequireConfined;

    char *saveImageFormat;
    char *dumpImageFormat;
    char *snapshotImageFormat;

    char *autoDumpPath;
    bool autoDumpBypassCache;
    bool autoStartBypassCache;
    char *defaultTLSx509certdir;
    char *lockManagerName;

    int keepAliveInterval;
    unsigned int keepAliveCount;

    int seccompSandbox;

    bool logTimestamp;
    bool stdioLogD;

    virFirmwarePtr *firmwares;
    size_t nfirmwares;
};


typedef struct _sreDomainCmdlineDef sreDomainCmdlineDef;
typedef sreDomainCmdlineDef *sreDomainCmdlineDefPtr;
struct _sreDomainCmdlineDef {
    size_t num_args;
    char **args;

    unsigned int num_env;
    char **env_name;
    char **env_value;
};

virDomainXMLOptionPtr sreDomainXMLConfInit(void);

virCapsPtr virSRECapsInit(void);

void sreDomainCmdlineDefFree(sreDomainCmdlineDefPtr def);

virSREDriverConfigPtr virSREDriverConfigNew(bool privileged);

int virSREDriverConfigLoadFile(virSREDriverConfigPtr cfg,
                               const char *filename);

virSREDriverConfigPtr virSREDriverGetConfig(sreDriverPtr driver);
bool virSREDriverIsPrivileged(sreDriverPtr driver);

virCapsPtr virSREDriverCreateCapabilities(sreDriverPtr driver);
virCapsPtr virSREDriverGetCapabilities(sreDriverPtr driver, bool refresh);

typedef struct _sreSharedDeviceEntry sreSharedDeviceEntry;
typedef sreSharedDeviceEntry *sreSharedDeviceEntryPtr;

bool
sreSharedDeviceEntryDomainExists(sreSharedDeviceEntryPtr entry,
                                 const char *name, int *idx)
ATTRIBUTE_NONNULL(1)
ATTRIBUTE_NONNULL(2);

     char *sreGetSharedDeviceKey(const char *disk_path)
  ATTRIBUTE_NONNULL(1);

     void sreSharedDeviceEntryFree(void *payload, const void *name);

     int sreAddSharedDevice(sreDriverPtr driver,
                            virDomainDeviceDefPtr dev, const char *name)
  ATTRIBUTE_NONNULL(1)
ATTRIBUTE_NONNULL(2)
ATTRIBUTE_NONNULL(3);

     int sreRemoveSharedDevice(sreDriverPtr driver,
                               virDomainDeviceDefPtr dev, const char *name)
  ATTRIBUTE_NONNULL(1)
ATTRIBUTE_NONNULL(2)
ATTRIBUTE_NONNULL(3);

     int sreRemoveSharedDisk(sreDriverPtr driver,
                             virDomainDiskDefPtr disk, const char *name)
  ATTRIBUTE_NONNULL(1)
ATTRIBUTE_NONNULL(2)
ATTRIBUTE_NONNULL(3);

     int sreSetUnprivSGIO(virDomainDeviceDefPtr dev);

     int sreDriverAllocateID(sreDriverPtr driver);
     virDomainXMLOptionPtr virSREDriverCreateXMLConf(sreDriverPtr driver);

     int sreTranslateSnapshotDiskSourcePool(virConnectPtr conn,
                                            virDomainSnapshotDiskDefPtr
                                            def);

#endif /* __SRE_CONF_H */
