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
#include "configmake.h"
#include "sre_conf.h"
#include "virhostdev.h"
#include "virpci.h"
#include "virnetdev.h"
#include "sre_domain.h"
#include <libxml/xpathInternals.h>

#define VIR_FROM_THIS VIR_FROM_SRE

VIR_LOG_INIT("sre.sre_conf");

/* These are only defaults, they can be changed now in sre.conf and
 * explicitly specified port is checked against these two (makes
 * sense to limit the values).
 *
 * This limitation is mentioned in sre.conf, so bear in mind that the
 * configuration file should reflect any changes made to these values.
 */
#define SRE_REMOTE_PORT_MIN 5900
#define SRE_REMOTE_PORT_MAX 65535

#define SRE_WEBSOCKET_PORT_MIN 5700
#define SRE_WEBSOCKET_PORT_MAX 65535


static virClassPtr virSREDriverConfigClass;
static void virSREDriverConfigDispose(void *obj);
static int


sreAddSharedHostdev(sreDriverPtr driver,
                    virDomainHostdevDefPtr hostdev, const char *name);

static int
virSREConfigOnceInit(void)
{
    virSREDriverConfigClass = virClassNew(virClassForObject(),
                                          "virSREDriverConfig",
                                          sizeof(virSREDriverConfig),
                                          virSREDriverConfigDispose);

    if (!virSREDriverConfigClass)
        return -1;
    else
        return 0;
}

VIR_ONCE_GLOBAL_INIT(virSREConfig)


     static void
       sreDriverLock(sreDriverPtr driver)
{
    virMutexLock(&driver->lock);
}

static void
sreDriverUnlock(sreDriverPtr driver)
{
    virMutexUnlock(&driver->lock);
}

void
sreDomainCmdlineDefFree(sreDomainCmdlineDefPtr def)
{
    size_t i;

    if (!def)
        return;

    for (i = 0; i < def->num_args; i++)
        VIR_FREE(def->args[i]);
    for (i = 0; i < def->num_env; i++) {
        VIR_FREE(def->env_name[i]);
        VIR_FREE(def->env_value[i]);
    }
    VIR_FREE(def->args);
    VIR_FREE(def->env_name);
    VIR_FREE(def->env_value);
    VIR_FREE(def);
}

#define VIR_SRE_OVMF_LOADER_PATH "/usr/share/OVMF/OVMF_CODE.fd"
#define VIR_SRE_OVMF_NVRAM_PATH "/usr/share/OVMF/OVMF_VARS.fd"
#define VIR_SRE_OVMF_SEC_LOADER_PATH "/usr/share/OVMF/OVMF_CODE.secboot.fd"
#define VIR_SRE_OVMF_SEC_NVRAM_PATH "/usr/share/OVMF/OVMF_VARS.fd"
#define VIR_SRE_AAVMF_LOADER_PATH "/usr/share/AAVMF/AAVMF_CODE.fd"
#define VIR_SRE_AAVMF_NVRAM_PATH "/usr/share/AAVMF/AAVMF_VARS.fd"

virSREDriverConfigPtr
virSREDriverConfigNew(bool privileged)
{
    virSREDriverConfigPtr cfg;

    if (virSREConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virSREDriverConfigClass)))
        return NULL;

    cfg->uri = privileged ? "sre:///system" : "sre:///session";

    if (privileged) {
        if (virGetUserID(SRE_USER, &cfg->user) < 0)
            goto error;
        if (virGetGroupID(SRE_GROUP, &cfg->group) < 0)
            goto error;
    } else {
        cfg->user = (uid_t) - 1;
        cfg->group = (gid_t) - 1;
    }
    cfg->dynamicOwnership = privileged;

    cfg->cgroupControllers = -1;        /* -1 == auto-detect */

    if (privileged) {
        if (virAsprintf(&cfg->logDir,
                        "%s/log/libvirt/sre", LOCALSTATEDIR) < 0)
            goto error;

        if (VIR_STRDUP(cfg->configBaseDir, SYSCONFDIR "/libvirt") < 0)
            goto error;

        if (virAsprintf(&cfg->stateDir,
                        "%s/run/libvirt/sre", LOCALSTATEDIR) < 0)
            goto error;

        if (virAsprintf(&cfg->cacheDir,
                        "%s/cache/libvirt/sre", LOCALSTATEDIR) < 0)
            goto error;

        if (virAsprintf(&cfg->libDir,
                        "%s/lib/libvirt/sre", LOCALSTATEDIR) < 0)
            goto error;
        if (virAsprintf(&cfg->saveDir, "%s/save", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->snapshotDir, "%s/snapshot", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->autoDumpPath, "%s/dump", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->channelTargetDir,
                        "%s/channel/target", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->nvramDir, "%s/nvram", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->memoryBackingDir, "%s/ram", cfg->libDir) < 0)
            goto error;
    } else {
        char *rundir;
        char *cachedir;

        cachedir = virGetUserCacheDirectory();
        if (!cachedir)
            goto error;

        if (virAsprintf(&cfg->logDir, "%s/sre/log", cachedir) < 0) {
            VIR_FREE(cachedir);
            goto error;
        }
        if (virAsprintf(&cfg->cacheDir, "%s/sre/cache", cachedir) < 0) {
            VIR_FREE(cachedir);
            goto error;
        }
        VIR_FREE(cachedir);

        rundir = virGetUserRuntimeDirectory();
        if (!rundir)
            goto error;
        if (virAsprintf(&cfg->stateDir, "%s/sre/run", rundir) < 0) {
            VIR_FREE(rundir);
            goto error;
        }
        VIR_FREE(rundir);

        if (!(cfg->configBaseDir = virGetUserConfigDirectory()))
            goto error;

        if (virAsprintf(&cfg->libDir, "%s/sre/lib", cfg->configBaseDir) <
            0)
            goto error;
        if (virAsprintf(&cfg->saveDir, "%s/sre/save", cfg->configBaseDir) <
            0)
            goto error;
        if (virAsprintf
            (&cfg->snapshotDir, "%s/sre/snapshot", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf
            (&cfg->autoDumpPath, "%s/sre/dump", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf(&cfg->channelTargetDir,
                        "%s/sre/channel/target", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf(&cfg->nvramDir,
                        "%s/sre/nvram", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf
            (&cfg->memoryBackingDir, "%s/sre/ram", cfg->configBaseDir) < 0)
            goto error;
    }

    if (virAsprintf(&cfg->configDir, "%s/sre", cfg->configBaseDir) < 0)
        goto error;
    if (virAsprintf
        (&cfg->autostartDir, "%s/sre/autostart", cfg->configBaseDir) < 0)
        goto error;



    cfg->clearEmulatorCapabilities = true;

    cfg->securityDefaultConfined = true;
    cfg->securityRequireConfined = false;

    cfg->keepAliveInterval = 5;
    cfg->keepAliveCount = 5;
    cfg->seccompSandbox = -1;

    cfg->logTimestamp = true;
    cfg->stdioLogD = true;



#ifdef DEFAULT_LOADER_NVRAM
    if (virFirmwareParseList(DEFAULT_LOADER_NVRAM,
                             &cfg->firmwares, &cfg->nfirmwares) < 0)
        goto error;

#else
    if (VIR_ALLOC_N(cfg->firmwares, 3) < 0)
        goto error;
    cfg->nfirmwares = 3;
    if (VIR_ALLOC(cfg->firmwares[0]) < 0
        || VIR_ALLOC(cfg->firmwares[1]) < 0
        || VIR_ALLOC(cfg->firmwares[2]) < 0)
        goto error;

    if (VIR_STRDUP(cfg->firmwares[0]->name, VIR_SRE_AAVMF_LOADER_PATH) < 0
        || VIR_STRDUP(cfg->firmwares[0]->nvram,
                      VIR_SRE_AAVMF_NVRAM_PATH) < 0
        || VIR_STRDUP(cfg->firmwares[1]->name,
                      VIR_SRE_OVMF_LOADER_PATH) < 0
        || VIR_STRDUP(cfg->firmwares[1]->nvram,
                      VIR_SRE_OVMF_NVRAM_PATH) < 0
        || VIR_STRDUP(cfg->firmwares[2]->name,
                      VIR_SRE_OVMF_SEC_LOADER_PATH) < 0
        || VIR_STRDUP(cfg->firmwares[2]->nvram,
                      VIR_SRE_OVMF_SEC_NVRAM_PATH) < 0)
        goto error;
#endif

    return cfg;


  error:
    virObjectUnref(cfg);
    return NULL;

}

static void
virSREDriverConfigDispose(void *obj)
{
    virSREDriverConfigPtr cfg = obj;

    VIR_FREE(cfg->configBaseDir);
    VIR_FREE(cfg->configDir);
    VIR_FREE(cfg->autostartDir);
    VIR_FREE(cfg->logDir);
    VIR_FREE(cfg->stateDir);

    VIR_FREE(cfg->libDir);
    VIR_FREE(cfg->cacheDir);
    VIR_FREE(cfg->saveDir);
    VIR_FREE(cfg->memoryBackingDir);
    VIR_FREE(cfg->snapshotDir);
    VIR_FREE(cfg->channelTargetDir);
    VIR_FREE(cfg->nvramDir);

    VIR_FREE(cfg->bridgeHelperName);

    VIR_FREE(cfg->saveImageFormat);
    VIR_FREE(cfg->dumpImageFormat);
    VIR_FREE(cfg->autoDumpPath);

    virStringListFree(cfg->securityDriverNames);

    VIR_FREE(cfg->lockManagerName);

    virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);
}



int
virSREDriverConfigLoadFile(virSREDriverConfigPtr cfg, const char *filename)
{
    virConfPtr conf = NULL;
    int ret = -1;
    size_t i, j;
    char *stdioHandler = NULL;
    char *user = NULL, *group = NULL;
    char **controllers = NULL;
    char **hugetlbfs = NULL;
    char **nvram = NULL;
    char *corestr = NULL;

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read sre config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        goto cleanup;

    if (virConfGetValueStringList
        (conf, "security_driver", true, &cfg->securityDriverNames) < 0)
        goto cleanup;

    for (i = 0;
         cfg->securityDriverNames && cfg->securityDriverNames[i] != NULL;
         i++) {
        for (j = i + 1; cfg->securityDriverNames[j] != NULL; j++) {
            if (STREQ(cfg->securityDriverNames[i],
                      cfg->securityDriverNames[j])) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Duplicate security driver %s"),
                               cfg->securityDriverNames[i]);
                goto cleanup;
            }
        }
    }

    if (virConfGetValueBool
        (conf, "security_default_confined",
         &cfg->securityDefaultConfined) < 0)
        goto cleanup;
    if (virConfGetValueBool
        (conf, "security_require_confined",
         &cfg->securityRequireConfined) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "log_with_libvirtd", &cfg->log_libvirtd)
        < 0)
        goto cleanup;




#undef GET_CONFIG_TLS_CERTINFO
#if 0
    if (virConfGetValueUInt
        (conf, "remote_websocket_port_min", &cfg->webSocketPortMin) < 0)
        goto cleanup;
    if (cfg->webSocketPortMin < SRE_WEBSOCKET_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5700, e.g. localhost:1
         * for port 5701) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _
                       ("%s: remote_websocket_port_min: port must be greater than or equal to %d"),
                       filename, SRE_WEBSOCKET_PORT_MIN);
        goto cleanup;
    }

    if (virConfGetValueUInt
        (conf, "remote_websocket_port_max", &cfg->webSocketPortMax) < 0)
        goto cleanup;
    if (cfg->webSocketPortMax > SRE_WEBSOCKET_PORT_MAX ||
        cfg->webSocketPortMax < cfg->webSocketPortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _
                       ("%s: remote_websocket_port_max: port must be between the minimal port and %d"),
                       filename, SRE_WEBSOCKET_PORT_MAX);
        goto cleanup;
    }

    if (cfg->webSocketPortMin > cfg->webSocketPortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _
                       ("%s: remote_websocket_port_min: min port must not be greater than max port"),
                       filename);
        goto cleanup;
    }

    if (virConfGetValueUInt
        (conf, "remote_display_port_min", &cfg->remotePortMin) < 0)
        goto cleanup;
    if (cfg->remotePortMin < SRE_REMOTE_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5900, e.g. localhost:1
         * for port 5901) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _
                       ("%s: remote_display_port_min: port must be greater than or equal to %d"),
                       filename, SRE_REMOTE_PORT_MIN);
        goto cleanup;
    }

    if (virConfGetValueUInt
        (conf, "remote_display_port_max", &cfg->remotePortMax) < 0)
        goto cleanup;
    if (cfg->remotePortMax > SRE_REMOTE_PORT_MAX ||
        cfg->remotePortMax < cfg->remotePortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _
                       ("%s: remote_display_port_max: port must be between the minimal port and %d"),
                       filename, SRE_REMOTE_PORT_MAX);
        goto cleanup;
    }

    if (cfg->remotePortMin > cfg->remotePortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _
                       ("%s: remote_display_port_min: min port must not be greater than max port"),
                       filename);
        goto cleanup;
    }
//      if (virConfGetValueUInt(conf, "migration_port_min", &cfg->migrationPortMin) < 0)
//          goto cleanup;
//      if (cfg->migrationPortMin <= 0) {
//          virReportError(VIR_ERR_INTERNAL_ERROR,
//                         _("%s: migration_port_min: port must be greater than 0"),
//                          filename);
//          goto cleanup;
//      }
//
//      if (virConfGetValueUInt(conf, "migration_port_max", &cfg->migrationPortMax) < 0)
//          goto cleanup;
//      if (cfg->migrationPortMax > 65535 ||
//          cfg->migrationPortMax < cfg->migrationPortMin) {
//          virReportError(VIR_ERR_INTERNAL_ERROR,
//                          _("%s: migration_port_max: port must be between the minimal port %d and 65535"),
//                         filename, cfg->migrationPortMin);
//          goto cleanup;
//      }
#endif
    if (virConfGetValueString(conf, "user", &user) < 0)
        goto cleanup;
    if (user && virGetUserID(user, &cfg->user) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "group", &group) < 0)
        goto cleanup;
    if (group && virGetGroupID(group, &cfg->group) < 0)
        goto cleanup;

    if (virConfGetValueBool
        (conf, "dynamic_ownership", &cfg->dynamicOwnership) < 0)
        goto cleanup;

    if (virConfGetValueStringList(conf, "cgroup_controllers", false,
                                  &controllers) < 0)
        goto cleanup;

    if (controllers) {
        cfg->cgroupControllers = 0;
        for (i = 0; controllers[i] != NULL; i++) {
            int ctl;

            if ((ctl =
                 virCgroupControllerTypeFromString(controllers[i])) < 0) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Unknown cgroup controller '%s'"),
                               controllers[i]);
                goto cleanup;
            }
            cfg->cgroupControllers |= (1 << ctl);
        }
    }

    if (virConfGetValueStringList(conf, "cgroup_device_acl", false,
                                  &cfg->cgroupDeviceACL) < 0)
        goto cleanup;

    if (virConfGetValueString
        (conf, "save_image_format", &cfg->saveImageFormat) < 0)
        goto cleanup;
    if (virConfGetValueString
        (conf, "dump_image_format", &cfg->dumpImageFormat) < 0)
        goto cleanup;
    if (virConfGetValueString
        (conf, "snapshot_image_format", &cfg->snapshotImageFormat) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "auto_dump_path", &cfg->autoDumpPath) <
        0)
        goto cleanup;
    if (virConfGetValueBool
        (conf, "auto_dump_bypass_cache", &cfg->autoDumpBypassCache) < 0)
        goto cleanup;
    if (virConfGetValueBool
        (conf, "auto_start_bypass_cache", &cfg->autoStartBypassCache) < 0)
        goto cleanup;

    if (virConfGetValueStringList(conf, "hugetlbfs_mount", true,
                                  &hugetlbfs) < 0)
        goto cleanup;


    if (virConfGetValueString
        (conf, "bridge_helper", &cfg->bridgeHelperName) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "mac_filter", &cfg->macFilter) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "relaxed_acs_check", &cfg->relaxedACS) <
        0)
        goto cleanup;
    if (virConfGetValueBool
        (conf, "clear_emulator_capabilities",
         &cfg->clearEmulatorCapabilities) < 0)
        goto cleanup;
    if (virConfGetValueBool
        (conf, "allow_disk_format_probing",
         &cfg->allowDiskFormatProbing) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "set_process_name", &cfg->setProcessName)
        < 0)
        goto cleanup;

    if (virConfGetValueType(conf, "max_core") == VIR_CONF_STRING) {
        if (virConfGetValueString(conf, "max_core", &corestr) < 0)
            goto cleanup;
        if (STREQ(corestr, "unlimited")) {
            cfg->maxCore = ULLONG_MAX;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown core size '%s'"), corestr);
            goto cleanup;
        }
    } else if (virConfGetValueULLong(conf, "max_core", &cfg->maxCore) < 0) {
        goto cleanup;
    }

    if (virConfGetValueBool(conf, "dump_guest_core", &cfg->dumpGuestCore) <
        0)
        goto cleanup;

    if (virConfGetValueString(conf, "lock_manager", &cfg->lockManagerName)
        < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "stdio_handler", &stdioHandler) < 0)
        goto cleanup;
    if (stdioHandler) {
        if (STREQ(stdioHandler, "logd")) {
            cfg->stdioLogD = true;
        } else if (STREQ(stdioHandler, "file")) {
            cfg->stdioLogD = false;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown stdio handler %s"), stdioHandler);
            VIR_FREE(stdioHandler);
            goto cleanup;
        }
        VIR_FREE(stdioHandler);
    }

    if (virConfGetValueUInt(conf, "max_queued", &cfg->maxQueuedJobs) < 0)
        goto cleanup;

    if (virConfGetValueInt
        (conf, "keepalive_interval", &cfg->keepAliveInterval) < 0)
        goto cleanup;
    if (virConfGetValueUInt(conf, "keepalive_count", &cfg->keepAliveCount)
        < 0)
        goto cleanup;

    if (virConfGetValueInt(conf, "seccomp_sandbox", &cfg->seccompSandbox) <
        0)
        goto cleanup;


    if (virConfGetValueBool(conf, "log_timestamp", &cfg->logTimestamp) < 0)
        goto cleanup;

    if (virConfGetValueStringList(conf, "nvram", false, &nvram) < 0)
        goto cleanup;
    if (nvram) {
        virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);

        cfg->nfirmwares = virStringListLength((const char *const *) nvram);
        if (nvram[0] && VIR_ALLOC_N(cfg->firmwares, cfg->nfirmwares) < 0)
            goto cleanup;

        for (i = 0; nvram[i] != NULL; i++) {
            if (VIR_ALLOC(cfg->firmwares[i]) < 0)
                goto cleanup;
            if (virFirmwareParse(nvram[i], cfg->firmwares[i]) < 0)
                goto cleanup;
        }
    }

    if (virConfGetValueString
        (conf, "memory_backing_dir", &cfg->memoryBackingDir) < 0)
        goto cleanup;

    ret = 0;

  cleanup:
    virStringListFree(controllers);
    virStringListFree(hugetlbfs);
    virStringListFree(nvram);
    VIR_FREE(corestr);
    VIR_FREE(user);
    VIR_FREE(group);
    virConfFree(conf);
    return ret;
}


virSREDriverConfigPtr
virSREDriverGetConfig(sreDriverPtr driver)
{
    virSREDriverConfigPtr conf;

    conf = virObjectRef(driver->config);
    return conf;
}

bool
virSREDriverIsPrivileged(sreDriverPtr driver)
{
    return driver->privileged;
}

static int
sreCapsInitCPU(virCapsPtr caps, virArch arch)
{
    virCPUDefPtr cpu = NULL;
    virCPUDataPtr data = NULL;
    virNodeInfo nodeinfo;
    int ret = -1;

    if (VIR_ALLOC(cpu) < 0)
        goto error;

    cpu->arch = arch;

    if (virCapabilitiesGetNodeInfo(&nodeinfo))
        goto error;

    cpu->type = VIR_CPU_TYPE_HOST;
    cpu->sockets = nodeinfo.sockets;
    cpu->cores = nodeinfo.cores;
    cpu->threads = nodeinfo.threads;
    caps->host.cpu = cpu;

    if (!(data = virCPUDataNew(arch)) || cpuDecode(cpu, data, NULL) < 0)
        goto cleanup;

    ret = 0;

  cleanup:
    virCPUDataFree(data);

    return ret;

  error:
    virCPUDefFree(cpu);
    goto cleanup;
}

virCapsPtr
virSRECapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (virCapabilitiesInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN
            ("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (sreCapsInitCPU(caps, virArchFromHost()) < 0)
        VIR_WARN("Failed to get host CPU: %s", virGetLastErrorMessage());

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                         VIR_ARCH_X86_64,
                                         "sre", NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_SRE,
                                      NULL, NULL, 0, NULL) == NULL)
        goto error;

    return caps;

  error:
    virObjectUnref(caps);
    return NULL;
}

virCapsPtr
virSREDriverCreateCapabilities(sreDriverPtr driver)
{
    // size_t i, j;
    virCapsPtr caps;
    virSecurityManagerPtr *sec_managers = NULL;

    /* Security driver data */
    //const char *doi, *model, *lbl, *type;
    virSREDriverConfigPtr cfg = virSREDriverGetConfig(driver);

    /* Basic host arch / guest machine capabilities */
    if (!(caps = virSRECapsInit()))
        goto error;

    if (virGetHostUUID(caps->host.host_uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        goto error;
    }
//    /* access sec drivers and create a sec model for each one */
//    if (!(sec_managers = virSecurityManagerGetNested(driver->securityManager)))
//        goto error;
//
//    /* calculate length */
//    for (i = 0; sec_managers[i]; i++)
//        ;
//    caps->host.nsecModels = i;
//
//    if (VIR_ALLOC_N(caps->host.secModels, caps->host.nsecModels) < 0)
//        goto error;
//
//    for (i = 0; sec_managers[i]; i++) {
//        virCapsHostSecModelPtr sm = &caps->host.secModels[i];
//        doi = virSecurityManagerGetDOI(sec_managers[i]);
//        model = virSecurityManagerGetModel(sec_managers[i]);
//        if (VIR_STRDUP(sm->model, model) < 0 ||
//            VIR_STRDUP(sm->doi, doi) < 0)
//            goto error;
//
//        for (j = 0; j < ARRAY_CARDINALITY(virtTypes); j++) {
//            lbl = virSecurityManagerGetBaseLabel(sec_managers[i], virtTypes[j]);
//            type = virDomainVirtTypeToString(virtTypes[j]);
//            if (lbl &&
//                virCapabilitiesHostSecModelAddBaseLabel(sm, type, lbl) < 0)
//                goto error;
//        }
//
//        VIR_WARN("Initialized caps for security driver \"%s\" with "
//                  "DOI \"%s\"", model, doi);
//    }
//    VIR_FREE(sec_managers);

    virObjectUnref(cfg);
    return caps;

  error:
    VIR_FREE(sec_managers);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return NULL;
}


/**
 * virSREDriverGetCapabilities:
 *
 * Get a reference to the virCapsPtr instance for the
 * driver. If @refresh is true, the capabilities will be
 * rebuilt first
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCapsPtr instance or NULL
 */
virCapsPtr
virSREDriverGetCapabilities(sreDriverPtr driver, bool refresh)
{
    virCapsPtr ret = NULL;

    if (refresh) {
        virCapsPtr caps = NULL;

        if ((caps = virSREDriverCreateCapabilities(driver)) == NULL)
            return NULL;

        sreDriverLock(driver);
        virObjectUnref(driver->caps);
        driver->caps = caps;
    } else {
        sreDriverLock(driver);
    }

    if (driver->caps->nguests == 0 && !refresh) {
        VIR_DEBUG("Capabilities didn't detect any guests. Forcing a "
                  "refresh.");
        sreDriverUnlock(driver);
        return virSREDriverGetCapabilities(driver, true);
    }

    ret = virObjectRef(driver->caps);
    sreDriverUnlock(driver);
    return ret;
}

struct _sreSharedDeviceEntry {
    size_t ref;
    char **domains;             /* array of domain names */
};

/* Construct the hash key for sharedDevices as "major:minor" */
char *
sreGetSharedDeviceKey(const char *device_path)
{
    int maj, min;
    char *key = NULL;
    int rc;

    if ((rc = virGetDeviceID(device_path, &maj, &min)) < 0) {
        virReportSystemError(-rc,
                             _
                             ("Unable to get minor number of device '%s'"),
                             device_path);
        return NULL;
    }

    if (virAsprintf(&key, "%d:%d", maj, min) < 0)
        return NULL;

    return key;
}

/*
 * Make necessary checks for the need to check and for the current setting
 * of the 'unpriv_sgio' value for the device_path passed.
 *
 * Returns:
 *  0 - Success
 * -1 - Some failure which would already have been messaged
 * -2 - Mismatch with the "shared" sgio setting - needs to be messaged
 *      by caller since it has context of which type of disk resource is
 *      being used and in the future the hostdev information.
 */
static int
sreCheckUnprivSGIO(virHashTablePtr sharedDevices,
                   const char *device_path, int sgio)
{
    char *sysfs_path = NULL;
    char *key = NULL;
    int val;
    int ret = -1;

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(device_path, NULL)))
        goto cleanup;

    /* It can't be conflict if unpriv_sgio is not supported by kernel. */
    if (!virFileExists(sysfs_path)) {
        ret = 0;
        goto cleanup;
    }

    if (!(key = sreGetSharedDeviceKey(device_path)))
        goto cleanup;

    /* It can't be conflict if no other domain is sharing it. */
    if (!(virHashLookup(sharedDevices, key))) {
        ret = 0;
        goto cleanup;
    }

    if (virGetDeviceUnprivSGIO(device_path, NULL, &val) < 0)
        goto cleanup;

    /* Error message on failure needs to be handled in caller
     * since there is more specific knowledge of device
     */
    if (!((val == 0 &&
           (sgio == VIR_DOMAIN_DEVICE_SGIO_FILTERED ||
            sgio == VIR_DOMAIN_DEVICE_SGIO_DEFAULT)) ||
          (val == 1 && sgio == VIR_DOMAIN_DEVICE_SGIO_UNFILTERED))) {
        ret = -2;
        goto cleanup;
    }

    ret = 0;

  cleanup:
    VIR_FREE(sysfs_path);
    VIR_FREE(key);
    return ret;
}


/* Check if a shared device's setting conflicts with the conf
 * used by other domain(s). Currently only checks the sgio
 * setting. Note that this should only be called for disk with
 * block source if the device type is disk.
 *
 * Returns 0 if no conflicts, otherwise returns -1.
 */
static int
sreCheckSharedDisk(virHashTablePtr sharedDevices, virDomainDiskDefPtr disk)
{
    int ret;

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_LUN)
        return 0;

    if ((ret = sreCheckUnprivSGIO(sharedDevices, disk->src->path,
                                  disk->sgio)) < 0) {
        if (ret == -2) {
            if (virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_VOLUME) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _
                               ("sgio of shared disk 'pool=%s' 'volume=%s' conflicts with other active domains"),
                               disk->src->srcpool->pool,
                               disk->src->srcpool->volume);
            } else {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _
                               ("sgio of shared disk '%s' conflicts with other active domains"),
                               disk->src->path);
            }
        }
        return -1;
    }

    return 0;
}


bool
sreSharedDeviceEntryDomainExists(sreSharedDeviceEntryPtr entry,
                                 const char *name, int *idx)
{
    size_t i;

    for (i = 0; i < entry->ref; i++) {
        if (STREQ(entry->domains[i], name)) {
            if (idx)
                *idx = i;
            return true;
        }
    }

    return false;
}

void
sreSharedDeviceEntryFree(void *payload, const void *name ATTRIBUTE_UNUSED)
{
    sreSharedDeviceEntryPtr entry = payload;
    size_t i;

    if (!entry)
        return;

    for (i = 0; i < entry->ref; i++)
        VIR_FREE(entry->domains[i]);
    VIR_FREE(entry->domains);
    VIR_FREE(entry);
}


static int
sreSharedDeviceEntryInsert(sreDriverPtr driver,
                           const char *key, const char *name)
{
    sreSharedDeviceEntry *entry = NULL;

    if ((entry = virHashLookup(driver->sharedDevices, key))) {
        /* Nothing to do if the shared scsi host device is already
         * recorded in the table.
         */
        if (!sreSharedDeviceEntryDomainExists(entry, name, NULL)) {
            if (VIR_EXPAND_N(entry->domains, entry->ref, 1) < 0 ||
                VIR_STRDUP(entry->domains[entry->ref - 1], name) < 0) {
                /* entry is owned by the hash table here */
                entry = NULL;
                goto error;
            }
        }
    } else {
        if (VIR_ALLOC(entry) < 0 ||
            VIR_ALLOC_N(entry->domains, 1) < 0 ||
            VIR_STRDUP(entry->domains[0], name) < 0)
            goto error;

        entry->ref = 1;

        if (virHashAddEntry(driver->sharedDevices, key, entry))
            goto error;
    }

    return 0;

  error:
    sreSharedDeviceEntryFree(entry, NULL);
    return -1;
}


/* sreAddSharedDisk:
 * @driver: Pointer to sre driver struct
 * @src: disk source
 * @name: The domain name
 *
 * Increase ref count and add the domain name into the list which
 * records all the domains that use the shared device if the entry
 * already exists, otherwise add a new entry.
 */
static int
sreAddSharedDisk(sreDriverPtr driver,
                 virDomainDiskDefPtr disk, const char *name)
{
    char *key = NULL;
    int ret = -1;

    if (virStorageSourceIsEmpty(disk->src) ||
        !disk->src->shared || !virStorageSourceIsBlockLocal(disk->src))
        return 0;

    sreDriverLock(driver);

    if (sreCheckSharedDisk(driver->sharedDevices, disk) < 0)
        goto cleanup;

    if (!(key = sreGetSharedDeviceKey(virDomainDiskGetSource(disk))))
        goto cleanup;

    if (sreSharedDeviceEntryInsert(driver, key, name) < 0)
        goto cleanup;

    ret = 0;

  cleanup:
    sreDriverUnlock(driver);
    VIR_FREE(key);
    return ret;
}

//TODO SCSI shared drive????
static bool
sreIsSharedHostdev(virDomainHostdevDefPtr hostdev)
{
    return (hostdev->shareable &&
            (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
             hostdev->source.subsys.type ==
             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI
             && hostdev->source.subsys.u.scsi.protocol !=
             VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI));
}


static char *
sreGetHostdevPath(virDomainHostdevDefPtr hostdev)
{
    virDomainHostdevSubsysSCSIPtr scsisrc = &hostdev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
    char *dev_name = NULL;
    char *dev_path = NULL;

    if (!(dev_name = virSCSIDeviceGetDevName(NULL,
                                             scsihostsrc->adapter,
                                             scsihostsrc->bus,
                                             scsihostsrc->target,
                                             scsihostsrc->unit)))
        goto cleanup;

    ignore_value(virAsprintf(&dev_path, "/dev/%s", dev_name));

  cleanup:
    VIR_FREE(dev_name);
    return dev_path;
}


static int
sreAddSharedHostdev(sreDriverPtr driver,
                    virDomainHostdevDefPtr hostdev, const char *name)
{
    char *dev_path = NULL;
    char *key = NULL;
    int ret = -1;

    if (!sreIsSharedHostdev(hostdev))
        return 0;

    if (!(dev_path = sreGetHostdevPath(hostdev)))
        goto cleanup;

    if (!(key = sreGetSharedDeviceKey(dev_path)))
        goto cleanup;

    sreDriverLock(driver);
    ret = sreSharedDeviceEntryInsert(driver, key, name);
    sreDriverUnlock(driver);

  cleanup:
    VIR_FREE(dev_path);
    VIR_FREE(key);
    return ret;
}


static int
sreSharedDeviceEntryRemove(sreDriverPtr driver,
                           const char *key, const char *name)
{
    sreSharedDeviceEntryPtr entry = NULL;
    int idx;

    if (!(entry = virHashLookup(driver->sharedDevices, key)))
        return -1;

    /* Nothing to do if the shared disk is not recored in the table. */
    if (!sreSharedDeviceEntryDomainExists(entry, name, &idx))
        return 0;

    if (entry->ref != 1)
        VIR_DELETE_ELEMENT(entry->domains, idx, entry->ref);
    else
        ignore_value(virHashRemoveEntry(driver->sharedDevices, key));

    return 0;
}


/* sreAddSharedDevice:
 * @driver: Pointer to sre driver struct
 * @dev: The device def
 * @name: The domain name
 *
 * Increase ref count and add the domain name into the list which
 * records all the domains that use the shared device if the entry
 * already exists, otherwise add a new entry.
 */
int
sreAddSharedDevice(sreDriverPtr driver,
                   virDomainDeviceDefPtr dev, const char *name)
{
    /* Currently the only conflicts we have to care about for
     * the shared disk and shared host device is "sgio" setting,
     * which is only valid for block disk and scsi host device.
     */
    if (dev->type == VIR_DOMAIN_DEVICE_DISK)
        return sreAddSharedDisk(driver, dev->data.disk, name);
    else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV)
        return sreAddSharedHostdev(driver, dev->data.hostdev, name);
    else
        return 0;
}


int
sreRemoveSharedDisk(sreDriverPtr driver,
                    virDomainDiskDefPtr disk, const char *name)
{
    char *key = NULL;
    int ret = -1;

    if (virStorageSourceIsEmpty(disk->src) ||
        !disk->src->shared || !virStorageSourceIsBlockLocal(disk->src))
        return 0;

    sreDriverLock(driver);

    if (!(key = sreGetSharedDeviceKey(virDomainDiskGetSource(disk))))
        goto cleanup;

    if (sreSharedDeviceEntryRemove(driver, key, name) < 0)
        goto cleanup;

    ret = 0;
  cleanup:
    sreDriverUnlock(driver);
    VIR_FREE(key);
    return ret;
}


static int
sreRemoveSharedHostdev(sreDriverPtr driver,
                       virDomainHostdevDefPtr hostdev, const char *name)
{
    char *dev_path = NULL;
    char *key = NULL;
    int ret = -1;

    if (!sreIsSharedHostdev(hostdev))
        return 0;

    if (!(dev_path = sreGetHostdevPath(hostdev)))
        goto cleanup;

    if (!(key = sreGetSharedDeviceKey(dev_path)))
        goto cleanup;

    sreDriverLock(driver);
    ret = sreSharedDeviceEntryRemove(driver, key, name);
    sreDriverUnlock(driver);

  cleanup:
    VIR_FREE(dev_path);
    VIR_FREE(key);
    return ret;
}


/* sreRemoveSharedDevice:
 * @driver: Pointer to sre driver struct
 * @device: The device def
 * @name: The domain name
 *
 * Decrease ref count and remove the domain name from the list which
 * records all the domains that use the shared device if ref is not
 * 1, otherwise remove the entry.
 */
int
sreRemoveSharedDevice(sreDriverPtr driver,
                      virDomainDeviceDefPtr dev, const char *name)
{
    if (dev->type == VIR_DOMAIN_DEVICE_DISK)
        return sreRemoveSharedDisk(driver, dev->data.disk, name);
    else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV)
        return sreRemoveSharedHostdev(driver, dev->data.hostdev, name);
    else
        return 0;
}


int
sreSetUnprivSGIO(virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk = NULL;
    virDomainHostdevDefPtr hostdev = NULL;
    char *sysfs_path = NULL;
    const char *path = NULL;
    int val = -1;
    int ret = -1;

    /* "sgio" is only valid for block disk; cdrom
     * and floopy disk can have empty source.
     */
    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        disk = dev->data.disk;

        if (disk->device != VIR_DOMAIN_DISK_DEVICE_LUN ||
            !virStorageSourceIsBlockLocal(disk->src))
            return 0;

        path = virDomainDiskGetSource(disk);
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        hostdev = dev->data.hostdev;

        if (!sreIsSharedHostdev(hostdev))
            return 0;

        if (hostdev->source.subsys.u.scsi.sgio) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _
                           ("'sgio' is not supported for SCSI generic device yet "));
            goto cleanup;
        }

        return 0;
    } else {
        return 0;
    }

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(path, NULL)))
        goto cleanup;

    /* By default, filter the SG_IO commands, i.e. set unpriv_sgio to 0.  */
    val = (disk->sgio == VIR_DOMAIN_DEVICE_SGIO_UNFILTERED);

    /* Do not do anything if unpriv_sgio is not supported by the kernel and the
     * whitelist is enabled.  But if requesting unfiltered access, always call
     * virSetDeviceUnprivSGIO, to report an error for unsupported unpriv_sgio.
     */
    if ((virFileExists(sysfs_path) || val == 1) &&
        virSetDeviceUnprivSGIO(path, NULL, val) < 0)
        goto cleanup;

    ret = 0;

  cleanup:
    VIR_FREE(sysfs_path);
    return ret;
}

int
sreTranslateSnapshotDiskSourcePool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virDomainSnapshotDiskDefPtr def)
{
    if (def->src->type != VIR_STORAGE_TYPE_VOLUME)
        return 0;

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _
                   ("Snapshots are not yet supported with 'pool' volumes"));
    return -1;
}



virDomainXMLOptionPtr
sreDomainXMLConfInit(void)
{
    return virDomainXMLOptionNew(NULL,
                                 &virSREDriverPrivateDataCallbacks,
                                 &virSREDriverDomainXMLNamespace,
                                 NULL, NULL);
}
