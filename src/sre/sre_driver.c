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
 * sre_driver.c: A SRE driver for libvirt
 *
 */
#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libxml/xmlsave.h>
#include <libxml/xpathInternals.h>
#include "sre_driver.h"
#include "sre_driver_access.h"
#include "sre_conf.h"
#include "dirname.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "sre_domain.h"
#include "sre_monitor.h"
#include "sre_process_domain.h"
#include "sre_domain_portal.h"
#define VIR_FROM_THIS VIR_FROM_SRE

VIR_LOG_INIT("sre.sre_driver");

//driver for shared state between connections
sreDriverPtr sre_default_driver = 0;
static int num_default_connections = 0;
static virMutex defaultLock = VIR_MUTEX_INITIALIZER;

#define SRE_EMULATOR "/usr/bin/sre-hv"
#define POLICY_API_PATH "/usr/bin/sre_policy_tool"
static virDrvOpenStatus virDrvSRECheckPaths(void);
static int sreStateStop(void);

static void
sreDriverFree(sreDriverPtr driver)
{
    if (!driver)
        return;

    virObjectUnref(driver->caps);
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->domains);
    virNodeDeviceObjListFree(driver->devs);
    virObjectUnref(&driver->pools);
    virObjectUnref(driver->eventState);
    virMutexUnlock(&driver->lock);
    virMutexDestroy(&driver->lock);

    VIR_FREE(driver);
}

#define SRE_SAVE_MAGIC "SREGuestMagic"


static virCapsPtr
sreBuildCapabilities(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(), true, true)) == NULL)
        goto error;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the
     * driver in this scenario, so log errors & carry on
     */
    if (virCapabilitiesInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN
            ("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (!(caps->host.cpu = virCPUProbeHost(caps->host.arch)))
        VIR_WARN("Failed to get host CPU");

    if (virGetHostUUID(caps->host.host_uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        goto error;
    }

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

static sreDriverPtr
sreDriverNew(void)
{
    sreDriverPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (virMutexInit(&ret->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        goto error;
    }

    if (!
        (ret->xmlopt =
         virDomainXMLOptionNew(NULL, &virSREDriverPrivateDataCallbacks,
                               &virSREDriverDomainXMLNamespace, NULL,
                               NULL))
        || !(ret->eventState = virObjectEventStateNew())
        || !(ret->domains = virDomainObjListNew()))
        goto error;

    virAtomicIntSet(&ret->nextDomID, 1);

    return ret;

  error:
    sreDriverFree(ret);
    return NULL;
}



static virDomainObjPtr
sreDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    sreDriverPtr driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
    }

    return vm;
}




static int
sreConnectAuthenticate(virConnectPtr conn, virConnectAuthPtr auth)
{
    sreDriverPtr driver = conn->privateData;
    int ret = -1;
    ssize_t i;
    char *username = NULL, *password = NULL;

    if (driver->numAuths == 0)
        return 0;

    /* Authentication is required because the sre XML contains a
     * non-empty <auth/> section.  First we must ask for a username.
     */
    username =
        virAuthGetUsername(conn, auth, "sre", NULL, "localhost" /*? */ );
    if (!username) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _
                       ("authentication failed when asking for username"));
        goto cleanup;
    }

    /* Does the username exist? */
    for (i = 0; i < driver->numAuths; ++i) {
        if (STREQ(driver->auths[i].username, username))
            goto found_user;
    }
    i = -1;

  found_user:
    /* Even if we didn't find the user, we still ask for a password. */
    if (i == -1 || driver->auths[i].password != NULL) {
        password = virAuthGetPassword(conn, auth, "sre",
                                      username, "localhost");
        if (password == NULL) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _
                           ("authentication failed when asking for password"));
            goto cleanup;
        }
    }

    if (i == -1 ||
        (password && STRNEQ(driver->auths[i].password, password))) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _
                       ("authentication failed, see sre XML for the correct username/password"));
        goto cleanup;
    }

    ret = 0;
  cleanup:
    VIR_FREE(username);
    VIR_FREE(password);
    return ret;
}

static virDrvOpenStatus
virDrvSRECheckPaths(void)
{
    virDrvOpenStatus status = VIR_DRV_OPEN_ERROR;
    char *policy_api = virFindFileInPath(POLICY_API_PATH);

#ifdef VUB_SUPORT
    char *vub_path = virFindFileInPath(SRE_UART_BRIDGE_PATH);
#endif

    if (policy_api == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "SRE policy tool not found in '%s'.",
                       POLICY_API_PATH);
        goto error;
    }
#ifdef VUB_SUPPORT
    if (vub_path == NULL)
        VIR_WARN
            ("SRE uart bridge device/driver not loaded vub console unavailable '%s'.",
             SRE_UART_BRIDGE_PATH);
#endif

    if (!virFileExists(SRE_EVENT_MON_PATH)) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "SRE event monitor socket not found '%s'.",
                       SRE_EVENT_MON_PATH);
        goto error;
    }
    status = VIR_DRV_OPEN_SUCCESS;

  error:
    VIR_FREE(policy_api);
#ifdef VUB_SUPPORT
    VIR_FREE(vub_path);
#endif
    return status;

}

static virDrvOpenStatus
sreConnectOpen(virConnectPtr conn,
               virConnectAuthPtr auth,
               virConfPtr conf ATTRIBUTE_UNUSED, unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (virDrvSRECheckPaths() != VIR_DRV_OPEN_SUCCESS) {
        VIR_WARN("Failed to find Dependencies");
        return VIR_DRV_OPEN_ERROR;
    }

    if (!conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (!conn->uri->scheme || STRNEQ(conn->uri->scheme, "sre"))
        return VIR_DRV_OPEN_DECLINED;

    /* Remote driver should handle these. */
    if (conn->uri->server) {
        VIR_WARN("remote server nonempty");
        return VIR_DRV_OPEN_DECLINED;
    }

    /* From this point on, the connection is for us. */
    if (!conn->uri->path
        || conn->uri->path[0] == '\0'
        || (conn->uri->path[0] == '/' && conn->uri->path[1] == '\0')) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s",
                       _("sreOpen: supply a path or use sre:///system"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (STRNEQ(conn->uri->path, "/system")
        && STRNEQ(conn->uri->path, "/session")) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("sreOpen: invalid uri try /system"));
        return VIR_DRV_OPEN_DECLINED;
    }

    /*
     * We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR
     */
    virMutexLock(&defaultLock);
    if (num_default_connections++ == 0) {
        sre_default_driver = sreDriverNew();

        sre_default_driver->caps = sreBuildCapabilities();

        if (VIR_STRNDUP
            (sre_default_driver->sre_run_path, POLICY_API_PATH,
             sizeof(POLICY_API_PATH)) < 0)
            goto error;

        sre_default_driver->sre_net_device_list = sreProbeNetDevices();
        if (virConnectOpenEnsureACL(conn) < 0) {
            goto error;
        }
        conn->privateData = sre_default_driver;
        if (!sre_default_driver->config) {
            sre_default_driver->config =
                virSREDriverConfigNew(sre_default_driver);
        }
    } else {

        if (virConnectOpenEnsureACL(conn) < 0) {
            VIR_WARN("Bad user");
            goto error;
        }
        conn->privateData = sre_default_driver;
    }
    /* Fake authentication. */
    if (sreConnectAuthenticate(conn, auth) < 0) {
        VIR_WARN("SRE Auth ERROR");
        goto error;
    }

    virMutexUnlock(&defaultLock);
    return VIR_DRV_OPEN_SUCCESS;

  error:
    sreDriverFree(sre_default_driver);
    conn->privateData = NULL;
    num_default_connections--;
    virMutexUnlock(&defaultLock);
    return VIR_DRV_OPEN_ERROR;
}

static int
sreConnectClose(virConnectPtr conn)
{
    sreDriverPtr driver = conn->privateData;
    bool dflt = false;

    if (driver == sre_default_driver) {
        dflt = true;
        virMutexLock(&defaultLock);
        if (--num_default_connections) {
            virMutexUnlock(&defaultLock);
            return 0;
        }
    }

    sreDriverFree(driver);

    if (dflt) {
        sre_default_driver = NULL;
        virMutexUnlock(&defaultLock);
    }

    conn->privateData = NULL;
    return 0;
}

static int
sreConnectGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED,
                     unsigned long *hvVer)
{
    if (virConnectGetVersionEnsureACL(conn) < 0) {
        return -1;
    }

    unsigned long version = 3000000;

    //TODO Read version from portal.
    *hvVer = version;
    return 0;
}

static char *
sreConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0) {
        return NULL;
    }

    return virGetHostname();
}


static int
sreConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int
sreConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
sreConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int
sreConnectGetMaxVcpus(virConnectPtr conn ATTRIBUTE_UNUSED,
                      const char *type ATTRIBUTE_UNUSED)
{
    if (virConnectGetMaxVcpusEnsureACL(conn) < 0) {
        return -1;
    }

    virNodeInfo info;

    memset(&info, 0, sizeof(virNodeInfo));
    virCapabilitiesGetNodeInfo(&info);
    sre_sys_info_t sys_info;

    sreDomainUpdateSysInfoPortal(&sys_info);

    /* int total_cores = LM_NUM_CORES_PER_PKG * LM_NUM_PACKAGES_PER_NODE * LM_NUM_PKG *info.threads; */
    int total_cores = sys_info.cpu_info.total_cores;

    return total_cores;
}


static char *
sreConnectBaselineCPU(virConnectPtr conn ATTRIBUTE_UNUSED,
                      const char **xmlCPUs,
                      unsigned int ncpus, unsigned int flags)
{
    virCPUDefPtr *cpus = NULL;
    virCPUDefPtr cpu = NULL;
    char *cpustr = NULL;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, NULL);

    if (virConnectBaselineCPUEnsureACL(conn) < 0)
        return NULL;

    if (!(cpus = virCPUDefListParse(xmlCPUs, ncpus, VIR_CPU_TYPE_HOST)))
        goto cleanup;

    if (!
        (cpu =
         virCPUBaseline(VIR_ARCH_NONE, cpus, ncpus, NULL, NULL, false)))
        goto cleanup;

    if ((flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) &&
        virCPUExpandFeatures(cpus[0]->arch, cpu) < 0)
        goto cleanup;

    cpustr = virCPUDefFormat(cpu, NULL);

  cleanup:
    virCPUDefListFree(cpus);
    virCPUDefFree(cpu);

    return cpustr;
}

static int
sreNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    int ret = -1;
    sreDriverPtr driver = conn->privateData;

    if (virNodeGetInfoEnsureACL(conn) < 0)
        return ret;

    sre_sys_info_t sys_info;

    if (sreDomainUpdateSysInfoPortal(&sys_info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Failed to update sys_info");
        return ret;
    }

    /* override with sawtooth package info */
    info->nodes = sys_info.cpu_info.num_numa_nodes;
    info->sockets = sys_info.cpu_info.num_sub_numa_clusters;

    if (info->nodes == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Failed to update sys_info invalid number of nodes %d ",
                       info->nodes);
        return ret;
    }

    if (sys_info.cpu_info.num_ht == 0) {
        sys_info.cpu_info.num_ht = 1;
    }

    info->threads = sys_info.cpu_info.num_ht;
    info->cores =
        sys_info.cpu_info.total_cores / (sys_info.cpu_info.num_ht *
                                         info->nodes);
    info->cpus = sys_info.cpu_info.total_cores;

    info->memory = sys_info.total_mem / 1024;

    driver->nodeInfo = *info;
    ret = 0;

    return ret;

}

static char *
sreConnectGetCapabilities(virConnectPtr conn)
{
    sreDriverPtr driver = conn->privateData;
    char *xml;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0) {
        return NULL;
    }

    sreDriverLock(driver);
    xml = virCapabilitiesFormatXML(driver->caps);
    sreDriverUnlock(driver);
    return xml;
}

static int
sreConnectNumOfDomains(virConnectPtr conn)
{
    sreDriverPtr driver = conn->privateData;
    int count = 0;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0) {
        return -1;
    }

    sreDriverLock(driver);
    //Not sure if NULL at the end of virDomainObjListNumOfDomains should be conn instead of NULL
    count =
        virDomainObjListNumOfDomains(driver->domains, true,
                                     virConnectNumOfDomainsCheckACL, NULL);
    sreDriverUnlock(driver);

    return count;
}

static int
sreDomainIsActive(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = sreDomObjFromDomain(dom)))
        return -1;

    if (virDomainIsActiveEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

  cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int
sreDomainIsPersistent(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = sreDomObjFromDomain(dom)))
        return -1;

    if (virDomainIsPersistentEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

  cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int
sreDomainIsUpdated(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = sreDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsUpdated(dom) < 0)
        goto cleanup;

    if (virDomainIsUpdatedEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->updated;

  cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}


/**
 * sreDomainSaveImageOpen:
 * @driver: sre driver data
 * @path: path of the save image
 * @ret_def: returns domain definition created from the XML stored in the image
 * @ret_header: returns structure filled with data from the image header
 * @xmlout: returns the XML from the image file (may be NULL)
 * @bypass_cache: bypass cache when opening the file
 * @wrapperFd: returns the file wrapper structure
 * @open_write: open the file for writing (for updates)
 * @unlink_corrupt: remove the image file if it is corrupted
 *
 * Returns the opened fd of the save image file and fills the appropriate fields
 * on success. On error returns -1 on most failures, -3 if corrupt image was
 * unlinked (no error raised).
 */
static int
sreDomainSaveImageOpen(sreDriverPtr driver,
                       const char *path,
                       virDomainDefPtr * ret_def,
                       char **xmlout,
                       bool bypass_cache,
                       virFileWrapperFdPtr * wrapperFd,
                       bool open_write, unsigned int flags)
{
    int fd = -1;
    char magic[14];
    int len = -1;
    char *xml = NULL;
    virDomainDefPtr def = NULL;
    int oflags = open_write ? O_RDWR : O_RDONLY;
    virCapsPtr caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (bypass_cache) {
        int directFlag = virFileDirectFdFlag();

        if (directFlag < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("bypass cache unsupported by this system"));
            goto cleanup;
        }
        oflags |= directFlag;
    }

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("cannot read domain image '%s'"), path);
        goto cleanup;
    }

    if (bypass_cache &&
        !(*wrapperFd = virFileWrapperFdNew(&fd, path,
                                           VIR_FILE_WRAPPER_BYPASS_CACHE)))
    {
        goto cleanup;
    }
    if (saferead(fd, magic, sizeof(magic)) != sizeof(magic)) {
        virReportSystemError(errno,
                             _("incomplete save header in '%s'"), path);
        goto cleanup;
    }
    if (memcmp(magic, SRE_SAVE_MAGIC, sizeof(magic))) {
        VIR_WARN("%s %s", magic, SRE_SAVE_MAGIC);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("mismatched header magic"));
        goto cleanup;
    }
    if (saferead(fd, (char *) &len, sizeof(len)) != sizeof(len)) {
        virReportSystemError(errno,
                             _("failed to read metadata length in '%s'"),
                             path);
        goto cleanup;
    }
    if (len < 1 || len > 8192) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("length of metadata out of range"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(xml, len + 1) < 0) {
        goto cleanup;
    }
    if (saferead(fd, xml, len) != len) {
        virReportSystemError(errno,
                             _("incomplete metadata in '%s'"), path);
        goto cleanup;
    }
    xml[len] = '\0';

    /* Create a domain from this XML */
    if (!
        (def =
         virDomainDefParseString(xml, driver->caps, driver->xmlopt, NULL,
                                 parse_flags)))
        goto cleanup;

    if (xmlout)
        *xmlout = xml;
    else
        VIR_FREE(xml);

    *ret_def = def;

    virObjectUnref(caps);

    return fd;

  cleanup:
    virDomainDefFree(def);
    VIR_FREE(xml);
    VIR_FORCE_CLOSE(fd);
    virObjectUnref(caps);

    return -1;
}

static virDomainPtr
sreDomainCreateXML(virConnectPtr conn, const char *xml, unsigned int flags)
{
    sreDriverPtr driver = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainDefPtr def;
    virDomainObjPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if ((def = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0) {
        goto cleanup;
    }

    if (!(dom = virDomainObjListAdd(driver->domains,
                                    def,
                                    driver->xmlopt,
                                    VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                    VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                    NULL))) {
        goto cleanup;
    }
    if (virSREProcessStartDomain
        (conn, conn->privateData, dom,
         (flags & VIR_DOMAIN_START_AUTODESTROY),
         VIR_DOMAIN_RUNNING_BOOTED)) {
        VIR_WARN("Error starting domain");
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid, dom->def->id);
    if (ret)
        ret->id = dom->def->id;

  cleanup:
    if (dom)
        virObjectUnlock(dom);

    return ret;
}


static virDomainPtr
sreDomainLookupByID(virConnectPtr conn, int id)
{
    sreDriverPtr driver = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    if (!(dom = virDomainObjListFindByID(driver->domains, id))) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, dom->def) < 0) {
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid, dom->def->id);
    if (ret)
        ret->id = dom->def->id;

  cleanup:
    if (dom)
        virObjectUnlock(dom);

    return ret;
}

static virDomainPtr
sreDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    sreDriverPtr driver = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    if (!(dom = virDomainObjListFindByUUID(driver->domains, uuid))) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, dom->def) < 0) {
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid, dom->def->id);
    if (ret)
        ret->id = dom->def->id;

  cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static virDomainPtr
sreDomainLookupByName(virConnectPtr conn, const char *name)
{
    sreDriverPtr driver = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    if (!(dom = virDomainObjListFindByName(driver->domains, name))) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, dom->def) < 0) {
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid, dom->def->id);
    if (ret)
        ret->id = dom->def->id;

  cleanup:
    virDomainObjEndAPI(&dom);
    return ret;
}


static int
sreDomainObjListUpdateDomain(virDomainObjPtr dom, void *data)
{
    (void) data;
    virObjectLock(dom);

    if (sreDomainUpdateStatePortal(dom)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("domain failed to update state"));
    }

    virObjectUnlock(dom);

    return 0;
}

static void
sreDomainObjListUpdateAll(virDomainObjListPtr doms, sreDriverPtr driver)
{
    virDomainObjListForEach(doms, sreDomainObjListUpdateDomain, driver);
}

static int
sreConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    int n;
    sreDriverPtr driver = conn->privateData;

    if (virConnectListDomainsEnsureACL(conn) < 0) {
        return -1;
    }

    sreDomainObjListUpdateAll(driver->domains, driver);
    //Now sure if this should be virDomainObjListGetActiveIDs(driver->domains, ids, maxids, virConnectListDomainsCheckACL, conn)
    // or stay the way it is
    n = virDomainObjListGetActiveIDs(driver->domains, ids, maxids,
                                     virConnectListDomainsCheckACL, NULL);
    return n;
}

static int
sreDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    sreDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;
    virSREDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_DESTROY_GRACEFUL, -1);

    if (!(vm = sreDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;

    priv->doneStopEvent = true;
    priv->wantReboot = false;
    if (flags & VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN) {
        VIR_WARN("domain soft stop");
        if (sreShutdownDomainPortal
            (vm, VIR_DOMAIN_SHUTOFF_DESTROYED, ACPI_PWR_BUTTON_SHUTDOWN))
            goto cleanup;
    } else {
        VIR_WARN("domain hard stop");
        if (sreShutdownDomainPortal
            (vm, VIR_DOMAIN_SHUTOFF_DESTROYED, FORCE_SHUTDOWN))
            goto cleanup;

        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STOPPED,
                                                  VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

        if (sreDomainReleaseSRENetDev
            (driver, (sreDomainNamespaceDefPtr) vm->def->namespaceData,
             vm->def)) {
            VIR_WARN("domain netdev config failed");
            goto cleanup;
        }
    }

    ret = 0;

    if (!vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
    }

  cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->eventState, event);
    return ret;
}

static int
sreDomainDestroy(virDomainPtr domain)
{
    return sreDomainDestroyFlags(domain, 0);
}

static int
sreDomainResume(virDomainPtr domain)
{
    sreDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainResumeEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("domain '%s' not paused"),
                       domain->name);
        goto cleanup;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                         VIR_DOMAIN_RUNNING_UNPAUSED);

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_RESUMED,
                                              VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    sreObjectEventQueue(driver, event);

    return ret;
}

static int
sreDomainSuspend(virDomainPtr domain)
{
    sreDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;
    int state;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainSuspendEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    state = virDomainObjGetState(vm, NULL);
    if (state == VIR_DOMAIN_SHUTOFF || state == VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("domain '%s' not running"), domain->name);
        goto cleanup;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_SUSPENDED,
                                              VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    sreObjectEventQueue(driver, event);

    return ret;
}

static int
sreDomainShutdownFlags(virDomainPtr domain, unsigned int flags)
{
    sreDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = sreDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainShutdownFlagsEnsureACL(domain->conn, vm->def, flags) < 0) {
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("domain '%s' not running"), domain->name);
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN) {
        if (sreShutdownDomainPortal
            (vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN, ACPI_PWR_BUTTON_SHUTDOWN)) {
            goto cleanup;
        }

        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SHUTDOWN,
                                                  VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
    } else {
        if (sreShutdownDomainPortal
            (vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN, FORCE_SHUTDOWN)) {
            goto cleanup;
        }

        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STOPPED,
                                                  VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
    }
    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    sreObjectEventQueue(driver, event);

    return ret;
}

static int
sreDomainShutdown(virDomainPtr domain)
{
    return sreDomainShutdownFlags(domain, 0);
}

/* Similar behaviour as shutdown */
static int
sreDomainReboot(virDomainPtr domain, unsigned int flags)
{
    sreDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;
    bool isReboot = true;

    virCheckFlags(VIR_DOMAIN_REBOOT_ACPI_POWER_BTN, -1);


    if (!(vm = sreDomObjFromDomain(domain)))
        goto cleanup;

    if (vm->def->onReboot == VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY ||
        vm->def->onReboot == VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE) {
        isReboot = false;
        VIR_INFO("Domain on_reboot setting overridden, shutting down");
    }

    if (virDomainRebootEnsureACL(domain->conn, vm->def, flags) < 0) {
        goto cleanup;
    }

    if (isReboot) {
        if (flags & VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN) {
            if (virSREProcessRebootDomain
                (driver, vm, ACPI_PWR_BUTTON_SHUTDOWN))
                goto cleanup;
        } else {
            if (virSREProcessRebootDomain(driver, vm, FORCE_SHUTDOWN))
                goto cleanup;
        }
    } else {
        if (flags & VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN) {
            if (sreShutdownDomainPortal
                (vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN,
                 ACPI_PWR_BUTTON_SHUTDOWN))
                virReportError(VIR_ERR_CALL_FAILED, "%s",
                               _("VM Shutdown failed"));

        } else {
            if (sreShutdownDomainPortal
                (vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN, FORCE_SHUTDOWN))
                virReportError(VIR_ERR_CALL_FAILED, "%s",
                               _("VM Shutdown failed"));
        }
    }
    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_SHUTDOWN,
                                              VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);

    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;
  cleanup:
    virDomainObjEndAPI(&vm);
    sreObjectEventQueue(driver, event);

    return ret;
}

static int
sreDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    struct timeval tv;
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainGetInfoEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("getting time of day"));
        goto cleanup;
    }
    if (sreDomainUpdateStatePortal(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("domain '%s' failed to update state"),
                       domain->name);
        goto cleanup;
    }

    info->state = virDomainObjGetState(vm, NULL);
    info->memory = vm->def->mem.cur_balloon;
    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    info->cpuTime =
        ((tv.tv_sec * 1000ll * 1000ll * 1000ll) + (tv.tv_usec * 1000ll));
    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainGetState(virDomainPtr domain,
                  int *state, int *reason, unsigned int flags)
{
    virDomainObjPtr vm;

    (void) reason;
    (void) flags;
    if (!(vm = sreDomObjFromDomain(domain))) {
        return -1;
    }

    if (virDomainGetStateEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    if (sreDomainUpdateStatePortal(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("domain '%s' failed to update state"),
                       domain->name);
        return 1;
    } else {
        *state = virDomainObjGetState(vm, NULL);
    }

  cleanup:
    virDomainObjEndAPI(&vm);
    return 0;
}

static int
sreDomainSaveFlags(virDomainPtr domain, const char *path,
                   const char *dxml, unsigned int flags)
{
    sreDriverPtr driver = domain->conn->privateData;
    char *xml = NULL;
    int fd = -1;
    int len;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    if (!(vm = sreDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainSaveFlagsEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    xml = virDomainDefFormat(vm->def, driver->caps,
                             VIR_DOMAIN_DEF_FORMAT_SECURE);

    if (xml == NULL) {
        virReportSystemError(errno,
                             _
                             ("saving domain '%s' failed to allocate space for metadata"),
                             domain->name);
        goto cleanup;
    }

    if ((fd =
         open(path, O_CREAT | O_TRUNC | O_WRONLY,
              S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': open failed"),
                             domain->name, path);
        goto cleanup;
    }

    len = strlen(xml);
    if (safewrite(fd, SRE_SAVE_MAGIC, sizeof(SRE_SAVE_MAGIC)) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }

    if (safewrite(fd, (char *) &len, sizeof(len)) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }

    if (safewrite(fd, xml, len) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }
    fd = -1;

    sreShutdownDomainPortal(vm, VIR_DOMAIN_SHUTOFF_SAVED, FORCE_SHUTDOWN);
    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_SAVED);

    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;
  cleanup:
    VIR_FREE(xml);

    /* Don't report failure in close or unlink, because
     * in either case we're already in a failure scenario
     * and have reported a earlier error */
    if (ret != 0) {
        VIR_FORCE_CLOSE(fd);
        unlink(path);
    }

    virDomainObjEndAPI(&vm);
    sreObjectEventQueue(driver, event);
    return ret;
}

static int
sreDomainSave(virDomainPtr domain, const char *path)
{
    return sreDomainSaveFlags(domain, path, NULL, 0);
}

static int
sreDomainRestoreFlags(virConnectPtr conn,
                      const char *path,
                      const char *dxml, unsigned int flags)
{
    sreDriverPtr driver = conn->privateData;
    char *xml = NULL;
    int fd = -1;
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom = NULL;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    fd = sreDomainSaveImageOpen(driver, path, &def, &xml,
                                false, NULL, false, flags);

    def = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                  NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE);

    if (!def)
        goto cleanup;

    if (virDomainRestoreFlagsEnsureACL(conn, def) < 0) {
        goto cleanup;
    }

    if (!(dom = virDomainObjListAdd(driver->domains,
                                    def,
                                    driver->xmlopt,
                                    VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                    VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                    NULL)))
        goto cleanup;
    def = NULL;

    if (sreDomainStartState(driver, dom, VIR_DOMAIN_RUNNING_RESTORED) < 0) {
        if (!dom->persistent) {
            virDomainObjListRemove(driver->domains, dom);
            dom = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(dom,
                                              VIR_DOMAIN_EVENT_STARTED,
                                              VIR_DOMAIN_EVENT_STARTED_RESTORED);
    ret = 0;

  cleanup:
    virDomainDefFree(def);
    VIR_FREE(xml);
    VIR_FORCE_CLOSE(fd);
    if (dom)
        virObjectUnlock(dom);
    sreObjectEventQueue(driver, event);

    return ret;
}

static int
sreDomainRestore(virConnectPtr conn, const char *path)
{
    return sreDomainRestoreFlags(conn, path, NULL, 0);
}

static int
sreDomainCoreDumpWithFormat(virDomainPtr domain,
                            const char *to,
                            unsigned int dumpformat, unsigned int flags)
{
    sreDriverPtr driver = domain->conn->privateData;
    int fd = -1;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(VIR_DUMP_CRASH, -1);

    if (!(vm = sreDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainCoreDumpWithFormatEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    if ((fd =
         open(to, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("domain '%s' coredump: failed to open %s"),
                             domain->name, to);
        goto cleanup;
    }

    if (safewrite(fd, SRE_SAVE_MAGIC, sizeof(SRE_SAVE_MAGIC)) < 0) {
        virReportSystemError(errno,
                             _
                             ("domain '%s' coredump: failed to write header to %s"),
                             domain->name, to);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("domain '%s' coredump: write failed: %s"),
                             domain->name, to);
        goto cleanup;
    }

    /* we don't support non-raw formats in sre driver */
    if (dumpformat != VIR_DOMAIN_CORE_DUMP_FORMAT_RAW) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("kdump-compressed format is not supported here"));
        goto cleanup;
    }

    if (flags & VIR_DUMP_CRASH) {
        sreShutdownDomainPortal(vm, VIR_DOMAIN_SHUTOFF_CRASHED,
                                FORCE_SHUTDOWN);
        event =
            virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_CRASHED);
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
    }

    ret = 0;
  cleanup:
    VIR_FORCE_CLOSE(fd);
    virDomainObjEndAPI(&vm);
    sreObjectEventQueue(driver, event);
    return ret;
}


static int
sreDomainCoreDump(virDomainPtr domain, const char *to, unsigned int flags)
{
    return sreDomainCoreDumpWithFormat(domain, to,
                                       VIR_DOMAIN_CORE_DUMP_FORMAT_RAW,
                                       flags);
}


static char *
sreDomainGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    virDomainObjPtr vm;
    char *ret;

    if (!(vm = sreDomObjFromDomain(dom))) {
        goto cleanup;
    }

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0) {
        goto cleanup;
    }

    ignore_value(VIR_STRDUP
                 (ret, virDomainOSTypeToString(vm->def->os.type)));
    // ignore_value(VIR_STRDUP(ret, "linux"));
    // return ret;
  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static unsigned long long
sreDomainGetMaxMemory(virDomainPtr domain)
{
    virDomainObjPtr vm;
    unsigned long long ret = 0;

    if (!(vm = sreDomObjFromDomain(domain)))
        return 0;

    if (virDomainGetMaxMemoryEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    ret = virDomainDefGetMemoryTotal(vm->def);

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    virDomainObjPtr vm;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainSetMaxMemoryEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    /* XXX validate not over host memory wrt to other domains */
    virDomainDefSetMemoryTotal(vm->def, memory);

  cleanup:
    virDomainObjEndAPI(&vm);
    return 0;
}

static int
sreDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainSetMemoryEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }


    if (memory > virDomainDefGetMemoryTotal(vm->def)) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    vm->def->mem.cur_balloon = memory;
    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainGetVcpusFlags(virDomainPtr domain, unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainDefPtr def;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG | VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainGetVcpusFlagsEnsureACL(domain->conn, vm->def, flags) < 0) {
        goto cleanup;
    }

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    if (flags & VIR_DOMAIN_VCPU_MAXIMUM)
        ret = virDomainDefGetVcpusMax(def);
    else
        ret = virDomainDefGetVcpus(def);

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainGetMaxVcpus(virDomainPtr domain)
{
    return sreDomainGetVcpusFlags(domain, (VIR_DOMAIN_AFFECT_LIVE |
                                           VIR_DOMAIN_VCPU_MAXIMUM));
}

static int
sreDomainSetVcpusFlags(virDomainPtr domain, unsigned int nrCpus,
                       unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    sreDriverPtr driver = domain->conn->privateData;
    int ret = -1, maxvcpus;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG | VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if ((maxvcpus = sreConnectGetMaxVcpus(domain->conn, NULL)) < 0)
        return -1;

    if (nrCpus > maxvcpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _
                       ("requested cpu amount exceeds maximum supported amount (%d > %d)"),
                       nrCpus, maxvcpus);
        return -1;
    }

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainSetVcpusFlagsEnsureACL(domain->conn, vm->def, flags) < 0) {
        goto cleanup;
    }

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto cleanup;

    if (def && virDomainDefGetVcpusMax(def) < nrCpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested cpu amount exceeds maximum (%d > %d)"),
                       nrCpus, virDomainDefGetVcpusMax(def));
        goto cleanup;
    }

    if (persistentDef &&
        !(flags & VIR_DOMAIN_VCPU_MAXIMUM) &&
        virDomainDefGetVcpusMax(persistentDef) < nrCpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested cpu amount exceeds maximum (%d > %d)"),
                       nrCpus, virDomainDefGetVcpusMax(persistentDef));
        goto cleanup;
    }

    if (def && virDomainDefSetVcpus(def, nrCpus) < 0)
        goto cleanup;

    if (persistentDef) {
        if (flags & VIR_DOMAIN_VCPU_MAXIMUM) {
            if (virDomainDefSetVcpusMax
                (persistentDef, nrCpus, driver->xmlopt) < 0)
                goto cleanup;
        } else {
            if (virDomainDefSetVcpus(persistentDef, nrCpus) < 0)
                goto cleanup;
        }
    }

    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainSetVcpus(virDomainPtr domain, unsigned int nrCpus)
{
    return sreDomainSetVcpusFlags(domain, nrCpus, VIR_DOMAIN_AFFECT_LIVE);
}

static int
sreDomainGetVcpus(virDomainPtr domain,
                  virVcpuInfoPtr info,
                  int maxinfo, unsigned char *cpumaps, int maplen)
{
    sreDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    size_t i;
    int maxcpu = 0, hostcpus = 0;
    int ret = -1;
    struct timeval tv;
    unsigned long long statbase;
    virBitmapPtr allcpumap = NULL;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainGetVcpusEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s",
                       _("cannot list vcpus for an inactive domain"));
        goto cleanup;
    }

    def = vm->def;

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno, "%s", _("getting time of day"));
        goto cleanup;
    }

    statbase = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;

    hostcpus = VIR_NODEINFO_MAXCPUS(driver->nodeInfo);
    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    if (!(allcpumap = virBitmapNew(hostcpus)))
        goto cleanup;

    virBitmapSetAll(allcpumap);

    /* Clamp to actual number of vcpus */
    if (maxinfo > virDomainDefGetVcpus(vm->def))
        maxinfo = virDomainDefGetVcpus(vm->def);

    memset(info, 0, sizeof(*info) * maxinfo);
    memset(cpumaps, 0, maxinfo * maplen);

    for (i = 0; i < maxinfo; i++) {
        virDomainVcpuDefPtr vcpu = virDomainDefGetVcpu(def, i);
        virBitmapPtr bitmap = NULL;

        if (!vcpu->online)
            continue;

        if (vcpu->cpumask)
            bitmap = vcpu->cpumask;
        else if (def->cpumask)
            bitmap = def->cpumask;
        else
            bitmap = allcpumap;

        if (cpumaps)
            virBitmapToDataBuf(bitmap, VIR_GET_CPUMAP(cpumaps, maplen, i),
                               maplen);

        info[i].number = i;
        info[i].state = VIR_VCPU_RUNNING;
        info[i].cpu = virBitmapLastSetBit(bitmap);

        /* Fake an increasing cpu time value */
        info[i].cpuTime = statbase / 10;
    }

    ret = maxinfo;
  cleanup:
    virBitmapFree(allcpumap);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainPinVcpu(virDomainPtr domain,
                 unsigned int vcpu, unsigned char *cpumap, int maplen)
{
    virDomainVcpuDefPtr vcpuinfo;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    int ret = -1;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    def = vm->def;

    if (virDomainPinVcpuEnsureACL(domain->conn, vm->def) < 0) {
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    if (!(vcpuinfo = virDomainDefGetVcpu(def, vcpu)) || !vcpuinfo->online) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _
                       ("requested vcpu '%d' is not present in the domain"),
                       vcpu);
        goto cleanup;
    }

    virBitmapFree(vcpuinfo->cpumask);

    if (!(vcpuinfo->cpumask = virBitmapNewData(cpumap, maplen)))
        goto cleanup;

    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainGetVcpuPinInfo(virDomainPtr dom,
                        int ncpumaps,
                        unsigned char *cpumaps,
                        int maplen, unsigned int flags)
{
    sreDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainDefPtr def;
    int ret = -1;

    if (!(vm = sreDomObjFromDomain(dom)))
        return -1;

    if (virDomainGetVcpuPinInfoEnsureACL(dom->conn, vm->def) < 0) {
        goto cleanup;
    }

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    ret = virDomainDefGetVcpuPinInfoHelper(def, maplen, ncpumaps, cpumaps,
                                           VIR_NODEINFO_MAXCPUS(driver->
                                                                nodeInfo),
                                           NULL);

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
sreDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    sreDriverPtr driver = domain->conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    if (!(vm = sreDomObjFromDomain(domain)))
        return NULL;

    if (virDomainGetXMLDescEnsureACL(domain->conn, vm->def, flags) < 0) {
        goto cleanup;
    }

    def = (flags & VIR_DOMAIN_XML_INACTIVE) &&
        vm->newDef ? vm->newDef : vm->def;

    ret = virDomainDefFormat(def, driver->caps,
                             virDomainDefFormatConvertXMLFlags(flags));

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreConnectNumOfDefinedDomains(virConnectPtr conn)
{
    sreDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0) {
        goto cleanup;
    }
    //Not sure if NULL at the end of virDomainObjListNumOfDomains should be conn or stay NULL
    ret =
        virDomainObjListNumOfDomains(driver->domains, false,
                                     virConnectNumOfDefinedDomainsCheckACL,
                                     NULL);

  cleanup:
    return ret;
}

static int
sreConnectListDefinedDomains(virConnectPtr conn,
                             char **const names, int maxnames)
{

    sreDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0) {
        goto cleanup;
    }

    memset(names, 0, sizeof(*names) * maxnames);
    //Not sure if NULL at the end of virDomainObjListGetInactiveNames should be conn or stay NULL
    ret =
        virDomainObjListGetInactiveNames(driver->domains, names, maxnames,
                                         virConnectListDefinedDomainsCheckACL,
                                         NULL);

  cleanup:
    return ret;
}

static int
sreDomainSaveImageDefineXML(virConnectPtr conn, const char *path,
                            const char *dxml, unsigned int flags)
{
    sreDriverPtr driver = conn->privateData;
    int ret = -1;
    virDomainDefPtr def = NULL;
    int fd = -1;

    char *xml = NULL;
    size_t len;

    char magic[14];
    virDomainObjPtr dom = NULL;
    virObjectEventPtr event = NULL;
    int state = -1;

    virCheckFlags(VIR_DOMAIN_SAVE_RUNNING | VIR_DOMAIN_SAVE_PAUSED, -1);

    if (flags & VIR_DOMAIN_SAVE_RUNNING)
        state = 1;
    else if (flags & VIR_DOMAIN_SAVE_PAUSED)
        state = 0;

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("cannot read domain image '%s'"), path);
        goto cleanup;
    }

    if (virDomainSaveImageDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (saferead(fd, magic, sizeof(magic)) != sizeof(magic)) {
        virReportSystemError(errno,
                             _("incomplete save header in '%s'"), path);
        goto cleanup;
    }

    if (memcmp(magic, SRE_SAVE_MAGIC, sizeof(magic))) {
        VIR_DEBUG("%s %s", magic, SRE_SAVE_MAGIC);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("mismatched header magic"));
        goto cleanup;
    }

    if (saferead(fd, (char *) &len, sizeof(len)) != sizeof(len)) {
        virReportSystemError(errno,
                             _("failed to read metadata length in '%s'"),
                             path);
        goto cleanup;
    }

    if (len < 1 || len > 8192) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("length of metadata out of range"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(xml, len + 1) < 0)
        goto cleanup;

    if (saferead(fd, xml, len) != len) {
        virReportSystemError(errno,
                             _("incomplete metadata in '%s'"), path);
        goto cleanup;
    }
    xml[len] = '\0';


    if (STREQ(xml, dxml) && (state < 0)) {      //state == header.was_running
        /* no change to the XML */
        ret = 0;
        VIR_WARN("domain was running");
        goto cleanup;
    }

    def = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                  NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (!def)
        goto cleanup;
    if (!(dom = virDomainObjListAdd(driver->domains,
                                    def,
                                    driver->xmlopt,
                                    VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                    VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                    NULL)))
        goto cleanup;
    def = NULL;
    dom->autostart = 0;
    if (sreDomainStartState(driver, dom, VIR_DOMAIN_RUNNING_RESTORED) < 0) {
        if (!dom->persistent) {
            virDomainObjListRemove(driver->domains, dom);
            dom = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(dom,
                                              VIR_DOMAIN_EVENT_STARTED,
                                              VIR_DOMAIN_EVENT_STARTED_RESTORED);
    ret = 0;

  cleanup:
    virDomainDefFree(def);
    VIR_FREE(xml);
    VIR_FORCE_CLOSE(fd);
    if (dom)
        virObjectUnlock(dom);
    sreObjectEventQueue(driver, event);
    return ret;
}

static virDomainPtr
sreDomainDefineXMLFlags(virConnectPtr conn,
                        const char *xml, unsigned int flags)
{
    sreDriverPtr driver = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom = NULL;
    virObjectEventPtr event = NULL;
    virDomainDefPtr oldDef = NULL;
    unsigned int parse_flags =
        VIR_DOMAIN_DEF_PARSE_INACTIVE | VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;
    virSREDriverConfigPtr cfg;

    cfg = virSREDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if ((def = virDomainDefParseString(xml, driver->caps, driver->xmlopt,
                                       NULL, parse_flags)) == NULL) {
        goto cleanup;
    }

    if (!driver->domains) {
        VIR_DEBUG("domain xml parse list is null");
    }

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(dom = virDomainObjListAdd(driver->domains,
                                    def,
                                    driver->xmlopt,
                                    VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                    &oldDef))) {
        goto cleanup;
    }

    def = NULL;
    dom->persistent = 1;

    if (!cfg || !cfg->configDir || !driver->caps) {
        VIR_DEBUG("driver is null %lx %lx", (uint64_t) dom->newDef,
                  (uint64_t) dom->def);
    }

    if (virDomainSaveConfig(cfg->configDir, driver->caps,
                            dom->newDef ? dom->newDef : dom->def) < 0) {
        virDomainObjListRemove(driver->domains, dom);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(dom,
                                              VIR_DOMAIN_EVENT_DEFINED,
                                              !oldDef ?
                                              VIR_DOMAIN_EVENT_DEFINED_ADDED
                                              :
                                              VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid, dom->def->id);
    if (ret)
        ret->id = dom->def->id;

  cleanup:
    virDomainDefFree(def);
    virDomainDefFree(oldDef);
    virObjectUnref(cfg);

    if (dom)
        virObjectUnlock(dom);

    sreObjectEventQueue(driver, event);

    return ret;
}

static virDomainPtr
sreDomainDefineXML(virConnectPtr conn, const char *xml)
{
    sreConnectGetCapabilities(conn);
    return sreDomainDefineXMLFlags(conn, xml, 0);
}

static char *
sreDomainGetMetadata(virDomainPtr dom,
                     int type, const char *uri, unsigned int flags)
{
    virDomainObjPtr vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, NULL);

    if (!(vm = sreDomObjFromDomain(dom)))
        return NULL;

    if (virDomainGetMetadataEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainObjGetMetadata(vm, type, uri, flags);

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainSetMetadata(virDomainPtr dom,
                     int type,
                     const char *metadata,
                     const char *key, const char *uri, unsigned int flags)
{
    sreDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = sreDomObjFromDomain(dom)))
        return -1;

    if (virDomainSetMetadataEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri,
                                  driver->caps, driver->xmlopt,
                                  NULL, NULL, flags);

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
sreNodeGetCellsFreeMemory(virConnectPtr conn,
                          unsigned long long *freemems,
                          int startCell, int maxCells)
{
    sreDriverPtr driver = conn->privateData;
    int cell;
    size_t i;
    int ret = -1;

    if (virNodeGetCellsFreeMemoryEnsureACL(conn) < 0)
        return -1;

    sreDriverLock(driver);
    if (startCell > driver->numCells) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("Range exceeds available cells"));
        goto cleanup;
    }

    for (cell = startCell, i = 0;
         (cell < driver->numCells && i < maxCells); ++cell, ++i) {
        freemems[i] = driver->cells[cell].mem;
    }
    ret = i;

  cleanup:
    sreDriverUnlock(driver);
    return ret;
}

static int
sreDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    sreDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = sreDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is already running"));
        goto cleanup;
    }

    if (virSREProcessStartDomain
        (domain->conn, driver, vm, (flags & VIR_DOMAIN_START_AUTODESTROY),
         VIR_DOMAIN_RUNNING_BOOTED)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "vm %s failed to launch error %s", vm->def->name,
                       virGetLastErrorMessage());
        goto cleanup;
    }
    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);

    return ret;
}

static int
sreDomainCreate(virDomainPtr domain)
{
    return sreDomainCreateWithFlags(domain, 0);
}

static int
sreDomainUndefineFlags(virDomainPtr domain, unsigned int flags)
{
    sreDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;

    (void) flags;
    int ret = -1;
    virSREDriverConfigPtr cfg;

    cfg = virSREDriverGetConfig(driver);

    if (!(vm = sreDomObjFromDomain(domain)))
        goto cleanup;

    if (sreDomainReleaseSRENetDev
        (driver, (sreDomainNamespaceDefPtr) vm->def->namespaceData,
         vm->def)) {
        VIR_WARN("domain netdev config failed");
        goto cleanup;
    }

    if (virDomainUndefineFlagsEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_UNDEFINED,
                                              VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);
    vm->hasManagedSave = false;

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(driver->domains, vm);
    }

    if (virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm) < 0)
        goto cleanup;

    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);

    sreObjectEventQueue(driver, event);
    return ret;
}

static int
sreDomainUndefine(virDomainPtr domain)
{
    return sreDomainUndefineFlags(domain, 0);
}


static int
sreDomainAttachDeviceFlags(virDomainPtr dom,
                           const char *xml, unsigned int flags)
{
    (void) dom;
    (void) xml;
    (void) flags;
    virDomainObjPtr vm = NULL;

    VIR_WARN("%s not supported", __FUNCTION__);

    if (!(vm = sreDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

  cleanup:
    virDomainObjEndAPI(&vm);
    return 0;
}

static int
sreDomainAttachDevice(virDomainPtr dom, const char *xml)
{
    return sreDomainAttachDeviceFlags(dom, xml, VIR_DOMAIN_AFFECT_LIVE);
}

static int
sreDomainUpdateDeviceFlags(virDomainPtr dom,
                           const char *xml, unsigned int flags)
{
    (void) dom;
    (void) xml;
    (void) flags;
    virDomainObjPtr vm = NULL;

    VIR_WARN("not supported");

    if (!(vm = sreDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

  cleanup:
    virDomainObjEndAPI(&vm);
    return 0;
}

static int
sreDomainDetachDeviceFlags(virDomainPtr dom,
                           const char *xml, unsigned int flags)
{
    sreDriverPtr driver = dom->conn->privateData;
    virSREDriverConfigPtr cfg = NULL;
    virDomainDeviceDefPtr dev = NULL, dev_copy = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = sreDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    cfg = virSREDriverGetConfig(driver);

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) &&
        !(flags & VIR_DOMAIN_AFFECT_LIVE))
        parse_flags |= VIR_DOMAIN_DEF_PARSE_INACTIVE;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             driver->caps, driver->xmlopt,
                                             NULL, parse_flags);
    if (dev == NULL)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG && flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy =
            virDomainDeviceDefCopy(dev, vm->def, driver->caps,
                                   driver->xmlopt,NULL);
        if (!dev_copy)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef =
            virDomainObjCopyPersistentDef(vm, driver->caps,
                                          driver->xmlopt,NULL);
        if (!vmdef)
            goto cleanup;

    }



    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (virDomainSaveConfig(cfg->configDir, driver->caps, vmdef) < 0)
            goto cleanup;

        virDomainObjAssignDef(vm, vmdef, false, NULL);
        vmdef = NULL;
    }

    ret = 0;

  cleanup:
    virObjectUnref(cfg);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    virDomainDefFree(vmdef);
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
sreDomainDetachDevice(virDomainPtr dom, const char *xml)
{
    return sreDomainDetachDeviceFlags(dom, xml, VIR_DOMAIN_AFFECT_LIVE);
}

static int
sreDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    virDomainObjPtr vm;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainGetAutostartEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;

  cleanup:
    virDomainObjEndAPI(&vm);
    return 0;
}


static int
sreDomainSetAutostart(virDomainPtr domain, int autostart)
{
    virDomainObjPtr vm;
    sreDriverPtr driver = domain->conn->privateData;
    virSREDriverConfigPtr cfg;

    cfg = virSREDriverGetConfig(driver);
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    if (!(vm = sreDomObjFromDomain(domain)))
        goto cleanup;


    configFile = virDomainConfigFile(cfg->configDir, vm->def->name);

    if (virDomainSetAutostartEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if (!
            (configFile =
             virDomainConfigFile(cfg->configDir, vm->def->name)))
            goto cleanup;

        if (!(autostartLink = virDomainConfigFile(cfg->autostartDir,
                                                  vm->def->name)))
            goto cleanup;

        if (autostart) {

            if (virFileMakePath(cfg->autostartDir) < 0) {
                virReportSystemError(errno,
                                     _
                                     ("cannot create autostart directory %s"),
                                     cfg->autostartDir);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _
                                     ("Failed to create symlink '%s to '%s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT
                && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%s'"),
                                     autostartLink);
                goto cleanup;
            }
        }
    }
    ret = 0;
    vm->autostart = autostart;

  cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);

    return ret;
}

static char *
sreDomainGetSchedulerType(virDomainPtr domain ATTRIBUTE_UNUSED,
                          int *nparams)
{
    char *type = NULL;
    virDomainObjPtr vm = NULL;

    if (nparams)
        *nparams = 1;

    if (!(vm = sreDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetSchedulerTypeEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    ignore_value(VIR_STRDUP(type, "fair"));

  cleanup:
    return type;
}

static int
sreDomainGetSchedulerParametersFlags(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int *nparams, unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainGetSchedulerParametersFlagsEnsureACL
        (domain->conn, vm->def) < 0)
        goto cleanup;

    if (virTypedParameterAssign(params, VIR_DOMAIN_SCHEDULER_WEIGHT,
                                VIR_TYPED_PARAM_UINT, 50) < 0)
        goto cleanup;

    /*params[0].value.ui = vm->weight; */

    *nparams = 1;
    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainGetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int *nparams)
{
    return sreDomainGetSchedulerParametersFlags(domain, params, nparams,
                                                0);
}

static int
sreDomainSetSchedulerParametersFlags(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int nparams, unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;
    size_t i;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_SCHEDULER_WEIGHT,
                               VIR_TYPED_PARAM_UINT, NULL) < 0)
        return -1;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainSetSchedulerParametersFlagsEnsureACL
        (domain->conn, vm->def, flags) < 0)
        goto cleanup;

    for (i = 0; i < nparams; i++) {
        if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_WEIGHT)) {
            /*vm->weight = params[i].value.ui; */
        }
    }

    ret = 0;

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainSetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int nparams)
{
    return sreDomainSetSchedulerParametersFlags(domain, params, nparams,
                                                0);
}

static int
sreDomainBlockStats(virDomainPtr domain,
                    const char *path, virDomainBlockStatsPtr stats)
{
    virDomainObjPtr vm = NULL;
    struct timeval tv;
    unsigned long long statbase = 0;
    int ret = -1;

    if (!*path) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("summary statistics are not supported yet"));
        return ret;
    }

    if (!(vm = sreDomObjFromDomain(domain)))
        return ret;

    if (virDomainBlockStatsEnsureACL(domain->conn, vm->def) < 0)
        goto error;

    if (virDomainDiskIndexByName(vm->def, path, false) < 0) {
        virReportError(VIR_ERR_INVALID_ARG, _("invalid path: %s"), path);
        goto error;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno, "%s", _("getting time of day"));
        goto error;
    }

    /* No significance to these numbers, just enough to mix it up */
    statbase = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;
    stats->rd_req = statbase / 10;
    stats->rd_bytes = statbase / 20;
    stats->wr_req = statbase / 30;
    stats->wr_bytes = statbase / 40;
    stats->errs = tv.tv_sec / 2;

    ret = 0;
  error:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainInterfaceStats(virDomainPtr domain,
                        const char *path, virDomainInterfaceStatsPtr stats)
{
    virDomainObjPtr vm;
    struct timeval tv;
    unsigned long long statbase;
    size_t i;
    int found = 0, ret = -1;

    if (!(vm = sreDomObjFromDomain(domain)))
        return -1;

    if (virDomainInterfaceStatsEnsureACL(domain->conn, vm->def) < 0)
        goto error;

    for (i = 0; i < vm->def->nnets; i++) {
        if (vm->def->nets[i]->ifname &&
            STREQ(vm->def->nets[i]->ifname, path)) {
            found = 1;
            break;
        }
    }

    if (!found) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path, '%s' is not a known interface"),
                       path);
        goto error;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno, "%s", _("getting time of day"));
        goto error;
    }

    /* No significance to these numbers, just enough to mix it up */
    statbase = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;
    stats->rx_bytes = statbase / 10;
    stats->rx_packets = statbase / 100;
    stats->rx_errs = tv.tv_sec / 1;
    stats->rx_drop = tv.tv_sec / 2;
    stats->tx_bytes = statbase / 20;
    stats->tx_packets = statbase / 110;
    stats->tx_errs = tv.tv_sec / 3;
    stats->tx_drop = tv.tv_sec / 4;

    ret = 0;
  error:
    virDomainObjEndAPI(&vm);
    return ret;
}



/* Domain event implementations */
static int
sreConnectDomainEventRegister(virConnectPtr conn,
                              virConnectDomainEventCallback callback,
                              void *opaque, virFreeCallback freecb)
{
    sreDriverPtr driver = conn->privateData;
    int ret = 0;

    if (virConnectDomainEventRegisterEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegister(conn, driver->eventState,
                                    callback, opaque, freecb) < 0)
        ret = -1;

    return ret;
}


static int
sreConnectDomainEventDeregister(virConnectPtr conn,
                                virConnectDomainEventCallback callback)
{
    sreDriverPtr driver = conn->privateData;
    int ret = 0;

    if (virConnectDomainEventDeregisterEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateDeregister(conn, driver->eventState,
                                      callback) < 0)
        ret = -1;

    return ret;
}


static int
sreConnectDomainEventRegisterAny(virConnectPtr conn,
                                 virDomainPtr dom,
                                 int eventID,
                                 virConnectDomainEventGenericCallback
                                 callback, void *opaque,
                                 virFreeCallback freecb)
{
    sreDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        goto cleanup;

    if (virDomainEventStateRegisterID(conn, driver->eventState,
                                      dom, eventID,
                                      callback, opaque, freecb, &ret) < 0)
        ret = -1;

  cleanup:
    return ret;
}

static int
sreConnectDomainEventDeregisterAny(virConnectPtr conn, int callbackID)
{
    sreDriverPtr driver = conn->privateData;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->eventState,
                                        callbackID, true) < 0)
        return -1;

    return 0;
}

static int
sreConnectListAllDomains(virConnectPtr conn,
                         virDomainPtr ** domains, unsigned int flags)
{
    sreDriverPtr driver = conn->privateData;
    int ret = -1;

    if (virConnectListAllDomainsEnsureACL(conn) < 0) {
        return ret;
    }

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    sreDomainObjListUpdateAll(driver->domains, driver);

    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 virConnectListAllDomainsCheckACL, flags);

    return ret;
}

static int
sreNodeGetCPUMap(virConnectPtr conn ATTRIBUTE_UNUSED,
                 unsigned char **cpumap,
                 unsigned int *online, unsigned int flags)
{

    virCheckFlags(0, -1);
    sre_sys_info_t sys_info;

    if (sreDomainUpdateSysInfoPortal(&sys_info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Failed to update sys_info");
        return -1;
    }

    if (virNodeGetCPUMapEnsureACL(conn) < 0)
        return -1;

    int map_size =
        (sys_info.cpu_info.total_cores / 8) +
        (sys_info.cpu_info.total_cores % 8 > 0);
    if (sys_info.cpu_info.total_cores > MAX_NUMBER_OF_CORES) {
        return -1;
    }

    if (cpumap) {
        if (VIR_ALLOC_N(*cpumap, map_size) < 0)
            return -1;
        memcpy(*cpumap, sys_info.cpu_info.core_mask, map_size);

    }

    if (online)
        *online = sys_info.cpu_info.avail_cores;

    return sys_info.cpu_info.total_cores;
}

static int
sreConnectGetCPUModelNames(virConnectPtr conn ATTRIBUTE_UNUSED,
                           const char *archName,
                           char ***models, unsigned int flags)
{
    virArch arch;

    virCheckFlags(0, -1);
    if (virConnectGetCPUModelNamesEnsureACL(conn) < 0)
        return -1;

    if (!(arch = virArchFromString(archName))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cannot find architecture %s"), archName);
        return -1;
    }

    return virCPUGetModels(arch, models);
}

static int
sreDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    sreDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE |
                  VIR_DOMAIN_SAVE_RUNNING | VIR_DOMAIN_SAVE_PAUSED, -1);

    if (!(vm = sreDomObjFromDomain(dom)))
        return -1;

    if (virDomainManagedSaveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot do managed save for transient domain"));
        goto cleanup;
    }

    sreShutdownDomainPortal(vm, VIR_DOMAIN_SHUTOFF_SAVED, FORCE_SHUTDOWN);
    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_SAVED);
    vm->hasManagedSave = true;

    ret = 0;
  cleanup:
    virDomainObjEndAPI(&vm);
    sreObjectEventQueue(driver, event);

    return ret;
}


static int
sreDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = sreDomObjFromDomain(dom)))
        return -1;

    if (virDomainHasManagedSaveImageEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->hasManagedSave;

  cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
sreDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm;

    virCheckFlags(0, -1);

    if (!(vm = sreDomObjFromDomain(dom)))
        return -1;

    if (virDomainManagedSaveRemoveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    vm->hasManagedSave = false;

  cleanup:
    virDomainObjEndAPI(&vm);
    return 0;
}

static char *
sreDomainSaveImageGetXMLDesc(virConnectPtr conn, const char *path,
                             unsigned int flags)
{
    sreDriverPtr driver = conn->privateData;
    char *ret = NULL;
    virDomainDefPtr def = NULL;
    int fd = -1;

    /* We only take subset of virDomainDefFormat flags.  */
    virCheckFlags(VIR_DOMAIN_XML_SECURE, NULL);

    fd = sreDomainSaveImageOpen(driver, path, &def, &ret,
                                false, NULL, false, flags);

    if (fd < 0)
        goto cleanup;

    if (virDomainSaveImageGetXMLDescEnsureACL(conn, def) < 0) {
        goto cleanup;
    }

  cleanup:
    virDomainDefFree(def);
    VIR_FORCE_CLOSE(fd);

    return ret;
}

static virHypervisorDriver sreHypervisorDriver = {
    .name = SRE_DRIVER_NAME,
    .connectOpen = sreConnectOpen,      /* 0.1.1 */
    .connectClose = sreConnectClose,    /* 0.1.1 */
    .connectGetVersion = sreConnectGetVersion,  /* 0.1.1 */
    .connectGetHostname = sreConnectGetHostname,        /* 0.6.3 */
    .connectGetMaxVcpus = sreConnectGetMaxVcpus,        /* 0.3.2 */
    .nodeGetInfo = sreNodeGetInfo,      /* 0.1.1 */
    .connectGetCapabilities = sreConnectGetCapabilities,        /* 0.2.1 */
    .connectListDomains = sreConnectListDomains,        /* 0.1.1 */
    .connectNumOfDomains = sreConnectNumOfDomains,      /* 0.1.1 */
    .connectListAllDomains = sreConnectListAllDomains,  /* 0.9.13 */
    .domainCreateXML = sreDomainCreateXML,      /* 0.1.4 */
    .domainLookupByID = sreDomainLookupByID,    /* 0.1.1 */
    .domainLookupByUUID = sreDomainLookupByUUID,        /* 0.1.1 */
    .domainLookupByName = sreDomainLookupByName,        /* 0.1.1 */
    .domainSuspend = sreDomainSuspend,  /* 0.1.1 */
    .domainResume = sreDomainResume,    /* 0.1.1 */
    .domainShutdown = sreDomainShutdown,        /* 0.1.1 */
    .domainShutdownFlags = sreDomainShutdownFlags,      /* 0.9.10 */
    .domainReboot = sreDomainReboot,    /* 0.1.1 */
    .domainDestroy = sreDomainDestroy,  /* 0.1.1 */
    .domainDestroyFlags = sreDomainDestroyFlags,        /* 0.1.1 */
    .domainGetOSType = sreDomainGetOSType,      /* 0.1.9 */
    .domainGetMaxMemory = sreDomainGetMaxMemory,        /* 0.1.4 */
    .domainSetMaxMemory = sreDomainSetMaxMemory,        /* 0.1.1 */
    .domainSetMemory = sreDomainSetMemory,      /* 0.1.4 */
    .domainGetInfo = sreDomainGetInfo,  /* 0.1.1 */
    .domainGetState = sreDomainGetState,        /* 0.9.2 */
    .domainSave = sreDomainSave,        /* 0.3.2 */
    .domainSaveFlags = sreDomainSaveFlags,      /* 0.9.4 */
    .domainRestore = sreDomainRestore,  /* 0.3.2 */
    .domainRestoreFlags = sreDomainRestoreFlags,        /* 0.9.4 */
    .domainSaveImageGetXMLDesc = sreDomainSaveImageGetXMLDesc,  /* 0.9.4 */
    .domainCoreDump = sreDomainCoreDump,        /* 0.3.2 */
    .domainCoreDumpWithFormat = sreDomainCoreDumpWithFormat,    /* 1.2.3 */
    .domainSetVcpus = sreDomainSetVcpus,        /* 0.1.4 */
    .domainSetVcpusFlags = sreDomainSetVcpusFlags,      /* 0.8.5 */
    .domainGetVcpusFlags = sreDomainGetVcpusFlags,      /* 0.8.5 */
    .domainPinVcpu = sreDomainPinVcpu,  /* 0.7.3 */
    .domainGetVcpus = sreDomainGetVcpus,        /* 0.7.3 */
    .domainGetVcpuPinInfo = sreDomainGetVcpuPinInfo,    /* 1.2.18 */
    .domainGetMaxVcpus = sreDomainGetMaxVcpus,  /* 0.7.3 */
    .domainGetXMLDesc = sreDomainGetXMLDesc,    /* 0.1.4 */
    .connectListDefinedDomains = sreConnectListDefinedDomains,  /* 0.1.11 */
    .connectNumOfDefinedDomains = sreConnectNumOfDefinedDomains,        /* 0.1.11 */
    .domainCreate = sreDomainCreate,    /* 0.1.11 */
    .domainCreateWithFlags = sreDomainCreateWithFlags,  /* 0.8.2 */
    .domainDefineXML = sreDomainDefineXML,      /* 0.1.11 */
    .domainDefineXMLFlags = sreDomainDefineXMLFlags,    /* 1.2.12 */
    .domainSaveImageDefineXML = sreDomainSaveImageDefineXML,    /* 0.9.4 */
    .domainUndefine = sreDomainUndefine,        /* 0.1.11 */
    .domainUndefineFlags = sreDomainUndefineFlags,      /* 0.9.4 */
    .domainAttachDevice = sreDomainAttachDevice,        /* 1.0.1 */
    .domainAttachDeviceFlags = sreDomainAttachDeviceFlags,      /* 1.0.1 */
    .domainDetachDevice = sreDomainDetachDevice,        /* 1.0.1 */
    .domainDetachDeviceFlags = sreDomainDetachDeviceFlags,      /* 1.0.1 */
    .domainUpdateDeviceFlags = sreDomainUpdateDeviceFlags,      /* 1.0.1 */
    .domainGetAutostart = sreDomainGetAutostart,        /* 0.3.2 */
    .domainSetAutostart = sreDomainSetAutostart,        /* 0.3.2 */
    .domainGetSchedulerType = sreDomainGetSchedulerType,        /* 0.3.2 */
    .domainGetSchedulerParameters = sreDomainGetSchedulerParameters,    /* 0.3.2 */
    .domainSetSchedulerParameters = sreDomainSetSchedulerParameters,    /* 0.3.2 */
    .domainSetSchedulerParametersFlags = sreDomainSetSchedulerParametersFlags,  /* 0.9.2 */
    .domainBlockStats = sreDomainBlockStats,    /* 0.7.0 */
    .domainInterfaceStats = sreDomainInterfaceStats,    /* 0.7.0 */
    .nodeGetCellsFreeMemory = sreNodeGetCellsFreeMemory,        /* 0.4.2 */
    .connectDomainEventRegister = sreConnectDomainEventRegister,        /* 0.6.0 */
    .connectDomainEventDeregister = sreConnectDomainEventDeregister,    /* 0.6.0 */
    .connectIsEncrypted = sreConnectIsEncrypted,        /* 0.7.3 */
    .connectIsSecure = sreConnectIsSecure,      /* 0.7.3 */
    .domainIsActive = sreDomainIsActive,        /* 0.7.3 */
    .domainIsPersistent = sreDomainIsPersistent,        /* 0.7.3 */
    .domainIsUpdated = sreDomainIsUpdated,      /* 0.8.6 */
    .connectDomainEventRegisterAny = sreConnectDomainEventRegisterAny,  /* 0.8.0 */
    .connectDomainEventDeregisterAny = sreConnectDomainEventDeregisterAny,      /* 0.8.0 */
    .connectIsAlive = sreConnectIsAlive,        /* 0.9.8 */
    .nodeGetCPUMap = sreNodeGetCPUMap,  /* 1.0.0 */
    .domainGetMetadata = sreDomainGetMetadata,  /* 1.1.3 */
    .domainSetMetadata = sreDomainSetMetadata,  /* 1.1.3 */
    .connectGetCPUModelNames = sreConnectGetCPUModelNames,      /* 1.1.3 */

    .domainManagedSave = sreDomainManagedSave,  /* 1.1.4 */
    .domainHasManagedSaveImage = sreDomainHasManagedSaveImage,  /* 1.1.4 */
    .domainManagedSaveRemove = sreDomainManagedSaveRemove,      /* 1.1.4 */


    .connectBaselineCPU = sreConnectBaselineCPU,        /* 1.2.0 */
};

static virConnectDriver sreConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]) {"sre", NULL},
    .hypervisorDriver = &sreHypervisorDriver
};

/* static virConnectDriver sreConnectDriver = {
    .hypervisorDriver = &sreHypervisorDriver,
    .interfaceDriver = NULL,
    .networkDriver = NULL, //&sreNetworkDriver,
    .nodeDeviceDriver = NULL,//&sreNodeDeviceDriver,
    .nwfilterDriver = NULL,
    .secretDriver = NULL,
    .storageDriver = NULL, //&sreStorageDriver,
}; */


//SRE INIT CALLBACKS

static int
  sreStateCleanup(void);

static int
sreDomainFindMaxID(virDomainObjPtr vm, void *data)
{
    int *driver_maxid = data;

    if (vm->def->id > *driver_maxid)
        *driver_maxid = vm->def->id;

    return 0;
}

int
sreDriverAllocateID(sreDriverPtr driver)
{
    return virAtomicIntInc(&driver->lastvmid);
}

/**
 * sreStateInitialize:
 *
 * Initialization function for the sre daemon
 */
static bool driver_init_status = false;

static int
sreStateInitialize(bool privileged,
                   virStateInhibitCallback callback, void *opaque)
{
    driver_init_status = true;
    char *driverConf = NULL;
    virSREDriverConfigPtr cfg;

    if (!privileged) {
        VIR_INFO("Not running privileged, disabling driver");
        return 0;
    }
    char *policy_api = virFindFileInPath(POLICY_API_PATH);

    if (policy_api == NULL) {
        VIR_INFO("SRE policy tool not found in '%s'.", POLICY_API_PATH);
        return 0;
    }
    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */
    virMutexLock(&defaultLock);
    if (num_default_connections++ == 0) {
        sre_default_driver = sreDriverNew();
        if (!sre_default_driver)
            goto error;

        sre_default_driver->caps = sreBuildCapabilities();

        if (VIR_STRNDUP
            (sre_default_driver->sre_run_path, policy_api,
             sizeof(POLICY_API_PATH)) < 0)
            goto error;

        sre_default_driver->sre_net_device_list = sreProbeNetDevices();
    }
    VIR_FREE(policy_api);
    sre_default_driver->inhibitCallback = callback;
    sre_default_driver->inhibitOpaque = opaque;
    if (!sre_default_driver) {
        goto error;
    }

    virMutexUnlock(&defaultLock);
    /* read the host sysinfo */
    if (privileged)
        sre_default_driver->hostsysinfo = virSysinfoRead();

    if (!sre_default_driver->config) {
        sre_default_driver->config = virSREDriverConfigNew(privileged);
        if (!sre_default_driver->config)
            goto error;
    }
    cfg = sre_default_driver->config;

    if (virAsprintf(&driverConf, "%s/sre.conf", cfg->configBaseDir) < 0)
        goto error;

    if (virSREDriverConfigLoadFile(cfg, driverConf) < 0)
        goto error;
    VIR_FREE(driverConf);

    if (virFileMakePath(cfg->stateDir) < 0) {
        virReportSystemError(errno, _("Failed to create state dir %s"),
                             cfg->stateDir);
        goto error;
    }

    if (virFileMakePath(cfg->libDir) < 0) {
        virReportSystemError(errno, _("Failed to create lib dir %s"),
                             cfg->libDir);
        goto error;
    }

    if (virFileMakePath(cfg->cacheDir) < 0) {
        virReportSystemError(errno, _("Failed to create cache dir %s"),
                             cfg->cacheDir);
        goto error;
    }

    if (virFileMakePath(cfg->saveDir) < 0) {
        virReportSystemError(errno, _("Failed to create save dir %s"),
                             cfg->saveDir);
        goto error;
    }

    if (virFileMakePath(cfg->snapshotDir) < 0) {
        virReportSystemError(errno, _("Failed to create save dir %s"),
                             cfg->snapshotDir);
        goto error;
    }

    if (virFileMakePath(cfg->autoDumpPath) < 0) {
        virReportSystemError(errno, _("Failed to create dump dir %s"),
                             cfg->autoDumpPath);
        goto error;
    }

    if (virFileMakePath(cfg->channelTargetDir) < 0) {
        virReportSystemError(errno,
                             _("Failed to create channel target dir %s"),
                             cfg->channelTargetDir);
        goto error;
    }

    if (virFileMakePath(cfg->nvramDir) < 0) {
        virReportSystemError(errno, _("Failed to create nvram dir %s"),
                             cfg->nvramDir);
        goto error;
    }

    if (!(sre_default_driver->lockManager =
          virLockManagerPluginNew(cfg->lockManagerName ?
                                  cfg->lockManagerName : "nop",
                                  "sre", cfg->configBaseDir, 0)))
        goto error;

    /* Allocate bitmap for remote display port reservations. We cannot
     * do this before the config is loaded properly, since the port
     * numbers are configurable now */
#if 0
    if ((sre_default_driver->remotePorts =
         virPortAllocatorRangeNew(_("display"),
                                  cfg->remotePortMin,
                                  cfg->remotePortMax, 0)) == NULL)
        goto error;

    if ((sre_default_driver->webSocketPorts =
         virPortAllocatorRangeNew(_("webSocket"),
                                  cfg->webSocketPortMin,
                                  cfg->webSocketPortMax, 0)) == NULL)
        goto error;

#endif

    if (!(sre_default_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto error;

    if (!
        (sre_default_driver->sharedDevices =
         virHashCreate(30, sreSharedDeviceEntryFree)))
        goto error;

    if (privileged) {
        char *channeldir;

        if (chown(cfg->libDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("unable to set ownership of '%s' to user %d:%d"),
                                 cfg->libDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }

        if (chown(cfg->cacheDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("unable to set ownership of '%s' to %d:%d"),
                                 cfg->cacheDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }

        if (chown(cfg->saveDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("unable to set ownership of '%s' to %d:%d"),
                                 cfg->saveDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }

        if (chown(cfg->snapshotDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("unable to set ownership of '%s' to %d:%d"),
                                 cfg->snapshotDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }

        if (chown(cfg->autoDumpPath, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("unable to set ownership of '%s' to %d:%d"),
                                 cfg->autoDumpPath, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }

        if (!(channeldir = mdir_name(cfg->channelTargetDir))) {
            virReportOOMError();
            goto error;
        }

        if (chown(channeldir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("unable to set ownership of '%s' to %d:%d"),
                                 channeldir, (int) cfg->user,
                                 (int) cfg->group);
            VIR_FREE(channeldir);
            goto error;
        }

        VIR_FREE(channeldir);
        if (chown(cfg->channelTargetDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("unable to set ownership of '%s' to %d:%d"),
                                 cfg->channelTargetDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }

        if (chown(cfg->nvramDir, cfg->user, cfg->group) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("unable to set ownership of '%s' to %d:%d"),
                                 cfg->nvramDir, (int) cfg->user,
                                 (int) cfg->group);
            goto error;
        }
    }

    if (!(sre_default_driver->closeCallbacks = virCloseCallbacksNew()))
        goto error;
    /* TODO ADDRESS ISSUES WITH /var/run on reconnect to domains when libvirt can handle this state 
     * (reconnect to running domains when libvirtd is restarted */
    // /* Get all the running persistent or transient configs first */
    // if (virDomainObjListLoadAllConfigs(sre_default_driver->domains,
    //                                    cfg->stateDir,
    //                                    NULL, 1,
    //                                    sre_default_driver->caps,
    //                                    sre_default_driver->xmlopt,
    //                                    NULL, NULL) < 0)
    //     goto error;

    /* find the maximum ID from active and transient configs to initialize
     * the driver with. This is to avoid race between autostart and reconnect
     * threads */
    virDomainObjListForEach(sre_default_driver->domains,
                            sreDomainFindMaxID,
                            &sre_default_driver->lastvmid);


    /* Then inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(sre_default_driver->domains,
                                       cfg->configDir,
                                       cfg->autostartDir, 0,
                                       sre_default_driver->caps,
                                       sre_default_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto error;

    return 0;

  error:
    VIR_FREE(driverConf);
    sreStateCleanup();
    return -1;
}

/**
 * sreStateCleanup:
 *
 * Shutdown the sre daemon, it will stop all active domains and networks
 */
static int
sreStateCleanup(void)
{
    if (!sre_default_driver) {
        VIR_WARN("No driver");
        return -1;
    }

/* stop all domains upon stopping driver to avoid stateful tracking issues */
    sreStateStop();

    virObjectUnref(sre_default_driver->config);
    virObjectUnref(sre_default_driver->hostdevMgr);
    virHashFree(sre_default_driver->sharedDevices);
    virObjectUnref(sre_default_driver->caps);
    virObjectUnref(sre_default_driver->domains);
    virObjectUnref(sre_default_driver->xmlopt);

    virSysinfoDefFree(sre_default_driver->hostsysinfo);

    virObjectUnref(sre_default_driver->closeCallbacks);


    virObjectUnref(sre_default_driver->securityManager);

    //ebtablesContextFree(sre_default_driver->ebtables);

    /* Free domain callback list */
    virObjectUnref(sre_default_driver->eventState);

    virLockManagerPluginUnref(sre_default_driver->lockManager);

    virMutexDestroy(&sre_default_driver->lock);
    virObjectUnref(sre_default_driver->sre_net_device_list);
    VIR_FREE(sre_default_driver->sre_run_path);
    VIR_FREE(sre_default_driver);

    return 0;
}



/**
 * sreStateAutoStart:
 *
 * Function to auto start the SRE domains
 */
static void
sreStateAutoStart(void)
{
    if (!sre_default_driver)
        return;

    virSREProcessAutostartAll(sre_default_driver);
}

// static void sreNotifyLoadDomain(virDomainObjPtr vm, int newVM, void *opaque)
// {
//     sreDriverPtr driver = opaque;

//     if (newVM) {
//         virObjectEventPtr event =
//             virDomainEventLifecycleNewFromObj(vm,
//                                      VIR_DOMAIN_EVENT_DEFINED,
//                                      VIR_DOMAIN_EVENT_DEFINED_ADDED);
//         if (event)
//             virObjectEventStateQueue(driver->eventState, event);
//     }
// }

/**
 * sreStateReload:
 *
 * Function to restart the sre daemon, it will recheck the configuration
 * files and update its state and the networking
 */
static int
sreStateReload(void)
{
//     virSREDriverConfigPtr cfg = NULL;
//     virCapsPtr caps = NULL;

//     if (!sre_default_driver)
//         return 0;

//     if (!(caps = virSREDriverGetCapabilities(sre_default_driver, false)))
//         goto cleanup;

//     cfg = virSREDriverGetConfig(sre_default_driver);
//     virDomainObjListLoadAllConfigs(sre_default_driver->domains,
//                                    cfg->configDir,
//                                    cfg->autostartDir, 0,
//                                    caps, sre_default_driver->xmlopt,
//                                    sreNotifyLoadDomain, sre_default_driver);
//  cleanup:
//     virObjectUnref(cfg);
//     virObjectUnref(caps);
    return 0;
}

/*
 * sreStateStop:
 *
 * Save any VMs in preparation for shutdown
 *
 */
static int
sreStateStop(void)
{
    int ret = -1;
    virConnectPtr conn;
    int numInactiveDomains = 0, numRunningDomains = 0;
    size_t i;
    virDomainPtr *running_domains = NULL;
    virDomainPtr *inactive_domains = NULL;
    virSREDriverConfigPtr cfg = virSREDriverGetConfig(sre_default_driver);

    if (!(conn = virConnectOpen(cfg->uri)))
        goto cleanup;

    if ((numInactiveDomains = virConnectListAllDomains(conn,
                                                       &inactive_domains,
                                                       VIR_CONNECT_LIST_DOMAINS_INACTIVE))
        < 0)
        goto cleanup;
    if ((numRunningDomains = virConnectListAllDomains(conn,
                                                      &running_domains,
                                                      VIR_CONNECT_LIST_DOMAINS_ACTIVE))
        < 0)
        goto cleanup;

    for (i = 0; i < numRunningDomains; i++) {
        virDomainShutdown(running_domains[i]);
        virDomainObjPtr vm;

        if (!(vm = sreDomObjFromDomain(running_domains[i])))
            goto cleanup;
        if (sreDomainReleaseSRENetDev
            (sre_default_driver,
             (sreDomainNamespaceDefPtr) vm->def->namespaceData, vm->def)) {
            VIR_WARN("domain netdev config failed");
            goto cleanup;
        }
        virDomainObjEndAPI(&vm);
    }

    for (i = 0; i < numInactiveDomains; i++) {
        virDomainObjPtr vm;

        if (!(vm = sreDomObjFromDomain(inactive_domains[i])))
            goto cleanup;
        if (sreDomainReleaseSRENetDev
            (sre_default_driver,
             (sreDomainNamespaceDefPtr) vm->def->namespaceData, vm->def)) {
            VIR_WARN("domain netdev config failed");
            goto cleanup;
        }
        virDomainObjEndAPI(&vm);
    }


  cleanup:
    if (inactive_domains) {
        for (i = 0; i < numInactiveDomains; i++) {
            if (virObjectUnref(inactive_domains[i])) {
                VIR_FREE(inactive_domains[i]);
            }
        }
        VIR_FREE(inactive_domains);
    }

    if (running_domains) {
        for (i = 0; i < numRunningDomains; i++) {
            if (virObjectUnref(running_domains[i])) {
                VIR_FREE(running_domains[i]);
            }
        }
        VIR_FREE(running_domains);
    }
    virObjectUnref(conn);
    virObjectUnref(cfg);

    return ret;
}

static virStateDriver sreStateDriver = {
    .name = SRE_DRIVER_NAME,
    .stateInitialize = sreStateInitialize,
    .stateAutoStart = sreStateAutoStart,
    .stateCleanup = sreStateCleanup,
    .stateReload = sreStateReload,
    .stateStop = sreStateStop,
};

/**
 * sreRegister:
 *
 * Registers the sre driver
 */
int
sreRegister(void)
{
    if (virRegisterConnectDriver(&sreConnectDriver, true) < 0) {
        return -1;
    }

    if (virRegisterStateDriver(&sreStateDriver) < 0) {
        return -1;
    }

    return 0;
}
