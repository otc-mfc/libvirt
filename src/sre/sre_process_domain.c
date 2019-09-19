/*
 * sre_driver.c: A SRE driver for libvirt
 *
 */
#include <config.h>

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "sre_process_domain.h"
#include "sre_domain.h"
#include "datatypes.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virnetdev.h"
#include "virnetdevveth.h"
#include "virnetdevbridge.h"
#include "virnetdevopenvswitch.h"
#include "virtime.h"
#include "domain_nwfilter.h"
#include "viralloc.h"
#include "domain_audit.h"
#include "virerror.h"
#include "virlog.h"
#include "vircommand.h"
#include "virhook.h"
#include "virstring.h"
#include "viratomic.h"
#include "virprocess.h"
#include "virsystemd.h"
#include "netdev_bandwidth_conf.h"
#include "sre_domain_portal.h"
#include "sre_driver.h"

#define VIR_FROM_THIS VIR_FROM_SRE
VIR_LOG_INIT("sre.sre_process_domain");
#define START_POSTFIX ": starting up\n"

static int
virSREProcessReadLogOutput(virDomainObjPtr vm,
                           char *logfile,
                           off_t pos,
                           char *buf,
                           size_t buflen);
static void virSREProcessCleanupDomain(sreDriverPtr driver,
                            virDomainObjPtr vm, 
                            virDomainShutoffReason reason);
static virCommandPtr
virSREProcessBuildControllerCmd(sreDriverPtr driver,
                                virDomainObjPtr vm,
                                int *ttyFDs,
                                size_t nttyFDs,
                                int handshakefd,
                                int * const logfd,
                                const char *pidfile);
static void
sreProcessAutoDestroy(virDomainObjPtr dom,
                      virConnectPtr conn,
                      void *opaque);

static int virSREProcessStopDomain(sreDriverPtr driver,
                      virDomainObjPtr vm,
                      virDomainShutoffReason reason)
{
    virSREDomainObjPrivatePtr priv;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);
    priv = vm->privateData;


    /* If the SRE domain is suspended we send all processes a SIGKILL
     * and thaw them. Upon wakeup the process sees the pending signal
     * and dies immediately. It is guaranteed that priv->cgroup != NULL
     * here because the domain has aleady been suspended using the
     */
    priv->wantReboot = false;
    if (vm->pid > 0) {
        /* try cleaning up the libvirt_sre process */
        if (virProcessKillPainfully(vm->pid, true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Processes %d refused to die"), (int)vm->pid);
            return -1;
        }
    }
    
    
    virSREProcessCleanupDomain(driver, vm, VIR_DOMAIN_EVENT_STOPPED_FAILED);
    return 0;
}

/*
 * Precondition: driver is locked
 */
#define MAX_REBOOT_WAIT_LOOPS 6
int
virSREProcessRebootDomain(sreDriverPtr driver,
                    virDomainObjPtr vm,
                    shutdown_mode_t mode)
{
    virConnectPtr conn = virCloseCallbacksGetConn(driver->closeCallbacks, vm);
    int reason = vm->state.reason;
    bool autodestroy = false;
    int ret = -1;
    virDomainDefPtr savedDef;
    virSREDomainObjPrivatePtr priv; 

    VIR_DEBUG("Faking reboot");

    if (conn) {
        virObjectRef(conn);
        autodestroy = true;
    } else {
        conn = virConnectOpen("sre:///system");
        /* Ignoring NULL conn which is mostly harmless here */
    }

    /* In a reboot scenario, we need to make sure we continue
     * to use the current 'def', and not switch to 'newDef'.
     * So temporarily hide the newDef and then reinstate it
     */
    savedDef = vm->newDef;
    vm->newDef = NULL;
    priv =  vm->privateData;
    //shutdown vm with destroy packet
    virDomainState state = virDomainObjGetState(vm,NULL);
    if(state == VIR_DOMAIN_RUNNING )
    {
        if( sreShutdownDomainPortal(vm,VIR_DOMAIN_SHUTOFF_SHUTDOWN,mode)){
            virReportError(VIR_ERR_CALL_FAILED, "%s",_("VM Shutdown failed"));
            goto cleanup;
        }
        int loops =0;
        while(loops < MAX_REBOOT_WAIT_LOOPS)
        {
            if( virDomainObjGetState(vm,NULL) != VIR_DOMAIN_RUNNING)
            {
                break;
            }
            VIR_DEBUG("Waiting for shutdown\n");
            loops++;
            sleep(5);
        };
        
        if(loops == MAX_REBOOT_WAIT_LOOPS)
        {
            priv->wantReboot = true;
            VIR_WARN("VM Wait for shutdown timed out\n");
            goto cleanup;
        }
        priv->wantReboot = false;
        
        
        virSREProcessStopDomain(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        vm->newDef = savedDef;
    }

    if (virSREProcessStartDomain(conn, driver, vm,
                           autodestroy, reason) < 0) {
        VIR_WARN("Unable to handle reboot of vm %s",
                 vm->def->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virObjectUnref(conn);
    return ret;
}

extern sreDriverPtr sre_default_driver;
static void virSREProcessMonitorEOFNotify(virSREMonitorPtr mon,
                                          virDomainObjPtr vm)
{
    sreDriverPtr driver = sre_default_driver;
    virObjectEventPtr event = NULL;
    virSREDomainObjPrivatePtr priv;

    VIR_DEBUG("mon=%p vm=%p", mon, vm);

    virObjectLock(vm);

    priv = vm->privateData;
    if (!priv->wantReboot) {
        virSREProcessStopDomain(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        if (!priv->doneStopEvent) {
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             priv->stopReason);
            virDomainAuditStop(vm, "shutdown");
        } 
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
    } else {
        int ret = virSREProcessRebootDomain(driver, vm,FORCE_SHUTDOWN);
        virDomainAuditStop(vm, "reboot");
        virDomainAuditStart(vm, "reboot", ret == 0);
        if (ret == 0) {
            event = virDomainEventRebootNewFromObj(vm);
        } else {
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             priv->stopReason);
            if (!vm->persistent)
                virDomainObjListRemove(driver->domains, vm);
        }
    }

    /* NB: virSREProcessConnectMonitor will perform the virObjectRef(vm)
     * before adding monitorCallbacks. Since we are now done with the @vm
     * we can Unref/Unlock */
    virObjectUnref(vm);
    virDomainObjEndAPI(&vm);
    if(!driver->eventState )
            VIR_DEBUG("eventqueue is null");
        return;
    if(!event )
            VIR_DEBUG("event is null");
        return;

    virObjectEventStateQueue(driver->eventState, event);
}

static void virSREProcessMonitorStartNotify(virSREMonitorPtr mon ATTRIBUTE_UNUSED,
                                           int domain_id,
                                           virDomainObjPtr vm)
{
    virObjectLock(vm);

    int test = 0;
    virDomainAuditInit(vm, domain_id, test);

    virObjectUnlock(vm);
}

static void virSREProcessMonitorPolicyNotify(virSREMonitorPtr mon ATTRIBUTE_UNUSED,
                                           int domain_id,
                                           char *  message,
                                           int  message_len,
                                           virDomainObjPtr vm)
{
    /* controller logs policy events, any additional actions 
         for policy violations should be handled here */ 
    (void)message;
    (void)message_len;
    (void)domain_id;
    sreDriverPtr sre_driver = sre_default_driver;
    virSREDriverConfigPtr cfg = virSREDriverGetConfig(sre_driver);

    virObjectLock(vm);

    virObjectUnlock(vm);
    virObjectUnref(cfg);
}



static void virSREProcessMonitorShutdownNotify(virSREMonitorPtr mon ATTRIBUTE_UNUSED,
                                           virSREMonitorShutdownStatus status,
                                           virDomainObjPtr vm)
{
    virSREDomainObjPrivatePtr priv = vm->privateData;
    sreDriverPtr driver = sre_default_driver;
    virDomainShutoffReason shutdownReason = VIR_DOMAIN_SHUTOFF_UNKNOWN;

    switch (status) {
    case VIR_SRE_MONITOR_SHUTDOWN_STATUS_SHUTDOWN:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
        shutdownReason = VIR_DOMAIN_SHUTOFF_SHUTDOWN;
        break;
    case VIR_SRE_MONITOR_SHUTDOWN_STATUS_ERROR:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
        shutdownReason = VIR_DOMAIN_SHUTOFF_FAILED;
        break;
    case VIR_SRE_MONITOR_SHUTDOWN_STATUS_REBOOT:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
        priv->wantReboot = true;
        shutdownReason = VIR_DOMAIN_SHUTOFF_SHUTDOWN;
        break;
    case VIR_SRE_MONITOR_SHUTDOWN_STATUS_POLICY:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_CRASHED;
        shutdownReason = VIR_DOMAIN_SHUTOFF_CRASHED;
        break;
    default:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
        break;
    }
    if(sreDomainReleaseSRENetDev(driver, (sreDomainNamespaceDefPtr)vm->def->namespaceData, vm->def)) {
            VIR_WARN("domain netdev removal failed");
    }
        
    virObjectEventPtr event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             priv->stopReason);
    virObjectEventStateQueue(driver->eventState, event);
    virDomainObjSetState(vm,VIR_DOMAIN_SHUTOFF,shutdownReason);
    virDomainAuditStop(vm, "shutdown");
    priv->doneStopEvent = true;

}
static virSREMonitorCallbacks monitorCallbacks = {
    .eofNotify = virSREProcessMonitorEOFNotify,
    .shutdownNotify = virSREProcessMonitorShutdownNotify,
    .startNotify = virSREProcessMonitorStartNotify,
    .policyNotify = virSREProcessMonitorPolicyNotify,
};


static virSREMonitorPtr virSREProcessConnectMonitor(sreDriverPtr driver,
                                                    virDomainObjPtr vm)
{
    virSREMonitorPtr monitor = NULL;
    virSREDriverConfigPtr cfg = virSREDriverGetConfig(driver);

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted while the monitor is active. This will be unreffed
     * during EOFNotify processing. */
    virObjectRef(vm);

    monitor = virSREMonitorNew(vm, cfg->stateDir, &monitorCallbacks);

    if (monitor == NULL)
        virObjectUnref(vm);

    virObjectUnref(cfg);
    return monitor;
}

static int
virSREProcessAutostartDomain(virDomainObjPtr vm,
                             void *opaque)
{
    const struct virSREProcessAutostartData *data = opaque;
    int ret = 0;

    virObjectLock(vm);
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        ret = virSREProcessStartDomain(data->conn, data->driver, vm,
                                 false,
                                 VIR_DOMAIN_RUNNING_BOOTED);
        virDomainAuditStart(vm, "booted", ret >= 0);
        if (ret < 0) {
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      virGetLastErrorMessage());
        } else {
            virObjectEventPtr event =
                virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
            virObjectEventStateQueue(data->driver->eventState, event);
        }
    }
    virObjectUnlock(vm);
    return ret;
}


void
virSREProcessAutostartAll(sreDriverPtr driver)
{
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen("sre:///system");
    /* Ignoring NULL conn which is mostly harmless here */

    struct virSREProcessAutostartData data = { driver, conn };

    virDomainObjListForEach(driver->domains,
                            virSREProcessAutostartDomain,
                            &data);

    virObjectUnref(conn);
}


static void
sreProcessAutoDestroy(virDomainObjPtr dom,
                      virConnectPtr conn,
                      void *opaque)
{
    sreDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virSREDomainObjPrivatePtr priv;
    (void)conn;

    priv = dom->privateData;
    virSREProcessStopDomain(driver, dom, VIR_DOMAIN_SHUTOFF_DESTROYED);
    virDomainAuditStop(dom, "destroyed");
    event = virDomainEventLifecycleNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    priv->doneStopEvent = true;

    if (!dom->persistent)
        virDomainObjListRemove(driver->domains, dom);

    virObjectEventStateQueue(driver->eventState, event);
}


int virSREProcessStartDomain(virConnectPtr conn,
                       sreDriverPtr  driver,
                       virDomainObjPtr vm,
                       bool autoDestroy,
                       virDomainRunningReason reason)
{
    int rc = -1, r;
    size_t nttyFDs = 0;
    int *ttyFDs = NULL;
    size_t i;
    char *logfile = NULL;
    int logfd = -1;
    size_t nveths = 0;
    char **veths = NULL;
    int handshakefds[2] = { -1, -1 };
    off_t pos = -1;
    char ebuf[1024];
    char *timestamp;
    virCommandPtr cmd = NULL;
    virSREDomainObjPrivatePtr priv = vm->privateData;
    virCapsPtr caps = NULL;
    virErrorPtr err = NULL;
    virSREDriverConfigPtr cfg = virSREDriverGetConfig(driver);
    int status;
    char *pidfile = NULL;
    int n_ptys = 0; 
    int pty_idx = 0;
#ifdef VUB_SUPPORT
    char *vub_path = NULL; 
#endif

    if (virFileMakePath(cfg->logDir) < 0) {
        virReportSystemError(errno,
                             _("Cannot create log directory '%s'"),
                             cfg->logDir);
        return -1;
    }

    /*  this code origionally used consoles element but due to some backwards
    see comment in virDomainDefAddConsoleCompat " Some really crazy backcompat stuff for consoles" 
    using serials avoids dealing with this 
    The problematic behavior is */ 

    for (i = 0; i < vm->def->nserials; i++) {
        if (vm->def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_PTY) {  
            n_ptys++;
        }
    }
    if (virAsprintf(&logfile, "%s/%s-controller.log",
                    cfg->logDir, vm->def->name) < 0)
        goto cleanup;

    if (!(pidfile = virPidFileBuildPath(cfg->stateDir, vm->def->name)))
        goto cleanup;

    nttyFDs = n_ptys;
    if (VIR_ALLOC_N(ttyFDs, nttyFDs) < 0)
        goto cleanup;
    for (i = 0; i < nttyFDs; i++) {
        ttyFDs[i] = -1;
    }
#ifdef VUB_SUPPORT
    vub_path = virFindFileInPath(SRE_UART_BRIDGE_PATH);
    if( nttyFDs > 0 && vub_path == NULL ) {
        VIR_WARN("SRE uart bridge device/driver not loaded vub console unavailable '%s'.", SRE_UART_BRIDGE_PATH);
        goto cleanup;
    }
#endif

    /* If you are using a SecurityDriver with dynamic labelling,
       then generate a security label for isolation */
    VIR_DEBUG("Generating domain security label (if required)");

    if (vm->def->nseclabels &&
        vm->def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_DEFAULT)
        vm->def->seclabels[0]->type = VIR_DOMAIN_SECLABEL_NONE;

    for (i = 0; i < vm->def->nserials; i++) {
        char *ttyPath;
        if (vm->def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_PTY) { 

            if (virFileOpenTty(&ttyFDs[pty_idx], &ttyPath, 1) < 0) {
                virReportSystemError(errno, "%s",
                                    _("Failed to allocate tty process_domain"));
                goto cleanup;
            }

            VIR_FREE(vm->def->serials[i]->source->data.file.path);
            vm->def->serials[i]->source->data.file.path = ttyPath;

            VIR_FREE(vm->def->serials[i]->info.alias);
            if (virAsprintf(&vm->def->serials[i]->info.alias, "console%zu", i) < 0)
                goto cleanup;
            pty_idx++;
        }
    }

    if ((logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
             S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Failed to open '%s'"),
                             logfile);
        goto cleanup;
    }

    if (pipe(handshakefds) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create pipe"));
        goto cleanup;
    }

    if (!(cmd = virSREProcessBuildControllerCmd(driver,
                                                vm,
                                                ttyFDs, nttyFDs,
                                                handshakefds[1],
                                                &logfd,
                                                pidfile)))
        goto cleanup;

    /* now that we know it is about to start call the hook if present */
    /* Log timestamp */
    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;
    if (safewrite(logfd, timestamp, strlen(timestamp)) < 0 ||
        safewrite(logfd, START_POSTFIX, strlen(START_POSTFIX)) < 0)
        VIR_WARN("Unable to write timestamp to logfile: %s",
                 virStrerror(errno, ebuf, sizeof(ebuf)));
                 
    VIR_FREE(timestamp);

    /* Log generated command line */
    virCommandWriteArgLog(cmd, logfd);
    if ((pos = lseek(logfd, 0, SEEK_END)) < 0)
        VIR_WARN("Unable to seek to end of logfile: %s",
                 virStrerror(errno, ebuf, sizeof(ebuf)));

    //release old sre netdev as check
    if(sreDomainReleaseSRENetDev(driver,(sreDomainNamespaceDefPtr)vm->def->namespaceData,vm->def))
    {
         VIR_WARN("domain release netdev config failed");
         goto cleanup;
    }

    //reclaim sre netdev
    if (sreDomainAddSRENetDev(driver, (sreDomainNamespaceDefPtr)vm->def->namespaceData, vm->def)) {
        VIR_WARN("domain add netdev config failed");
        goto cleanup;
    }
    
    VIR_DEBUG("Launching Domain");
    
    //launch domain
    if( (rc = sreLaunchDomainPortal(vm,driver)) ) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Failed to launch VM '%s': %s"),
                    vm->def->name, virGetLastErrorMessage());
        
        goto cleanup_netdev;
    }
    else 
        VIR_DEBUG("Launched domain %s id %d",vm->def->name, vm->def->id);

    VIR_DEBUG("Launching Controller Process");
    virCommandRawStatus(cmd);
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup_netdev;

    if (status != 0) {
        if (virSREProcessReadLogOutput(vm, logfile, pos, ebuf,
                                       sizeof(ebuf)) <= 0) {
            if (WIFEXITED(status))
                snprintf(ebuf, sizeof(ebuf), _("unexpected exit status %d"),
                         WEXITSTATUS(status));
            else
                snprintf(ebuf, sizeof(ebuf), "%s", _("terminated abnormally"));
        }
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("controller failed to start: %s"), ebuf);
        goto cleanup_netdev;
    }

    /* It has started running, so get its pid */
    if ((r = virPidFileReadPath(pidfile, &vm->pid)) < 0) {
        if (virSREProcessReadLogOutput(vm, logfile, pos, ebuf, sizeof(ebuf)) > 0)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("controller log failed to start: %s"), ebuf);
        else
            virReportSystemError(-r,
                                 _("Failed to read pid file %s"),
                                 pidfile);
        goto cleanup_netdev;
    }

    priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
    priv->wantReboot = false;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);
    priv->doneStopEvent = false;

    if (VIR_CLOSE(handshakefds[1]) < 0) {
        virReportSystemError(errno, "%s", _("could not close handshake fd"));
        goto cleanup_netdev;
    }

    if (virCommandHandshakeWait(cmd) < 0)
        goto cleanup_netdev;

    /* Write domain status to disk for the controller to
     * read when it starts */
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto cleanup_netdev;

    /* Allow the child to exec the controller */
    if (virCommandHandshakeNotify(cmd) < 0)
        goto cleanup_netdev;

    if (virAtomicIntInc(&driver->nactive) == 1 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    if (sreWaitForContinue(handshakefds[0]) < 0) {
        char out[1024];

        if (!(virSREProcessReadLogOutput(vm, logfile, pos, out, 1024) < 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("handshake failed to start: %s"), out);
        }

        goto cleanup_netdev;
    }

    /* And we can get the first monitor connection now too */
    if (!(priv->monitor = virSREProcessConnectMonitor(driver, vm))) {
        /* Intentionally overwrite the real monitor error message,
         * since a better one is almost always found in the logs
         */
        if (virSREProcessReadLogOutput(vm, logfile, pos, ebuf, sizeof(ebuf)) > 0) {
            virResetLastError();
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("monitor connection failed to start: %s"), ebuf);
        }
        goto cleanup_netdev;
    }

    if (autoDestroy &&
        virCloseCallbacksSet(driver->closeCallbacks, vm,
                             conn, sreProcessAutoDestroy) < 0)
        goto cleanup_netdev;

    /* finally we can call the 'started' hook script if any */
    if (virHookPresent(VIR_HOOK_DRIVER_SRE)) {
        char *xml = virDomainDefFormat(vm->def, driver->caps, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_SRE, vm->def->name,
                              VIR_HOOK_SRE_OP_STARTED, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup_netdev;
    }
    rc = 0;
cleanup_netdev:
    if(rc != 0) {
        if(sreDomainReleaseSRENetDev(driver, (sreDomainNamespaceDefPtr)vm->def->namespaceData, vm->def)) {
                VIR_WARN("domain netdev config failed");
        }

    }

cleanup:
    if (VIR_CLOSE(logfd) < 0) {
        virReportSystemError(errno, "%s", _("could not close logfile"));
        rc = -1;
    }
    if (rc != 0) {
        VIR_DEBUG("CLEANING UP FAILED DOMAIN");
        err = virSaveLastError();
        if( sreShutdownDomainPortal(vm,VIR_DOMAIN_SHUTOFF_SHUTDOWN,FORCE_SHUTDOWN)){
            virReportError(VIR_ERR_CALL_FAILED, "%s",_("VM Shutdown failed"));
        }
        virSREProcessStopDomain(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
        
    }
    virCommandFree(cmd);
    for (i = 0; i < nveths; i++)
        VIR_FREE(veths[i]);
    for (i = 0; i < nttyFDs; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    VIR_FREE(ttyFDs);
    VIR_FORCE_CLOSE(handshakefds[0]);
    VIR_FORCE_CLOSE(handshakefds[1]);
    VIR_FREE(pidfile);
    VIR_FREE(logfile);
    virObjectUnref(cfg);
    virObjectUnref(caps);
#ifdef VUB_SUPPORT
    VIR_FREE(vub_path);
#endif
    if (err) {
        virSetError(err);
        virFreeError(err);
    }
    return rc;

}

static bool
virSREProcessIgnorableLogLine(const char *str)
{
    if (virLogProbablyLogMessage(str))
        return true;
    if (strstr(str, "PATH="))
        return true;
    if (strstr(str, "error receiving signal from container"))
        return true;
    if (STREQ(str, ""))
        return true;
    return false;
}
static int
virSREProcessReadLogOutputData(virDomainObjPtr vm,
                               int fd,
                               char *buf,
                               size_t buflen)
{
    int retries = 10;
    int got = 0;
    int ret = -1;
    char *filter_next = buf;

    buf[0] = '\0';

    while (retries) {
        ssize_t bytes;
        bool isdead = false;
        char *eol;

        if (vm->pid <= 0 ||
            (kill(vm->pid, 0) == -1 && errno == ESRCH))
            isdead = true;

        /* Any failures should be detected before we read the log, so we
         * always have something useful to report on failure. */
        bytes = saferead(fd, buf+got, buflen-got-1);
        if (bytes < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failure while reading log output"));
            goto cleanup;
        }

        got += bytes;
        buf[got] = '\0';

        /* Filter out debug messages from intermediate libvirt process */
        while ((eol = strchr(filter_next, '\n'))) {
            *eol = '\0';
            if (virSREProcessIgnorableLogLine(filter_next)) {
                memmove(filter_next, eol + 1, got - (eol - buf));
                got -= eol + 1 - filter_next;
            } else {
                filter_next = eol + 1;
                *eol = '\n';
            }
        }

        if (got == buflen-1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Out of space while reading log output: %s"),
                           buf);
            goto cleanup;
        }

        if (isdead) {
            ret = got;
            goto cleanup;
        }

        usleep(100*1000);
        retries--;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Timed out while reading log output: %s"),
                   buf);

 cleanup:
    return ret;
}


static int
virSREProcessReadLogOutput(virDomainObjPtr vm,
                           char *logfile,
                           off_t pos,
                           char *buf,
                           size_t buflen)
{
    int fd = -1;
    int ret;

    if ((fd = open(logfile, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open log file %s"),
                             logfile);
        return -1;
    }

    if (lseek(fd, pos, SEEK_SET) < 0) {
        virReportSystemError(errno,
                             _("Unable to seek log file %s to %llu"),
                             logfile, (unsigned long long)pos);
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    ret = virSREProcessReadLogOutputData(vm,
                                         fd,
                                         buf,
                                         buflen);
    ret = 0;

    VIR_FORCE_CLOSE(fd);
    return ret;
}

/**
 * virSREProcessCleanup:
 * @driver: pointer to driver structure
 * @vm: pointer to VM to clean up
 * @reason: reason for switching the VM to shutoff state
 *
 * Cleanout resources associated with the now dead VM
 *
 */
static void virSREProcessCleanupDomain(sreDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainShutoffReason reason)
{
    virSREDomainObjPrivatePtr priv = vm->privateData;
    virDomainState state = virDomainObjGetState(vm,NULL);
    VIR_DEBUG("Cleanup VM name=%s pid=%d reason=%d id=%d state=%d",
              vm->def->name, (int)vm->pid, (int)reason,vm->def->id,(int)state);
    if(vm->def->id  < 0)
    {
        return;
    }

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_SRE)) {
        char *xml = virDomainDefFormat(vm->def, driver->caps, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_SRE, vm->def->name,
                    VIR_HOOK_SRE_OP_STOPPED, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
        VIR_FREE(xml);
    }

    /* Stop autodestroy in case guest is restarted */
    // virCloseCallbacksUnset(driver->closeCallbacks, vm,
    //                        sreProcessAutoDestroy);

    if (priv->monitor) {
        virSREMonitorClose(priv->monitor);
        virObjectUnref(priv->monitor);
        priv->monitor = NULL;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    vm->pid = -1;
    vm->def->id = -1;

    if (virAtomicIntDecAndTest(&driver->nactive) && driver->inhibitCallback)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    virDomainConfVMNWFilterTeardown(vm);

    /* The "release" hook cleans up additional resources */
    if (virHookPresent(VIR_HOOK_DRIVER_SRE)) {
        char *xml = virDomainDefFormat(vm->def, driver->caps, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_SRE, vm->def->name,
                    VIR_HOOK_SRE_OP_RELEASE, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
        VIR_FREE(xml);
    }

    virDomainObjRemoveTransientDef(vm);
}

static virCommandPtr
virSREProcessBuildControllerCmd(sreDriverPtr driver,
                                virDomainObjPtr vm,
                                int *ttyFDs,
                                size_t nttyFDs,
                                int handshakefd,
                                int * const logfd,
                                const char *pidfile)
{
    size_t i;
    char *filterstr;
    char *outputstr;
    virCommandPtr cmd;
    virSREDriverConfigPtr cfg = virSREDriverGetConfig(driver);

    cmd = virCommandNew("/usr/libexec/libvirt_sre");

    /* The controller may call ip command, so we have to retain PATH. */
    virCommandAddEnvPassBlockSUID(cmd, "PATH", "/bin:/usr/bin");

    virCommandAddEnvFormat(cmd, "LIBVIRT_DEBUG=%d",
                           virLogGetDefaultPriority());

    if (virLogGetNbFilters() > 0) {
        filterstr = virLogGetFilters();
        if (!filterstr) {
            virReportOOMError();
            goto cleanup;
        }

        virCommandAddEnvPair(cmd, "LIBVIRT_LOG_FILTERS", filterstr);
        VIR_FREE(filterstr);
    }

    if (cfg->log_libvirtd) {
        if (virLogGetNbOutputs() > 0) {
            outputstr = virLogGetOutputs();
            if (!outputstr) {
                virReportOOMError();
                goto cleanup;
            }

            virCommandAddEnvPair(cmd, "LIBVIRT_LOG_OUTPUTS", outputstr);
            VIR_FREE(outputstr);
        }
    } else {
        virCommandAddEnvFormat(cmd,
                               "LIBVIRT_LOG_OUTPUTS=%d:stderr",
                               virLogGetDefaultPriority());
    }

    virCommandAddArgList(cmd, "--name", vm->def->name, NULL);
    for (i = 0; i < nttyFDs; i++) {
        virCommandAddArg(cmd, "--console");
        virCommandAddArgFormat(cmd, "%d", ttyFDs[i]);
        virCommandPassFD(cmd, ttyFDs[i], 0);
    }

    virCommandAddArg(cmd, "--handshake");
    virCommandAddArgFormat(cmd, "%d", handshakefd);

    virCommandPassFD(cmd, handshakefd, 0);
    virCommandDaemonize(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetOutputFD(cmd, logfd);
    virCommandSetErrorFD(cmd, logfd);
    /* So we can pause before exec'ing the controller to
     * write the live domain status XML with the PID */
    virCommandRequireHandshake(cmd);

    virObjectUnref(cfg);
    return cmd;
 cleanup:
    virCommandFree(cmd);
    virObjectUnref(cfg);
    return NULL;
}
