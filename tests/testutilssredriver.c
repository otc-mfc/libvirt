#include <config.h>
#ifdef WITH_SRE
#include <stdlib.h>

#include "testutilssredriver.h"
#include "testutilssre.h"
#include "testutilshostcpus.h"
#include "testutils.h"
#include "viralloc.h"
#include "cpu_conf.h"
#include "sre/sre_process_domain.h"
#include "sre/sre_domain.h"
#include "sre/sre_domain_portal.h"
#include "virstring.h"
#include "virfilecache.h"



#define POLICY_API_PATH "/usr/bin/sre_policy_tool"
#define VIR_FROM_THIS VIR_FROM_SRE

int
sreSystemInfo(sre_sys_info_t * sys_info)
{
    if (sreDomainUpdateSysInfoPortal(sys_info) < 0)
        return -1;
    return 0;
}

void
sreTestDriverFree(sreDriver * driver, int status)
{
    virMutexDestroy(&driver->lock);
    if (driver->config && status == EXIT_SUCCESS) {
        virFileDeleteTree(driver->config->stateDir);
        virFileDeleteTree(driver->config->configDir);
        virFileDeleteTree(driver->config->logDir);
    }
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->caps);
    virObjectUnref(driver->config);
    virObjectUnref(driver->securityManager);
}

#define STATEDIRTEMPLATE abs_builddir "/srestatedir-XXXXXX"
#define CONFIGDIRTEMPLATE abs_builddir "/sreconfigdir-XXXXXX"
#define LOGDIRTEMPLATE abs_builddir "/srelogdir-XXXXXX"

int
sreTestDriverInit(sreDriver * driver)
{
    virSecurityManagerPtr mgr = NULL;
    char statedir[] = STATEDIRTEMPLATE;
    char configdir[] = CONFIGDIRTEMPLATE;
    char logdir[] = LOGDIRTEMPLATE;
    char *policy_api = virFindFileInPath(POLICY_API_PATH);

    // virSREDriverConfigPtr cfg = NULL;



    memset(driver, 0, sizeof(*driver));

    if (!(driver->config = virSREDriverConfigNew(false)) < 0)
        goto error;

    if (virMutexInit(&driver->lock) < 0)
        goto error;

    if (!driver->config)
        goto error;

    VIR_FREE(driver->config->stateDir);
    VIR_FREE(driver->config->configDir);

    /* Overwrite some default paths so it's consistent for tests. */
    VIR_FREE(driver->config->libDir);
    VIR_FREE(driver->config->channelTargetDir);
    VIR_FREE(driver->config->logDir);
    if (VIR_STRDUP(driver->config->libDir, "/tmp/lib") < 0 ||
        VIR_STRDUP(driver->config->channelTargetDir, "/tmp/channel") < 0 ||
        VIR_STRDUP(driver->config->logDir, "/tmp/log") < 0)
        goto error;

    if (!mkdtemp(statedir)) {
        virFilePrintf(stderr, "Cannot create fake stateDir");
        goto error;
    }

    if (VIR_STRDUP(driver->config->stateDir, statedir) < 0) {
        rmdir(statedir);
        goto error;
    }

    if (!mkdtemp(configdir)) {
        virFilePrintf(stderr, "Cannot create fake configDir");
        goto error;
    }

    if (VIR_STRDUP(driver->config->configDir, configdir) < 0) {
        rmdir(configdir);
        goto error;
    }

    if (!mkdtemp(logdir)) {
        virFilePrintf(stderr, "Cannot create fake logDir");
        goto error;
    }

    if (VIR_STRDUP(driver->config->logDir, logdir) < 0) {
        rmdir(logdir);
        goto error;
    }

    if (!(driver->caps = virSRECapsInit()))
        goto error;

    if (!
        (driver->xmlopt =
         virDomainXMLOptionNew(NULL, &virSREDriverPrivateDataCallbacks,
                               &virSREDriverDomainXMLNamespace, NULL,
                               NULL)))
        goto error;

    if (!(mgr = virSecurityManagerNew("none", "sre",
                                      VIR_SECURITY_MANAGER_PRIVILEGED)))
        goto error;

    if (!(driver->securityManager = virSecurityManagerNewStack(mgr)))
        goto error;

    if (!(driver->closeCallbacks = virCloseCallbacksNew()))
        goto error;


    if (virDomainObjListLoadAllConfigs(driver->domains,
                                       driver->config->stateDir,
                                       NULL, 1,
                                       driver->caps,
                                       driver->xmlopt, NULL, NULL) < 0)
        goto error;

    if (VIR_STRNDUP
        (driver->sre_run_path, policy_api, sizeof(POLICY_API_PATH)) < 0)
        goto error;

    if (!(driver->sre_net_device_list = sreProbeNetDevices()))
        goto error;

    VIR_FREE(policy_api);

    return 0;

  error:
    virObjectUnref(mgr);
    sreTestDriverFree(driver, EXIT_FAILURE);
    return -1;
}

#endif
