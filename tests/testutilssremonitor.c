#include <config.h>
#ifdef WITH_SRE
#include <stdlib.h>

#include "testutilssremonitor.h"
#include "testutilshostcpus.h"
#include "testutils.h"
#include "viralloc.h"
#include "cpu_conf.h"
#include "sre/sre_process_domain.h"
#include "sre/sre_domain.h"
#include "sre/sre_monitor.h"
#include "virstring.h"
#include "virfilecache.h"
#include "rpc/virnetsocket.h"



#define VIR_FROM_THIS VIR_FROM_SRE

static void
virSREProcessMonitorEOFNotify(virSREMonitorPtr mon ATTRIBUTE_UNUSED,
                              virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}

static void
virSREProcessMonitorShutdownNotify(virSREMonitorPtr mon ATTRIBUTE_UNUSED,
                                   virSREMonitorShutdownStatus status
                                   ATTRIBUTE_UNUSED,
                                   virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}

static void
virSREProcessMonitorStartNotify(virSREMonitorPtr mon ATTRIBUTE_UNUSED,
                                int domain_id ATTRIBUTE_UNUSED,
                                virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}

static void
virSREProcessMonitorPolicyNotify(virSREMonitorPtr mon ATTRIBUTE_UNUSED,
                                 int domain_id ATTRIBUTE_UNUSED,
                                 char *message ATTRIBUTE_UNUSED,
                                 int message_len ATTRIBUTE_UNUSED,
                                 virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}

virSREMonitorCallbacks monitorCallbacks = {
    .eofNotify = virSREProcessMonitorEOFNotify,
    .shutdownNotify = virSREProcessMonitorShutdownNotify,
    .startNotify = virSREProcessMonitorStartNotify,
    .policyNotify = virSREProcessMonitorPolicyNotify,
};

sreMonitorTestPtr
testSREMonitorNew(virDomainObjPtr vm, virDomainChrSourceDefPtr src,
                  virDomainXMLOptionPtr xmlopt)
{

    char *tmpdir_template = NULL;
    char *path = NULL;
    sreMonitorTestPtr test = NULL;

    if (VIR_ALLOC(test) < 0)
        goto error;

    if (VIR_STRDUP(tmpdir_template, "/tmp/libvirt_XXXXXX") < 0)
        goto error;
    if (!(test->tmpdir = mkdtemp(tmpdir_template))) {
        virReportSystemError(errno, "%s",
                             "Failed to create temporary directory");
        goto error;
    }

    if (virAsprintf(&path, "%s/sretest.sock", test->tmpdir) < 0)
        goto error;


    if (vm) {
        test->vm = virObjectRef(vm);
    } else {
        test->vm = virDomainObjNew(xmlopt);
        if (!test->vm)
            goto error;
    }

    if (virNetSocketNewListenUNIX(path, 0700, geteuid(), getegid(),
                                  &test->server) < 0)
        goto error;

    memset(src, 0, sizeof(*src));
    src->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    src->data.nix.path = (char *) path;
    src->data.nix.listen = false;
    path = NULL;

    if (virNetSocketListen(test->server, 0) < 0)
        goto error;

    virEventRegisterDefaultImpl();

    if (!
        (test->mon =
         virSREMonitorNew(test->vm, test->tmpdir, &monitorCallbacks)))
        goto error;

    return test;

  error:
    VIR_FREE(path);
    VIR_FREE(tmpdir_template);
    if (test) {
        virSREMonitorClose(test->mon);
    }
    test = NULL;

    return test;
}

#endif
