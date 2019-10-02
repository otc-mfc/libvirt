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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"
#include "rpc/virnetsocket.h"

#ifdef WITH_SRE

#include "internal.h"
#include "testutilssremonitor.h"
#include "testutilssredriver.h"
#include "testutilssre.h"
#include "sre/sre_driver.h"
#include "sre/sre_domain_portal.h"
#include "sre/sre_process_domain.h"
#include "sre/sre_domain.h"

#include "sre/sre_monitor.h"
#include "sre/sre_conf.h"
#include "virfile.h"
#include "virlog.h"

#define SRE_TEST_DOMAIN_ID 2

#define VIRSH_CUSTOM  abs_topbuilddir "/tools/virsh", \
    "--connect", \
    custom_uri

// #include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_SRE
VIR_LOG_INIT("sre.sretest");

typedef struct {
    virConnectPtr conn;
    virNetworkPtr net;
    virStoragePoolPtr pool;
    virNodeDevicePtr dev;
} objecteventTest;

struct testInfo {
    const char *name;
};

static virCapsPtr capsPtr;
static virDomainXMLOptionPtr xmlopt;
static sreDriver driver;
static virConnectPtr conn;
virDomainObjPtr vm;
sreMonitorTestPtr test;

static int
testSreXml(const void *data)
{
    const struct testInfo *info = data;
    int ret = -1;
    char *xml_in = NULL;
    char *xml_out = NULL;

    VIR_DEBUG("test");

    if (virAsprintf(&xml_in, "%s/sretestdata/%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;
    if (virAsprintf(&xml_out, "%s/sretestdataout/%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt, xml_in,
                                     xml_out,
                                     false,
                                     0,
                                     TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);

  cleanup:
    VIR_FREE(xml_in);
    VIR_FREE(xml_out);
    return ret;
}

static int
initvm(char *xml)
{
    unsigned int parseFlags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    if (!(vm = virDomainObjNew(driver.xmlopt)))
        return -1;

    if (!
        (vm->def =
         virDomainDefParseFile(xml, driver.caps, driver.xmlopt, NULL,
                               parseFlags)))
        return -1;;

    vm->def->id = SRE_TEST_DOMAIN_ID;

    return 0;
}

static int
mymain(void)
{

    int ret = EXIT_FAILURE;
    char *xml = NULL;
    int status = -1;
    virDomainChrSourceDef src;
    virSRENetDevicePtr testdev;

    memset(&src, 0, sizeof(src));
    if (virAsprintf
        (&xml, "%s/sretestdata/%s.xml", abs_srcdir, "sretest.domain") < 0)
        goto cleanup;

    if (sreTestDriverInit(&driver) < 0)
        goto cleanup;
    VIR_WARN("INITED");

    if (!(conn = virGetConnect()))
        goto cleanup;
    VIR_WARN("CONNECTED");
    conn->privateData = &driver;
    if ((initvm(xml)) < 0)
        goto cleanup;
    VIR_WARN("init vm");

    if (!(test = testSREMonitorNew(vm, &src, driver.xmlopt)))
        goto cleanup;
    VIR_WARN("created monitor");

    if ((status =
         virSREProcessStartDomain(conn, &driver, test->vm, true,
                                  test->vm->state.reason)) != 0) {
        VIR_WARN("failed to start domain");

        if ((status != VIR_ERR_NO_CONNECT))
            goto cleanup;
    }

    if (sreRegister() < 0)
        goto cleanup;

    if (!(virSREDriverGetCapabilities(&driver, true)))
        goto cleanup;

    VIR_WARN("sretest");
    (void) testdev;


#define DO_XML_TEST(name) \
    do { \
            struct testInfo info = {name}; \
            if (virTestRun("SRE XML TEST", \
                           testSreXml, &info) < 0) { \
                goto cleanup; \
            } \
        } while (0)


    setenv("PATH", "/bin", 1);

    DO_XML_TEST("sre.domain");

    ret = EXIT_SUCCESS;


  cleanup:
    sreTestDriverFree(&driver, ret);
    virObjectUnref(capsPtr);
    virObjectUnref(xmlopt);
    virSREMonitorClose(test->mon);
    return ret;
}

VIR_TEST_MAIN(mymain)
#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif
