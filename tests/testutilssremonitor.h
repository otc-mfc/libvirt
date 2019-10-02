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

#ifdef WITH_SRE

#include "capabilities.h"
#include "sre/sre_conf.h"
#include "sre/sre_domain.h"

#include "rpc/virnetsocket.h"

struct _sreMonitorTest {
    virMutex lock;
    virThread thread;

    bool quit;
    bool running;
    bool started;

    char *incoming;
    size_t incomingLength;
    size_t incomingCapacity;

    char *outgoing;
    size_t outgoingLength;
    size_t outgoingCapacity;

    virNetSocketPtr server;
    virNetSocketPtr listen;
    virNetSocketPtr client;

    virSREMonitorPtr mon;
    // qemuAgentPtr agent;

    char *tmpdir;

    virDomainObjPtr vm;
    virHashTablePtr qapischema;
};


typedef struct _sreMonitorTest sreMonitorTest;
typedef sreMonitorTest *sreMonitorTestPtr;

extern virSREMonitorCallbacks monitorCallbacks;

sreMonitorTestPtr testSREMonitorNew(virDomainObjPtr vm,
                                    virDomainChrSourceDefPtr src,
                                    virDomainXMLOptionPtr xmlopt);
// static int sreMonitorTestInit(sreMonitorTestPtr test);
// static void sreMonitorTestWorker(void *opaque);
// static void sreMonitorTestIO(virNetSocketPtr sock, int events, void *opaque);
// static int sreMonitorTestProcessCommand(qemuMonitorTestPtr test, const char *cmdstr);

#endif
