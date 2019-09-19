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
