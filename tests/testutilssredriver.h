// #ifdef WITH_SRE

#include "capabilities.h"
// # include "virfilecache.h"
// # include "domain_conf.h"
// # include "sre/sre_capabilities.h"
#include "sre/sre_conf.h"
#include "sre/se_protocol.h"

typedef struct _sreMonitorTest sreMonitorTest;
typedef sreMonitorTest *sreMonitorTestPtr;

void sreTestDriverFree(sreDriver * driver, int status);
int sreTestDriverInit(sreDriver * driver);
int sreSystemInfo(sre_sys_info_t * sys_info);

// virCapsPtr sreBuildCapabilities(void);

// #endif
