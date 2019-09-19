#ifndef __SRE_PROCESS_DOMAIN_H__
# define __SRE_PROCESS_DOMAIN_H__

# include "vircgroup.h"
# include "sre_conf.h"
# include "sre_monitor.h"
#include "sre_driver.h"
#include "sre_internal_types.h"
/*
 * virStateDriver sreStateDriver initial compute node boot setup callbacks (autostart)
 */
struct virSREProcessAutostartData {
    sreDriverPtr driver;
    virConnectPtr conn;
};
int virSREProcessSoftStopDomain(sreDriverPtr driver,
                      virDomainObjPtr vm,
                      virDomainShutoffReason reason);
int virSREProcessStartDomain(virConnectPtr conn,
                       sreDriverPtr  driver,
                       virDomainObjPtr vm,
                       bool autoDestroy,
                       virDomainRunningReason reason);
int
virSREProcessRebootDomain(sreDriverPtr driver,
                    virDomainObjPtr vm, 
                    shutdown_mode_t mode);


int virSREProcessStop(sreDriverPtr driver,
                      virDomainObjPtr vm,
                      virDomainShutoffReason reason);

void virSREProcessAutostartAll(sreDriverPtr driver);
int virSREProcessReconnectAll(sreDriverPtr driver,
                              virDomainObjListPtr doms);

#endif