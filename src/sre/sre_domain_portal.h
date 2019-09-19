
#ifndef __SRE_DOMAIN_PORTAL_H__
#define __SRE_DOMAIN_PORTAL_H__


#include "sre_domain.h"

#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"
#include "virutil.h"
#include "virfile.h"
#include "virtime.h"
#include "virsystemd.h"
#include "se_protocol.h"
//netdev reserve
int sreDomainReleaseSRENetDev(sreDriverPtr privconn,
                              sreDomainNamespaceDefPtr ns_data,
                              virDomainDefPtr def);
//netdev release 
int sreDomainAddSRENetDev(sreDriverPtr privconn,
                          sreDomainNamespaceDefPtr ns_data,
                          virDomainDefPtr def);
//get sysinfo 
int sreDomainUpdateSysInfoPortal(sre_sys_info_t * sys_info);

//get domain state 
int sreDomainUpdateStatePortal(virDomainObjPtr domain);

//shutdown domain
int


sreShutdownDomainPortal(virDomainObjPtr privdom,
                        virDomainShutoffReason reason,
                        shutdown_mode_t mode);

//launch domain
int
  sreLaunchDomainPortal(virDomainObjPtr privdom, sreDriverPtr privconn);

//check start state
int


sreDomainStartState(sreDriverPtr privconn,
                    virDomainObjPtr dom, virDomainRunningReason reason);

#endif
