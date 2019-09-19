#ifndef __SRE_DOMAIN_H__
#define __SRE_DOMAIN_H__

#include "vircgroup.h"
#include "sre_conf.h"
#include "sre_monitor.h"


extern virDomainXMLNamespace virSREDriverDomainXMLNamespace;
extern virDomainXMLPrivateDataCallbacks virSREDriverPrivateDataCallbacks;

/* Only 1 job is allowed at any time
 * A job includes *all* sre.so api, even those just querying
 * information, not merely actions */

enum virSREDomainJob {
    SRE_JOB_NONE = 0,           /* Always set to 0 for easy if (jobActive) conditions */
    SRE_JOB_QUERY,              /* Doesn't change any state */
    SRE_JOB_DESTROY,            /* Destroys the domain (cannot be masked out) */
    SRE_JOB_MODIFY,             /* May change state */
    SRE_JOB_LAST
};

VIR_ENUM_DECL(virSREDomainJob)


     struct virSREDomainJobObj {
         virCond cond;          /* Use to coordinate jobs */
         enum virSREDomainJob active;   /* Currently running job */
         int owner;             /* Thread which set current job */
     };

     typedef struct _virSREDomainObjPrivate virSREDomainObjPrivate;
     typedef virSREDomainObjPrivate *virSREDomainObjPrivatePtr;
     struct _virSREDomainObjPrivate {
         virSREMonitorPtr monitor;
         bool doneStopEvent;
         int stopReason;
         bool wantReboot;
         pid_t initpid;
         struct virSREDomainJobObj job;
     };

     int sreSendContinue(int control);
     int sreWaitForContinue(int control);

#endif
