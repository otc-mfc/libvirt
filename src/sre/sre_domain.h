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
