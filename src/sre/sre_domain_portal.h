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
