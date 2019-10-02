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
#ifdef WITH_SRE
#include <stdlib.h>

#include "testutilssre.h"
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

virCapsPtr
testSRECapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(VIR_ARCH_X86_64, false, false)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                         VIR_ARCH_I686,
                                         "/usr/libexec/libvirt_sre", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain
        (guest, VIR_DOMAIN_VIRT_SRE, NULL, NULL, 0, NULL))
        goto error;


    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_EXE,
                                         VIR_ARCH_X86_64,
                                         "/usr/libexec/libvirt_sre", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain
        (guest, VIR_DOMAIN_VIRT_SRE, NULL, NULL, 0, NULL))
        goto error;


    if (virTestGetDebug()) {
        char *caps_str;

        caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            goto error;

        VIR_TEST_DEBUG("SREC driver capabilities:\n%s", caps_str);

        VIR_FREE(caps_str);
    }

    return caps;

  error:
    virObjectUnref(caps);
    return NULL;
}

#endif
