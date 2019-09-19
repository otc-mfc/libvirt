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
