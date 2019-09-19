
/*
 * sre_network_driver.h: network driver functions for managing SRE
 *                       host networks *
 */

#ifndef __SRE_DRIVER_ACCESS_H__
#define __SRE_DRIVER_ACCESS_H__

#include "sre_driver.h"
static void
sreDriverLock(sreDriverPtr driver)
{
    virMutexLock(&driver->lock);
}

static void
sreDriverUnlock(sreDriverPtr driver)
{
    virMutexUnlock(&driver->lock);
}

static void
sreObjectEventQueue(sreDriverPtr driver, virObjectEventPtr event)
{
    if (!event)
        return;

    virObjectEventStateQueue(driver->eventState, event);
}



#endif /* __ESX_NETWORK_DRIVER_H__ */
