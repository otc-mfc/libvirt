/* -*- c -*-
 * Define wire protocol for communication between the
 * sre driver in libvirtd, and the SRE controller in
 * the libvirt_sre helper program.
* doc http://www.workers.com.br/manuais/html/tcpacces/rp/rp-5.htm
 */

%#include "virxdrdefs.h"

const MAX_MSG_LEN = 2048;
typedef opaque event_print_data[MAX_MSG_LEN];

enum virSREMonitorShutdownStatus {
    VIR_SRE_MONITOR_SHUTDOWN_STATUS_ERROR,
    VIR_SRE_MONITOR_SHUTDOWN_STATUS_SHUTDOWN,
    VIR_SRE_MONITOR_SHUTDOWN_STATUS_REBOOT,
    VIR_SRE_MONITOR_SHUTDOWN_STATUS_POLICY
};

struct virSREMonitorShutdownEventMsg {
    virSREMonitorShutdownStatus status;
    unsigned hyper guest_id;
};

enum virSREMonitorStartStatus {
    VIR_SRE_MONITOR_START_STATUS_ERROR,
    VIR_SRE_MONITOR_START_STATUS_RUNNING
};

struct virSREMonitorStartEventMsg {
    virSREMonitorStartStatus status;
    unsigned hyper guest_id;
};
enum virSREMonitorPolicyStatus {
    VIR_SRE_MONITOR_POLICY_STATUS_ERROR,
    VIR_SRE_MONITOR_POLICY_STATUS_VIOLATE
};

struct virSREMonitorPolicyEventMsg {
    virSREMonitorPolicyStatus status;
    unsigned hyper guest_id;
    unsigned hyper event_type;
    unsigned hyper event_subtype;
    event_print_data data;
    unsigned hyper data_len; 
};

const VIR_SRE_MONITOR_PROGRAM = 0x23232323;
const VIR_SRE_MONITOR_PROGRAM_VERSION = 1;

enum virSREMonitorProcedure {
    VIR_SRE_MONITOR_PROC_SHUTDOWN_EVENT = 1, /* skipgen skipgen */
    VIR_SRE_MONITOR_PROC_START_EVENT = 2, /* skipgen skipgen */
    VIR_SRE_MONITOR_PROC_POLICY_EVENT = 3 /* skipgen skipgen */
};
