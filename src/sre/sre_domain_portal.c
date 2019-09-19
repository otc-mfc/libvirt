#include <config.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"
#include "virutil.h"
#include "virfile.h"
#include "virtime.h"
#include "virsystemd.h"
#include "sre_driver.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "sre_domain_portal.h"
#include "se_protocol.h"

#define VIR_FROM_THIS VIR_FROM_SRE
VIR_LOG_INIT("sre.sre_domain_launch");

#define PORTAL_DEV "/dev/SE0"

static virMutex portalLock = VIR_MUTEX_INITIALIZER;
static virMutex netdevLock = VIR_MUTEX_INITIALIZER;
static int portal_open( void );

static void
sreObjectEventQueue(sreDriverPtr driver, virObjectEventPtr event)
{
    if (!event)
        return;

    virObjectEventStateQueue(driver->eventState, event);
}

static int
writeDataToPortal(int portal_file, char *data, uint32_t size)
{
    int32_t bytes_written = 0;
    int32_t total_bytes_written = 0;

    while (total_bytes_written < size) {
        if ((bytes_written =
             write(portal_file, (char *) &data[total_bytes_written],
                   size - total_bytes_written)) < 0) {
            if (errno != EAGAIN) {
                return errno;
            }
        } else {
            total_bytes_written += bytes_written;
        }
    }

    /* expetc complete writes */
    if (total_bytes_written != size) {
        return -EIO;
    }
    return size;
}

static int
readDataFromPortal(int portal_file, char *data, uint32_t size)
{
    int32_t bytes_read = 0;
    int32_t total_bytes_read = 0;

    while (total_bytes_read < size) {
        if ((bytes_read =
             read(portal_file, (char *) &data[total_bytes_read],
                  size - total_bytes_read)) < 0) {
            if (errno != EAGAIN) {
                return errno;
            }
        } else {
            total_bytes_read += bytes_read;
        }
    }

    /* expect complete reads */
    if (total_bytes_read != size) {
        return -EIO;
    }

    return size;
}

int
sreDomainAddSRENetDev(sreDriverPtr privconn,
                      sreDomainNamespaceDefPtr ns_data,
                      virDomainDefPtr def)
{
    int net_idx = 0, pol_idx = 0;
    int status = 0;
    virMutexLock(&netdevLock);
    ns_data = def->namespaceData;
    for (net_idx = 0; net_idx < def->nnets; net_idx++) {
        for (pol_idx = 0; pol_idx < ns_data->portal_count; pol_idx++) {
            if (def->nets[net_idx]->type == VIR_DOMAIN_NET_TYPE_BRIDGE
                && STREQ(ns_data->portal_info[pol_idx].name,
                         def->nets[net_idx]->ifname)) {
                int portal_list_idx = 0;

                sre_pcidev_nic_t model_type = SRE_PORTAL_INIT;

                if (STREQ(def->nets[net_idx]->model, "sre-net")) {
                    model_type = SRE_PORTAL_NET;
                } else if (STREQ(def->nets[net_idx]->model, "sre-legacy")) {
                    model_type = SRE_LEGACY_NET;
                } else if (STREQ(def->nets[net_idx]->model, "virtio")) {
                    model_type = SRE_VIRTIO_NET;
                } else {
                    VIR_ERROR("Unsuported sre nic model %s",
                              def->nets[net_idx]->ifname);
                    status = -1;
                    break;
                }

                for (portal_list_idx = 0;
                     portal_list_idx <
                     virSRENetDeviceListCount(privconn->
                                              sre_net_device_list);
                     portal_list_idx++) {
                    virSRENetDevicePtr sre_netdev =
                        virSRENetDeviceListGet(privconn->
                                               sre_net_device_list,
                                               portal_list_idx);

                    if (sre_netdev->type == model_type
                        && sre_netdev->in_use_flag == 0) {
                        bool online = false;

                        if (virNetDevGetOnline
                            (sre_netdev->netdev_name, &online)) {
                            VIR_ERROR("Error getting nic status");
                            status = -1;
                            break;
                        }
                        if (online) {
                            if (virNetDevSetOnline
                                (sre_netdev->netdev_name, false)) {
                                VIR_ERROR("Error setting nic status");
                                status = -1;
                                break;
                            }
                        }

                        if (virNetDevExists
                            ((const char *) def->nets[net_idx]->data.
                             bridge.brname) != 1) {
                            VIR_ERROR
                                ("Bridge %s for interface %s does not exist",
                                 def->nets[net_idx]->data.bridge.brname,
                                 def->nets[net_idx]->ifname);
                            status = -1;
                            break;

                        }
                        if (sre_netdev->transient_name) {
                            VIR_FREE(sre_netdev->transient_name);
                            sre_netdev->transient_name = NULL;
                        }
                        ignore_value(VIR_STRDUP
                                     (sre_netdev->transient_name,
                                      def->nets[net_idx]->ifname));
                        if (virNetDevSetName
                            (sre_netdev->netdev_name,
                             sre_netdev->transient_name)) {
                            VIR_ERROR
                                ("Failed to rename sre netdev %s to %s",
                                 sre_netdev->netdev_name,
                                 sre_netdev->transient_name);
                            status = -1;
                            break;
                        } else
                            if (virNetDevSetMTUFromDevice
                                (sre_netdev->transient_name,
                                 (const char *) def->nets[net_idx]->data.
                                 bridge.brname)) {
                            VIR_ERROR("Failed to set %s mtu  of bridge %s",
                                      sre_netdev->transient_name,
                                      def->nets[net_idx]->data.bridge.
                                      brname);
                            status = -1;
                        } else
                            if (virNetDevBridgeAddPort
                                ((const char *) def->nets[net_idx]->data.
                                 bridge.brname,
                                 (const char *) sre_netdev->
                                 transient_name)) {
                            VIR_ERROR
                                ("Failed to add nic %s channel %d  to bridge %s",
                                 sre_netdev->transient_name,
                                 sre_netdev->channel,
                                 def->nets[net_idx]->data.bridge.brname);
                            status = -1;

                            if (virNetDevSetName
                                (sre_netdev->transient_name,
                                 sre_netdev->netdev_name)) {
                                VIR_ERROR
                                    ("Failed to rename sre netdev %s to %s",
                                     sre_netdev->transient_name,
                                     sre_netdev->netdev_name);
                                status = -1;
                            } else {
                                VIR_DEBUG("Reset nic name %s",
                                          sre_netdev->netdev_name);
                            }
                        } else {
                            VIR_DEBUG
                                ("Added NIC to bridge  %s (MTU %d)  channel %d NIC %s(MTU %d) ",
                                 def->nets[net_idx]->data.bridge.brname,
                                 virNetDevGetMTU(def->nets[net_idx]->data.
                                                 bridge.brname),
                                 sre_netdev->channel,
                                 sre_netdev->transient_name,
                                 virNetDevGetMTU(sre_netdev->
                                                 transient_name));

                            ns_data->portal_info[pol_idx].
                                portal_interface_id = sre_netdev->channel;
                            if (virNetDevSetOnline
                                (sre_netdev->transient_name, true) != 0) {
                                status = -1;
                            }
                            sre_netdev->in_use_flag = 1;
                            break;
                        }
                    }
                }
            }
        }
    }
    virMutexUnlock(&netdevLock);
    return status;
}


int
sreDomainReleaseSRENetDev(sreDriverPtr privconn,
                          sreDomainNamespaceDefPtr ns_data,
                          virDomainDefPtr def)
{
    int net_idx = 0, pol_idx = 0, portal_list_idx = 0;
    int status = 0;
    virMutexLock(&netdevLock);
    for (net_idx = 0; net_idx < def->nnets; net_idx++) {
        for (pol_idx = 0; pol_idx < ns_data->portal_count; pol_idx++) {
            if (def->nets[net_idx]->type == VIR_DOMAIN_NET_TYPE_BRIDGE &&
                STREQ(ns_data->portal_info[pol_idx].name,
                      def->nets[net_idx]->ifname)) {
                for (portal_list_idx = 0;
                     portal_list_idx <
                     virSRENetDeviceListCount(privconn->
                                              sre_net_device_list);
                     portal_list_idx++) {
                    virSRENetDevicePtr sre_netdev =
                        virSRENetDeviceListGet(privconn->
                                               sre_net_device_list,
                                               portal_list_idx);

                    if ((STREQ_NULLABLE
                         (sre_netdev->transient_name,
                          def->nets[net_idx]->ifname))
                        && (sre_netdev->channel ==
                            ns_data->portal_info[pol_idx].
                            portal_interface_id)
                        && sre_netdev->in_use_flag == 1) {

                        if (virNetDevSetOnline
                            (sre_netdev->transient_name, false)) {
                            VIR_WARN("Failed to set nic as down");
                        }

                        if (virNetDevExists(sre_netdev->transient_name)
                            && virNetDevExists(def->nets[net_idx]->data.
                                               bridge.brname)
                            && virNetDevBridgeRemovePort(def->
                                                         nets[net_idx]->
                                                         data.bridge.
                                                         brname,
                                                         (const char *)
                                                         sre_netdev->
                                                         transient_name)) {
                            VIR_WARN
                                ("Failed to remove nic %s channel %d from bridge %s",
                                 sre_netdev->transient_name,
                                 sre_netdev->channel,
                                 def->nets[net_idx]->data.bridge.brname);
                            status = -1;
                        } else
                            if (virNetDevExists(sre_netdev->transient_name)
                                && virNetDevSetName(sre_netdev->
                                                    transient_name,
                                                    sre_netdev->
                                                    netdev_name)) {
                            VIR_WARN
                                ("Failed to rename sre netdev %s to %s",
                                 sre_netdev->transient_name,
                                 sre_netdev->netdev_name);
                            status = -1;
                        } else {
                            sre_netdev->in_use_flag = 0;
                            VIR_DEBUG
                                ("releasing netdev channel %d name %s",
                                 sre_netdev->channel,
                                 sre_netdev->netdev_name);
                        }
                    }
                }
            }
        }
    }
    virMutexUnlock(&netdevLock);
    return status;
}

#define MAX_OPEN_RETRY 5
static int portal_open( void )
{
    int portal_fd = -1;
    int retry_count = 0;
    while( retry_count < MAX_OPEN_RETRY ){
        if( (portal_fd = open(PORTAL_DEV, O_RDWR | O_NONBLOCK | O_SYNC , S_IRUSR|S_IWUSR)) < 0 ){
            if(errno != EAGAIN) {
                return portal_fd;
            }
            VIR_DEBUG("retry opening portal count %d", retry_count);
            sleep(1);
            retry_count++;
        }
        else
            break;
    }
    return portal_fd;
    
}

int
sreDomainUpdateStatePortal(virDomainObjPtr domain)
{
    int newState = VIR_DOMAIN_SHUTOFF;
    se_packet_header_t stat_header;

    stat_header.type = REQ_DOMAIN_STATUS;
    stat_header.size = sizeof(stat_header);
    guest_id_t guest_id = domain->def->id;
    int ret = -1;

    if (domain->def->id < 0) {
        virDomainObjSetState(domain, newState, VIR_DOMAIN_SHUTOFF_UNKNOWN);
        return 0;
    }

    virMutexLock(&portalLock);

    int portal_file = -1;
    if ((portal_file = portal_open()) < 0) {
        virReportSystemError(errno,
                             _("error Opening SE portal file at %s"),
                             PORTAL_DEV);
        goto cleanup;
    }

    /*Write out the file size */
    if (writeDataToPortal
        (portal_file, (char *) &stat_header, sizeof(stat_header)) < 0) {
        virReportSystemError(errno,
                             _
                             ("writing domain status header '%s' to '%s': write failed"),
                             domain->def->name, PORTAL_DEV);
        goto cleanup;
    }

    if (writeDataToPortal
        (portal_file, (char *) &guest_id, sizeof(guest_id)) < 0) {
        virReportSystemError(errno,
                             _
                             ("writing domain status id '%s' to '%s': write failed"),
                             domain->def->name, PORTAL_DEV);
        goto cleanup;
    }

    se_domain_status_t status;

    if (readDataFromPortal
        (portal_file, (char *) &status, sizeof(se_domain_status_t)) < 0) {
        virReportSystemError(errno,
                             _
                             ("reading domain status for '%s' to '%s': write failed"),
                             domain->def->name, PORTAL_DEV);
        goto cleanup;
    }

    if (status.status == GUEST_RUNNING) {
        newState = VIR_DOMAIN_RUNNING;
    } else {
        /* check for policy violation?? */
        newState = VIR_DOMAIN_SHUTOFF;
        domain->def->id = -1;
    }

    ret = 0;
  cleanup:
    if (VIR_CLOSE(portal_file) < 0) {
        virReportSystemError(errno,
                             _("closing portal file from update %s"),
                             PORTAL_DEV);
    }
    virDomainObjSetState(domain, newState, VIR_DOMAIN_SHUTOFF_UNKNOWN);
    virMutexUnlock(&portalLock);

    return ret;
}

int
sreDomainUpdateSysInfoPortal(sre_sys_info_t * sys_info)
{
    se_packet_header_t info_header;

    info_header.type = REQ_SYS_INFO;
    info_header.size = sizeof(info_header);
    int ret = -1;

    if (!sys_info) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("SYS INFO WAS NULL"));
    }

    virMutexLock(&portalLock);

    int portal_file = -1;
    if ((portal_file = portal_open()) < 0) {
        virReportSystemError(errno,
                             _("error Opening SE portal file at %s"),
                             PORTAL_DEV);
        goto cleanup;
    }

    /*Write out the file size */
    if (writeDataToPortal
        (portal_file, (char *) &info_header, sizeof(info_header)) < 0) {
        virReportSystemError(errno,
                             _
                             ("writing sysinfo header to '%s': write failed"),
                             PORTAL_DEV);
        goto cleanup;
    }

    se_system_info_t se_sys_info;

    if (readDataFromPortal
        (portal_file, (char *) &se_sys_info,
         sizeof(se_system_info_t)) < 0) {
        virReportSystemError(errno, _("reading sysinfo from '%s': failed"),
                             PORTAL_DEV);
        goto cleanup;
    }
    memcpy(sys_info, &se_sys_info.system_info, sizeof(sre_sys_info_t));
    ret = 0;
  cleanup:
    if (VIR_CLOSE(portal_file) < 0) {
        virReportSystemError(errno,
                             _("closing portal file from update %s"),
                             PORTAL_DEV);
    }
    virMutexUnlock(&portalLock);

    return ret;
}

static int
sreGeneratePolicyBin(virDomainObjPtr privdom,
                     sreDriverPtr privconn,
                     const char *path, char **error_output, int is_dynamic)
{
    (void) path;
    virCommandPtr cmd = NULL;
    int ret = 0;

    if (privconn->sre_run_path == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "No SRE utility path found!");
        return VIR_ERR_NO_CONNECT;
    } else {
        cmd = virCommandNew(privconn->sre_run_path);
        const char *arg1 = "--file";
        const char *opt1 = "/tmp/temp.xml";
        const char *arg2 = "--target";
        const char *opt2 = "/tmp/sre.domain";
        const char *type = "-domain";
        const char *dynamic_policy = "--dynamic-policy";
        const char *out_signature_file_arg = "--out-signature-file";
        const char *out_signature_path = "/var/lib/nova/instances";     /* Populate the signature for OPS nova extra spec if path exists. */

        virCommandAddArg(cmd, type);
        virCommandAddArgPair(cmd, arg1, opt1);
        virCommandAddArgPair(cmd, arg2, opt2);
        if (is_dynamic) {
            virCommandAddArg(cmd, dynamic_policy);
            struct stat s;

            if (stat(out_signature_path, &s) != -1) {
                if (S_ISDIR(s.st_mode)) {
                    char out_signature_file[80];
                    unsigned char *uuid;
                    char uuidstr[VIR_UUID_STRING_BUFLEN];

                    uuid = privdom->def->uuid;
                    virUUIDFormat(uuid, uuidstr);
                    /* /var/lib/nova/instances/uuid/domain.sig */
                    sprintf(out_signature_file, "%s/%s/%s",
                            out_signature_path, uuidstr, "domain.sig");
                    virCommandAddArgPair(cmd, out_signature_file_arg,
                                         out_signature_file);
                }
            }
        }
        char *output = NULL;

        virCommandSetOutputBuffer(cmd, &output);
        virCommandSetErrorBuffer(cmd, &output);
        int status;

        if (virCommandRun(cmd, &status) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           "Error on SRE utility");
            *error_output = output;
            ret = 1;
        } else {
            VIR_DEBUG("%s", output);
            *error_output = output;
        }

        if (status != 0) {
            *error_output = output;
            ret = 1;
        }
    }

    virCommandFree(cmd);
    return ret;
}

int
sreShutdownDomainPortal(virDomainObjPtr privdom,
                        virDomainShutoffReason reason,
                        shutdown_mode_t mode)
{
    int ret = -1;

    (void) reason;
    virDomainState state = virDomainObjGetState(privdom, NULL);

    if (privdom->def->id < 0
        || virDomainObjGetState(privdom, NULL) == VIR_DOMAIN_SHUTOFF) {
        VIR_WARN("domain already shutdown id %d state %d\n",
                 (int) privdom->def->id, (int) state);
        return 0;
    }
    int portal_file = -1;
    int read_len = 0;
    se_packet_header_t destroy_header;
    se_status_t destroy_status;
    se_domain_destroy_t destroy_packet;

    destroy_header.type = CMD_DESTROY_DOMAIN;
    destroy_header.size = sizeof(destroy_packet);
    destroy_packet.domain_id = privdom->def->id;
    destroy_packet.shutdown_mode = mode;
    VIR_DEBUG("Destroying domain %d reason %d mode %d\n",
              (int) privdom->def->id, (int) reason, (int) mode);

    virMutexLock(&portalLock);
    if ((portal_file = portal_open()) < 0) {
        virReportSystemError(errno,
                             _("error Opening SE portal file at %s"),
                             PORTAL_DEV);
        goto cleanup;
    }

    /*Write out the file size */
    if (writeDataToPortal
        (portal_file, (char *) &destroy_header,
         sizeof(destroy_header)) < 0) {
        virReportSystemError(errno,
                             _
                             ("writing domain destroy header '%s' to '%s': write failed"),
                             privdom->def->name, PORTAL_DEV);
        goto cleanup;
    }

    if (writeDataToPortal
        (portal_file, (char *) &destroy_packet,
         sizeof(destroy_packet)) < 0) {
        virReportSystemError(errno,
                             _
                             ("writing domain destroy id '%s' to '%s': write failed"),
                             privdom->def->name, PORTAL_DEV);
        goto cleanup;
    }

    if ((read_len =
         readDataFromPortal(portal_file, (char *) &destroy_status,
                            sizeof(se_status_t))) < 0) {
        virReportSystemError(errno,
                             _
                             ("reading destroy status for '%s' to '%s': failed"),
                             privdom->def->name, PORTAL_DEV);
        goto cleanup;
    }

    if (destroy_status.status != STATUS_OK) {
        VIR_WARN("failed to destroy domain %s, ID %d", privdom->def->name,
                 privdom->def->id);
    }

    ret = 0;
  cleanup:
    if (VIR_CLOSE(portal_file) < 0) {
        virReportSystemError(errno,
                             _("closing portal file domain '%s' to '%s'"),
                             privdom->def->name, PORTAL_DEV);
    }
    virMutexUnlock(&portalLock);
    return ret;
}

/* Set up domain runtime state */
int
sreDomainStartState(sreDriverPtr privconn,
                    virDomainObjPtr dom, virDomainRunningReason reason)
{
    int ret = -1;

    virDomainObjSetState(dom, VIR_DOMAIN_RUNNING, reason);

    if (virDomainObjSetDefTransient(privconn->caps,
                                    privconn->xmlopt, dom, NULL) < 0) {
        VIR_WARN("Failed to set running state, goto cleanup");
        goto cleanup;
    }

    dom->hasManagedSave = false;
    ret = 0;
  cleanup:
    if (ret < 0)
        sreShutdownDomainPortal(dom, VIR_DOMAIN_SHUTOFF_FAILED,
                                FORCE_SHUTDOWN);
    return ret;
}


int
sreLaunchDomainPortal(virDomainObjPtr privdom, sreDriverPtr privconn)
{
    virObjectEventPtr event = NULL;
    int len = -1;
    const char *path = "/tmp/temp.xml";
    char *xml = 0;
    int ret = -1;
    int fd = -1;
    int portal_file = -1;
    int domain_file = -1;
    const char *domain_path = "/tmp/sre.domain";
    int bin_size = 0;
    int bin_read_length;
    struct stat st;
    int portal_size = 64 * 1024;
    char *domain_bin = 0;
    int total_sent = 0;
    int write_size = 0;
    int write_offset = 0;
    char *output_buffer = 0;
    int domain_expected_size = 0;
    domain_header_t *domain_header = 0;

    se_packet_header_t auth_header;
    se_status_t auth_status;

    se_packet_header_t dom_header;
    se_status_t create_status;
    virDomainState state = virDomainObjGetState(privdom, NULL);

    virMutexLock(&portalLock);
    xml = virDomainDefFormat(privdom->def, privconn->caps,
                             VIR_DOMAIN_DEF_FORMAT_SECURE);
    len = strlen(xml);

    if (state != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Domain '%s' is not shutoff state %d"),
                       privdom->def->name, state);
        goto cleanup;
    }

    if (xml == NULL) {
        virReportSystemError(errno,
                             _
                             ("saving domain '%s' failed to allocate space for metadata"),
                             privdom->def->name);
        goto cleanup;
    }

    if ((fd =
         open(path, O_CREAT | O_TRUNC | O_WRONLY,
              S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': open failed"),
                             privdom->def->name, path);
        goto cleanup;
    }

    if (safewrite(fd, xml, len) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             privdom->def->name, path);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             privdom->def->name, path);
        goto cleanup;
    }

    if (sreGeneratePolicyBin(privdom, privconn, path, &output_buffer,
                              1)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Error on parsing SRE policy: %s "),
                       output_buffer);
        goto cleanup;
    }

    if ((portal_file = portal_open()) < 0) {
         virReportSystemError(errno,
                              _("error Opening SE portal file at %s"),
                              PORTAL_DEV);
        ret = VIR_ERR_NO_CONNECT;
        goto cleanup;
    }

    stat(domain_path, &st);
    bin_size = st.st_size;


    if ((domain_file = open(domain_path, O_RDONLY, S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("error Opening domain file at %s"),
                             domain_path);
        goto cleanup;
    }

    if ((bin_read_length =
         virFileReadLimFD(domain_file, bin_size,
                          &domain_bin)) != bin_size) {
        VIR_WARN("error Reading file");
        goto cleanup;
    }

    domain_header = (domain_header_t *) domain_bin;
    domain_expected_size = domain_header->data.domain_info.domain_size;
    if (domain_expected_size != bin_size - sizeof(domain_header_t)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _
                       ("Unexpected domain file size '%s' expected from header %d actual %lu"),
                       privdom->def->name, domain_expected_size,
                       bin_size - sizeof(domain_header_t));
        goto cleanup;
    }

    auth_header.type = CMD_AUTH_DOMAIN_HEADER;
    auth_header.size = sizeof(domain_header_t);
    if (writeDataToPortal
        (portal_file, (char *) &auth_header, sizeof(auth_header)) < 0) {
        virReportSystemError(errno,
                             _
                             ("writing domain auth header '%s' to '%s': write failed "),
                             privdom->def->name, PORTAL_DEV);
        goto cleanup;
    }

    if (writeDataToPortal
        (portal_file, &domain_bin[write_offset],
         sizeof(domain_header_t)) < 0) {
        virReportSystemError(errno,
                             _
                             ("writing domain auth header '%s' to '%s': \n write failed errno %d "),
                             privdom->def->name, PORTAL_DEV, errno);
    }
    write_offset += sizeof(domain_header_t);
    total_sent += sizeof(domain_header_t);

    if ((readDataFromPortal
         (portal_file, (char *) &auth_status, sizeof(se_status_t))) < 0) {
        virReportSystemError(errno,
                             _
                             ("READING AUTH STATUS for '%s' to '%s': \nread auth status failed errno is %d"),
                             privdom->def->name, PORTAL_DEV, errno);
    }

    if (auth_status.status != STATUS_OK) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain '%s' failed to authenticate Error: %s"),
                       privdom->def->name, auth_status.error_string);
        goto cleanup;
    }

    dom_header.type = CMD_CREATE_DOMAIN;
    dom_header.size = domain_expected_size;
    /* Write out the file size */
    if (writeDataToPortal
        (portal_file, (char *) &dom_header, sizeof(dom_header)) < 0) {
        virReportSystemError(errno,
                             _
                             ("writing create domain header '%s' to '%s': write failed "),
                             privdom->def->name, PORTAL_DEV);
        goto cleanup;
    }
    while (total_sent < bin_read_length) {
        if (total_sent + portal_size > bin_read_length) {
            write_size = bin_read_length - total_sent;
        } else {
            write_size = portal_size;
        }

        if (writeDataToPortal
            (portal_file, &domain_bin[write_offset], write_size) < 0) {
            virReportSystemError(errno,
                                 _
                                 ("writing domain '%s' to '%s': \n write failed errno %d"),
                                 privdom->def->name, PORTAL_DEV, errno);
        } else {
            write_offset += write_size;
            total_sent += write_size;
        }
    }

    if ((readDataFromPortal
         (portal_file, (char *) &create_status,
          sizeof(se_status_t))) < 0) {
        virReportSystemError(errno,
                             _
                             ("READING CREATE STATUS for '%s' to '%s': \nread create status failed errno is %d"),
                             privdom->def->name, PORTAL_DEV, errno);
        goto cleanup;
    }

    if (create_status.status != STATUS_OK) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain '%s' failed to launch Error: %s"),
                       privdom->def->name, create_status.error_string);
        goto cleanup;
    }

    if (sreDomainStartState(privconn, privdom,
                            VIR_DOMAIN_RUNNING_BOOTED) < 0)
        goto cleanup;

    privdom->def->id = create_status.guest_id;

    event = virDomainEventLifecycleNewFromObj(privdom,
                                              VIR_DOMAIN_EVENT_STARTED,
                                              VIR_DOMAIN_EVENT_STARTED_BOOTED);

    ret = 0;

  cleanup:
    if (xml)
        VIR_FREE(xml);
    if (domain_bin)
        VIR_FREE(domain_bin);
    if (output_buffer)
        VIR_FREE(output_buffer);
    sreObjectEventQueue(privconn, event);
    if (VIR_CLOSE(domain_file) < 0) {
        virReportSystemError(errno,
                             _
                             ("closing domain file domain '%s' to '%s': write failed"),
                             privdom->def->name, domain_path);
    }

    if (VIR_CLOSE(portal_file) < 0) {
        virReportSystemError(errno,
                             _("closing portal file domain '%s' to '%s'"),
                             privdom->def->name, PORTAL_DEV);
    }

    virMutexUnlock(&portalLock);

    return ret;
}
