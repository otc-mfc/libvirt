#include <config.h>

#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>

#ifdef MAJOR_IN_MKDEV
#include <sys/mkdev.h>
#elif MAJOR_IN_SYSMACROS
#include <sys/sysmacros.h>
#endif

#include <sys/types.h>
#include <sys/un.h>
#include <sys/personality.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <sys/mount.h>
#include <grp.h>
#include <sys/stat.h>
#include <time.h>

#if WITH_CAPNG
#include <cap-ng.h>
#endif

#include "virerror.h"
#include "virlog.h"

#include "sre_monitor_protocol.h"
#include "sre_conf.h"
#include "sre_domain.h"
#include "virnetdev.h"
#include "virnetdevveth.h"
#include "viralloc.h"
#include "virfile.h"
#include "virpidfile.h"
#include "vircommand.h"
#include "virhostcpu.h"
#include "virrandom.h"
#include "virprocess.h"
#include "virnuma.h"
#include "virdbus.h"
#include "rpc/virnetdaemon.h"
#include "virstring.h"
#include "virgettext.h"
#include "virstring.h"
#include "virtime.h"
#include "sre_evt_ctl_socket.h"
#include "sre_internal_types.h"



#define VIR_FROM_THIS VIR_FROM_SRE

VIR_LOG_INIT("sre.sre_controller");

typedef struct _virSREControllerConsole virSREControllerConsole;
typedef virSREControllerConsole *virSREControllerConsolePtr;
struct _virSREControllerConsole {
    int hostWatch;
    int hostFd;                 /* PTY FD in the host OS */
    bool hostClosed;
    int hostEpoll;

    int contWatch;
    int contFd;                 /* PTY FD in the container */
    bool contClosed;
    int contEpoll;

    int epollWatch;
    int epollFd;                /* epoll FD for dealing with EOF */

    size_t fromHostLen;
    char fromHostBuf[1024];
    size_t fromContLen;
    char fromContBuf[1024];

    virNetDaemonPtr daemon;
};

typedef struct _virSREControllerEvtMon virSREControllerEvtMon;
typedef virSREControllerEvtMon *virSREControllerEvtMonPtr;
struct _virSREControllerEvtMon {
    int evtMonWatch;
    int evtMonFd;               /* PTY FD in the host OS */
    bool evtMonClosed;
    int evtMonEpoll;

    int epollWatch;
    int epollFd;                /* epoll FD for dealing with EOF */
    virNetDaemonPtr daemon;
    struct _virSREController *ctrl;
};


typedef struct _virSREController virSREController;
typedef virSREController *virSREControllerPtr;
struct _virSREController {
    char *name;
    virDomainObjPtr vm;
    virDomainDefPtr def;

    int handshakeFd;

    virSREControllerEvtMonPtr evtMon;
    pid_t initpid;

    size_t nconsoles;
    virSREControllerConsolePtr consoles;
    struct vub_info_struct_t console_channels[MAX_NUM_SERIAL_PORTS];
    char *devptmx;

    size_t nloopDevs;
    int *loopDevFds;

    virSecurityManagerPtr securityManager;

    virNetDaemonPtr daemon;
    bool firstClient;
    virNetServerClientPtr client;
    virNetServerProgramPtr prog;
    bool inShutdown;
    int timerShutdown;
};

#include "sre_controller_dispatch.h"

static void virSREControllerFree(virSREControllerPtr ctrl);

static int virSREControllerEventSendPolicy(virSREControllerPtr ctrl,
                                           int guest_id,
                                           event_message_t *
                                           event_message);

static int virSREControllerEventSendStart(virSREControllerPtr ctrl,
                                          int guest_id);

static void virSREControllerEvtMonUpdateWatch(virSREControllerEvtMonPtr
                                              evt_mon);

static int


virSREControllerEventSendShutdown(virSREControllerPtr ctrl,
                                  int exitstatus);

static bool wantReboot;
static bool domainShutdown;
static virMutex lock = VIR_MUTEX_INITIALIZER;

static void
virSREControllerQuitTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virSREControllerPtr ctrl = opaque;

    VIR_DEBUG("Triggering event loop quit");
    virNetDaemonQuit(ctrl->daemon);
}


static virSREControllerPtr
virSREControllerNew(const char *name)
{
    virSREControllerPtr ctrl = NULL;
    virCapsPtr caps = NULL;
    virDomainXMLOptionPtr xmlopt = NULL;
    char *configFile = NULL;

    if (VIR_ALLOC(ctrl) < 0)
        goto error;

    ctrl->timerShutdown = -1;
    ctrl->firstClient = true;

    if (VIR_STRDUP(ctrl->name, name) < 0)
        goto error;

    if (!(caps = virSRECapsInit()))
        goto error;

    if (!(xmlopt = sreDomainXMLConfInit()))
        goto error;

    if ((configFile = virDomainConfigFile(SRE_STATE_DIR,
                                          ctrl->name)) == NULL)
        goto error;

    if ((ctrl->vm = virDomainObjParseFile(configFile,
                                          caps, xmlopt, 0)) == NULL)
        goto error;
    ctrl->def = ctrl->vm->def;

    if ((ctrl->timerShutdown = virEventAddTimeout(-1,
                                                  virSREControllerQuitTimer,
                                                  ctrl, NULL)) < 0)
        goto error;

  cleanup:
    VIR_FREE(configFile);
    virObjectUnref(caps);
    virObjectUnref(xmlopt);
    return ctrl;

  error:
    virSREControllerFree(ctrl);
    ctrl = NULL;
    goto cleanup;
}


static int
virSREControllerCloseLoopDevices(virSREControllerPtr ctrl)
{
    size_t i;

    for (i = 0; i < ctrl->nloopDevs; i++)
        VIR_FORCE_CLOSE(ctrl->loopDevFds[i]);

    return 0;
}


static void
virSREControllerStopInit(virSREControllerPtr ctrl)
{
    if (ctrl->initpid == 0)
        return;

    virSREControllerCloseLoopDevices(ctrl);
    virProcessAbort(ctrl->initpid);
    ctrl->initpid = 0;
}


static void
virSREControllerConsoleClose(virSREControllerConsolePtr console)
{
    if (console->hostWatch != -1)
        virEventRemoveHandle(console->hostWatch);
    VIR_FORCE_CLOSE(console->hostFd);

    if (console->contWatch != -1)
        virEventRemoveHandle(console->contWatch);
    VIR_FORCE_CLOSE(console->contFd);

    if (console->epollWatch != -1)
        virEventRemoveHandle(console->epollWatch);
    VIR_FORCE_CLOSE(console->epollFd);
}

static void
virSREControllerEvtMonClose(virSREControllerEvtMonPtr evt_mon)
{
    if (evt_mon->evtMonWatch != -1)
        virEventRemoveHandle(evt_mon->evtMonWatch);
    VIR_FORCE_CLOSE(evt_mon->evtMonWatch);

    if (evt_mon->epollWatch != -1)
        virEventRemoveHandle(evt_mon->epollWatch);
    VIR_FORCE_CLOSE(evt_mon->epollFd);
}



static void
virSREControllerFree(virSREControllerPtr ctrl)
{
    size_t i;

    if (!ctrl)
        return;

    virSREControllerStopInit(ctrl);

    virObjectUnref(ctrl->securityManager);


    for (i = 0; i < ctrl->nconsoles; i++)
        virSREControllerConsoleClose(&(ctrl->consoles[i]));
    VIR_FREE(ctrl->consoles);

    VIR_FREE(ctrl->devptmx);

    VIR_FREE(ctrl->name);
    virObjectUnref(ctrl->prog);

    virDomainObjEndAPI(&ctrl->vm);

    if (ctrl->timerShutdown != -1)
        virEventRemoveTimeout(ctrl->timerShutdown);

    virObjectUnref(ctrl->daemon);


    /* This must always be the last thing to be closed */
    VIR_FORCE_CLOSE(ctrl->handshakeFd);

    VIR_FORCE_CLOSE(ctrl->evtMon->evtMonFd);

    VIR_FREE(ctrl);
}


static int
virSREControllerAddConsole(virSREControllerPtr ctrl, int hostFd)
{
    if (VIR_EXPAND_N(ctrl->consoles, ctrl->nconsoles, 1) < 0)
        return -1;
    ctrl->consoles[ctrl->nconsoles - 1].daemon = ctrl->daemon;
    ctrl->consoles[ctrl->nconsoles - 1].hostFd = hostFd;
    ctrl->consoles[ctrl->nconsoles - 1].hostWatch = -1;

    ctrl->consoles[ctrl->nconsoles - 1].contFd = -1;
    ctrl->consoles[ctrl->nconsoles - 1].contWatch = -1;

    ctrl->consoles[ctrl->nconsoles - 1].epollFd = -1;
    ctrl->consoles[ctrl->nconsoles - 1].epollWatch = -1;
    return 0;
}


static int
virSREControllerConsoleSetNonblocking(virSREControllerConsolePtr console)
{
    if (virSetBlocking(console->hostFd, false) < 0 ||
        virSetBlocking(console->contFd, false) < 0) {
        virReportSystemError(errno, "%s",
                             _
                             ("Unable to set console file descriptor non-blocking"));
        return -1;
    }

    return 0;
}

static int
virSREControllerDaemonHandshake(virSREControllerPtr ctrl)
{
    if (sreSendContinue(ctrl->handshakeFd) < 0) {
        virReportSystemError(errno, "%s",
                             _("error sending continue signal to daemon"));
        return -1;
    }
    VIR_FORCE_CLOSE(ctrl->handshakeFd);
    return 0;
}



static int
virSREControllerValidateConsoles(virSREControllerPtr ctrl)
{
    int i = 0;
    int pty_count = 0;

#ifdef VUB_SUPPORT
    sreDomainNamespaceDefPtr nsdata =
        (sreDomainNamespaceDefPtr) ctrl->def->namespaceData;
#endif
    for (i = 0; i < ctrl->def->nserials; i++) {
        if (ctrl->def->serials[i]->source->type == VIR_DOMAIN_CHR_TYPE_PTY
            && pty_count < MAX_NUM_SERIAL_PORTS) {
#ifdef VUB_SUPPORT
            ctrl->console_channels[pty_count].vub_channel =
                nsdata->vub_info[pty_count].vub_channel;
            ctrl->console_channels[pty_count].vub_portval =
                nsdata->vub_info[pty_count].vub_portval;
#endif
            pty_count++;
        }
    }
#ifdef VUB_SUPPORT
    if (pty_count != nsdata->vub_count) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _
                       ("expecting %d vub consoles, but got %d tty file handlers"),
                       nsdata->vub_count, pty_count);
        return -1;
    }
#endif
    ctrl->nconsoles = pty_count;

    return 0;
}

static int
virSREControllerSetupEvtMonitor(virSREControllerPtr ctrl)
{
    int ret = -1;
    char *event_file_path;
    char uuid_str[GUEST_UUID_SIZE];
    int event_soc_fd = -1;
    int message_type = -1;

    virUUIDFormat(ctrl->def->uuid, uuid_str);
    if (virAsprintf(&event_file_path, "%s/%s.event.soc",
                    SRE_STATE_DIR, ctrl->def->name) < 0)
        goto cleanup;
    unlink(event_file_path);

    event_soc_fd = make_named_socket(event_file_path);

    if (event_soc_fd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Failed to make event socket %s", event_file_path);
        goto cleanup;
    }

    handshake_message_t handshake;

    memset(&handshake, 0, sizeof(handshake_message_t));
    handshake.guest_id = ctrl->def->id;
    //get the uuid in string format from domain def 
    virUUIDFormat(ctrl->def->uuid, handshake.uuid);
    if (virStrncpy
        (handshake.sock_path, event_file_path,
         strnlen(event_file_path, MAX_PATH_LEN), MAX_PATH_LEN) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Event Socket path too long %s", event_file_path);
        goto cleanup;
    }
    if (!send_handshake_message_client(handshake, LM_EVT_CTL_SOCKET_PATH)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Event Socket failed to handshake with event monitor %s",
                       event_file_path);
        goto cleanup;
    }

    handshake_message_t handshake_ack_message;

    message_type =
        rec_evt_message_client(event_soc_fd,
                               (char *) &handshake_ack_message,
                               sizeof(handshake_ack_message));
    if (message_type != EVT_MSG_SOCKET_INIT_CTL) {
        VIR_WARN("Unexpected Event message type");
        goto cleanup;
    }


    ctrl->evtMon->evtMonFd = event_soc_fd;

    ret = 0;
  cleanup:
    if (ret != 0) {
        VIR_FORCE_CLOSE(event_soc_fd);
    }
    VIR_FREE(event_file_path);
    return ret;
}

static void
virSREControllerEventMonEPoll(int watch, int fd, int events, void *opaque)
{
    virSREControllerEvtMonPtr evt_mon = opaque;

    virMutexLock(&lock);
    VIR_DEBUG("IO event watch=%d fd=%d events=%d", watch, fd, events);

    while (1) {
        struct epoll_event event;
        int ret;

        ret = epoll_wait(fd, &event, 1, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("Unable to wait on epoll"));
            virNetDaemonQuit(evt_mon->daemon);
            goto cleanup;
        }

        if (ret == 0)
            break;

        VIR_DEBUG("fd=%d", event.data.fd);

        /* If we get HUP+dead PID, we just re-enable the main loop
         * which will see the PID has died and exit */
        if ((event.events & (EPOLLIN | EPOLLOUT))) {
            if (event.data.fd == evt_mon->evtMonFd) {
                evt_mon->evtMonClosed = false;
            }
            virSREControllerEvtMonUpdateWatch(evt_mon);
            break;
        }



    }

  cleanup:
    virMutexUnlock(&lock);
}

static void
virSREControllerClientCloseHook(virNetServerClientPtr client)
{
    virSREControllerPtr ctrl = virNetServerClientGetPrivateData(client);

    if (ctrl->client == client)
        ctrl->client = NULL;
    if (ctrl->inShutdown) {
        VIR_DEBUG("Arm timer to quit event loop");
        virEventUpdateTimeout(ctrl->timerShutdown, 0);
    }
}

static void
virSREControllerClientPrivateFree(void *data)
{
    virSREControllerPtr ctrl = data;

    VIR_DEBUG("Got private data free %p", ctrl);
}

static void *
virSREControllerClientPrivateNew(virNetServerClientPtr client,
                                 void *opaque)
{
    virSREControllerPtr ctrl = opaque;

    virNetServerClientSetCloseHook(client,
                                   virSREControllerClientCloseHook);
    VIR_DEBUG("Got new client %p", client);
    ctrl->client = client;

    ctrl->firstClient = false;

    return ctrl;
}


static int
virSREControllerSetupServer(virSREControllerPtr ctrl)
{
    virNetServerPtr srv = NULL;
    virNetServerServicePtr svc = NULL;
    char *sockpath;

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    SRE_STATE_DIR, ctrl->name) < 0)
        return -1;

    if (!(srv = virNetServerNew("SRE", 1,
                                0, 0, 0, 1,
                                0, -1, 0,
                                NULL,
                                virSREControllerClientPrivateNew,
                                NULL,
                                virSREControllerClientPrivateFree, ctrl)))
        goto error;

    if (virSecurityManagerSetSocketLabel(ctrl->securityManager, ctrl->def)
        < 0)
        goto error;

    if (!(svc = virNetServerServiceNewUNIX(sockpath,
                                           0700, 0, 0, NULL, false, 0, 5)))
        goto error;

    if (virSecurityManagerClearSocketLabel
        (ctrl->securityManager, ctrl->def) < 0)
        goto error;

    if (virNetServerAddService(srv, svc, NULL) < 0)
        goto error;
    virObjectUnref(svc);
    svc = NULL;

    if (!(ctrl->prog = virNetServerProgramNew(VIR_SRE_MONITOR_PROGRAM,
                                              VIR_SRE_MONITOR_PROGRAM_VERSION,
                                              virSREMonitorProcs,
                                              virSREMonitorNProcs)))
        goto error;

    if (!(ctrl->daemon = virNetDaemonNew()) ||
        virNetDaemonAddServer(ctrl->daemon, srv) < 0)
        goto error;

    virNetDaemonUpdateServices(ctrl->daemon, true);
    VIR_FREE(sockpath);
    return 0;

  error:
    VIR_FREE(sockpath);
    virObjectUnref(srv);
    virObjectUnref(ctrl->daemon);
    ctrl->daemon = NULL;
    virObjectUnref(svc);
    return -1;
}


// static int sreControllerClearCapabilities(void)
// {
// #if WITH_CAPNG
//     int ret;

//     capng_clear(CAPNG_SELECT_BOTH);

//     if ((ret = capng_apply(CAPNG_SELECT_BOTH)) < 0) {
//         virReportError(VIR_ERR_INTERNAL_ERROR,
//                        _("failed to apply capabilities: %d"), ret);
//         return -1;
//     }
// #else
//     VIR_WARN("libcap-ng support not compiled in, unable to clear capabilities");
// #endif
//     return 0;
// }



static void
virSREControllerSignalChildIO(virNetDaemonPtr dmn,
                              siginfo_t * info ATTRIBUTE_UNUSED,
                              void *opaque)
{
    virSREControllerPtr ctrl = opaque;
    int ret;
    int status;

    ret = waitpid(-1, &status, WNOHANG);
    VIR_DEBUG("Got sig child %d vs %lld", ret, (long long) ctrl->initpid);
    if (ret == ctrl->initpid) {
        virNetDaemonQuit(dmn);
        virMutexLock(&lock);
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGHUP) {
            VIR_DEBUG("Status indicates reboot");
            wantReboot = true;
        }
        virMutexUnlock(&lock);
    }
}

static void
virSREControllerEvtMonUpdateWatch(virSREControllerEvtMonPtr evt_mon)
{

    int monEvetns = 0;

    if (!evt_mon->evtMonClosed) {
        monEvetns |= VIR_EVENT_HANDLE_READABLE;
    }

    VIR_DEBUG("EvtMon watch=%d, events=%d closed=%d;",
              evt_mon->evtMonWatch, monEvetns, evt_mon->evtMonClosed);
    virEventUpdateHandle(evt_mon->evtMonWatch, monEvetns);

    if (evt_mon->evtMonClosed) {
        /* Must setup an epoll to detect when host becomes accessible again */
        int events = EPOLLIN | EPOLLET;

        if (events != evt_mon->evtMonEpoll) {
            struct epoll_event event;
            int action = EPOLL_CTL_ADD;

            if (evt_mon->evtMonEpoll)
                action = EPOLL_CTL_MOD;

            VIR_DEBUG("newHostEvents=%x oldHostEvents=%x", events,
                      evt_mon->evtMonEpoll);

            event.events = events;
            event.data.fd = evt_mon->evtMonFd;
            if (epoll_ctl
                (evt_mon->epollFd, action, evt_mon->evtMonFd,
                 &event) < 0) {
                VIR_DEBUG(":fail");
                virReportSystemError(errno, "%s",
                                     _("Unable to add epoll fd"));
                virNetDaemonQuit(evt_mon->daemon);
                goto cleanup;
            }
            evt_mon->evtMonEpoll = events;
            VIR_DEBUG("newHostEvents=%x oldHostEvents=%x", events,
                      evt_mon->evtMonEpoll);
        }
    } else if (evt_mon->evtMonEpoll) {
        VIR_DEBUG("Stop epoll oldContEvents=%x", evt_mon->evtMonEpoll);
        if (epoll_ctl
            (evt_mon->evtMonEpoll, EPOLL_CTL_DEL, evt_mon->evtMonFd,
             NULL) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to remove epoll fd"));
            VIR_DEBUG(":fail");
            virNetDaemonQuit(evt_mon->daemon);
            goto cleanup;
        }
        evt_mon->evtMonEpoll = 0;
    }
  cleanup:
    return;
}



static void
virSREControllerConsoleUpdateWatch(virSREControllerConsolePtr console)
{
    int hostEvents = 0;
    int contEvents = 0;

    /* If host console is open, then we can look to read/write */
    if (!console->hostClosed) {
        if (console->fromHostLen < sizeof(console->fromHostBuf))
            hostEvents |= VIR_EVENT_HANDLE_READABLE;
        if (console->fromContLen)
            hostEvents |= VIR_EVENT_HANDLE_WRITABLE;
    }

    /* If cont console is open, then we can look to read/write */
    if (!console->contClosed) {
        if (console->fromContLen < sizeof(console->fromContBuf))
            contEvents |= VIR_EVENT_HANDLE_READABLE;
        if (console->fromHostLen)
            contEvents |= VIR_EVENT_HANDLE_WRITABLE;
    }

    VIR_DEBUG
        ("Container watch=%d, events=%d closed=%d; host watch=%d events=%d closed=%d",
         console->contWatch, contEvents, console->contClosed,
         console->hostWatch, hostEvents, console->hostClosed);
    virEventUpdateHandle(console->contWatch, contEvents);
    virEventUpdateHandle(console->hostWatch, hostEvents);

    if (console->hostClosed) {
        /* Must setup an epoll to detect when host becomes accessible again */
        int events = EPOLLIN | EPOLLET;

        if (console->fromContLen)
            events |= EPOLLOUT;

        if (events != console->hostEpoll) {
            struct epoll_event event;
            int action = EPOLL_CTL_ADD;

            if (console->hostEpoll)
                action = EPOLL_CTL_MOD;

            VIR_DEBUG("newHostEvents=%x oldHostEvents=%x", events,
                      console->hostEpoll);

            event.events = events;
            event.data.fd = console->hostFd;
            if (epoll_ctl
                (console->epollFd, action, console->hostFd, &event) < 0) {
                VIR_DEBUG(":fail");
                virReportSystemError(errno, "%s",
                                     _("Unable to add epoll fd"));
                virNetDaemonQuit(console->daemon);
                goto cleanup;
            }
            console->hostEpoll = events;
            VIR_DEBUG("newHostEvents=%x oldHostEvents=%x", events,
                      console->hostEpoll);
        }
    } else if (console->hostEpoll) {
        VIR_DEBUG("Stop epoll oldContEvents=%x", console->hostEpoll);
        if (epoll_ctl
            (console->epollFd, EPOLL_CTL_DEL, console->hostFd, NULL) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to remove epoll fd"));
            VIR_DEBUG(":fail");
            virNetDaemonQuit(console->daemon);
            goto cleanup;
        }
        console->hostEpoll = 0;
    }

    if (console->contClosed) {
        /* Must setup an epoll to detect when guest becomes accessible again */
        int events = EPOLLIN | EPOLLET;

        if (console->fromHostLen)
            events |= EPOLLOUT;

        if (events != console->contEpoll) {
            struct epoll_event event;
            int action = EPOLL_CTL_ADD;

            if (console->contEpoll)
                action = EPOLL_CTL_MOD;

            VIR_DEBUG("newContEvents=%x oldContEvents=%x", events,
                      console->contEpoll);

            event.events = events;
            event.data.fd = console->contFd;
            if (epoll_ctl
                (console->epollFd, action, console->contFd, &event) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Unable to add epoll fd"));
                VIR_DEBUG(":fail");
                virNetDaemonQuit(console->daemon);
                goto cleanup;
            }
            console->contEpoll = events;
            VIR_DEBUG("newHostEvents=%x oldHostEvents=%x", events,
                      console->contEpoll);
        }
    } else if (console->contEpoll) {
        VIR_DEBUG("Stop epoll oldContEvents=%x", console->contEpoll);
        if (epoll_ctl
            (console->epollFd, EPOLL_CTL_DEL, console->contFd, NULL) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to remove epoll fd"));
            VIR_DEBUG(":fail");
            virNetDaemonQuit(console->daemon);
            goto cleanup;
        }
        console->contEpoll = 0;
    }
  cleanup:
    return;
}


static void
virSREControllerConsoleEPoll(int watch, int fd, int events, void *opaque)
{
    virSREControllerConsolePtr console = opaque;

    virMutexLock(&lock);
    VIR_DEBUG
        ("IO event watch=%d fd=%d events=%d fromHost=%zu fromcont=%zu",
         watch, fd, events, console->fromHostLen, console->fromContLen);

    while (1) {
        struct epoll_event event;
        int ret;

        ret = epoll_wait(console->epollFd, &event, 1, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("Unable to wait on epoll"));
            virNetDaemonQuit(console->daemon);
            goto cleanup;
        }

        if (ret == 0)
            break;

        VIR_DEBUG("fd=%d hostFd=%d contFd=%d hostEpoll=%x contEpoll=%x",
                  event.data.fd, console->hostFd, console->contFd,
                  console->hostEpoll, console->contEpoll);

        /* If we get HUP+dead PID, we just re-enable the main loop
         * which will see the PID has died and exit */
        if ((event.events & (EPOLLIN | EPOLLOUT))) {
            if (event.data.fd == console->hostFd) {
                console->hostClosed = false;
            } else {
                console->contClosed = false;
            }
            virSREControllerConsoleUpdateWatch(console);
            break;
        }
    }

  cleanup:
    virMutexUnlock(&lock);
}

static void
virSREControllerConsoleIO(int watch, int fd, int events, void *opaque)
{
    virSREControllerConsolePtr console = opaque;

    virMutexLock(&lock);
    VIR_DEBUG
        ("IO event watch=%d fd=%d events=%d fromHost=%zu fromcont=%zu",
         watch, fd, events, console->fromHostLen, console->fromContLen);
    if (events & VIR_EVENT_HANDLE_READABLE) {
        char *buf;
        size_t *len;
        size_t avail;
        ssize_t done;

        if (watch == console->hostWatch) {
            buf = console->fromHostBuf;
            len = &console->fromHostLen;
            avail = sizeof(console->fromHostBuf) - *len;
        } else {
            buf = console->fromContBuf;
            len = &console->fromContLen;
            avail = sizeof(console->fromContBuf) - *len;
        }
      reread:
        done = read(fd, buf + *len, avail);
        if (done == -1 && errno == EINTR)
            goto reread;
        if (done == -1 && errno != EAGAIN) {
            virReportSystemError(errno, "%s",
                                 _("Unable to read container pty"));
            goto error;
        }
        if (done > 0) {
            *len += done;
        } else {
            VIR_DEBUG("Read fd %d done %d errno %d", fd, (int) done,
                      errno);
        }
    }

    if (events & VIR_EVENT_HANDLE_WRITABLE) {
        char *buf;
        size_t *len;
        ssize_t done;

        if (watch == console->hostWatch) {
            buf = console->fromContBuf;
            len = &console->fromContLen;
        } else {
            buf = console->fromHostBuf;
            len = &console->fromHostLen;
        }

      rewrite:
        done = write(fd, buf, *len);
        if (done == -1 && errno == EINTR)
            goto rewrite;
        if (done == -1 && errno != EAGAIN) {
            virReportSystemError(errno, "%s",
                                 _("Unable to write to container pty"));
            goto error;
        }
        if (done > 0) {
            memmove(buf, buf + done, (*len - done));
            *len -= done;
        } else {
            VIR_DEBUG("Write fd %d done %d errno %d", fd, (int) done,
                      errno);
        }
    }

    if (events & VIR_EVENT_HANDLE_HANGUP) {
        if (watch == console->hostWatch) {
            console->hostClosed = true;
        } else {
            console->contClosed = true;
        }
        VIR_DEBUG("Got EOF on %d %d", watch, fd);
    }

    virSREControllerConsoleUpdateWatch(console);
    virMutexUnlock(&lock);
    return;

  error:
    virEventRemoveHandle(console->contWatch);
    virEventRemoveHandle(console->hostWatch);
    console->contWatch = console->hostWatch = -1;
    virNetDaemonQuit(console->daemon);
    virMutexUnlock(&lock);
}

static void
virSREControllerEvtMonIO(int watch, int fd, int events, void *opaque)
{
    virSREControllerEvtMonPtr evt_mon = opaque;
    event_message_t *event_message = NULL;

    virMutexLock(&lock);
    VIR_DEBUG("IO event watch=%d fd=%d events=%d", watch, fd, events);
    if (VIR_ALLOC(event_message) < 0) {
        VIR_WARN("MESSAGE alloc failed");
        goto error;
    }
    if (events & VIR_EVENT_HANDLE_READABLE) {
        if (watch == evt_mon->evtMonWatch) {
            //read code
            int message_type = -1;


            message_type =
                rec_evt_message_client(evt_mon->evtMonFd,
                                       (char *) event_message,
                                       sizeof(event_message_t));
            if (message_type < 0) {
                VIR_WARN("MESSAGE BAD");
                goto error;
            }
            //check message length
            event_message->message_len =
                MIN(event_message->message_len, MAX_MSG_LEN);

            //make sure string is terminated 
            event_message->message_data[event_message->message_len] = 0;
            if (event_message->event_type == EVT_VM_SHUTDOWN) {
                domainShutdown = true;
                virSREControllerEventSendShutdown(evt_mon->ctrl,
                                                  event_message->
                                                  event_type);
            } else if (event_message->event_type == EVT_VM_STARTUP) {
                virSREControllerEventSendStart(evt_mon->ctrl,
                                               event_message->guest_id);
            } else {
                virSREControllerEventSendPolicy(evt_mon->ctrl,
                                                event_message->guest_id,
                                                event_message);
            }
        }
    }
    if (events & VIR_EVENT_HANDLE_HANGUP) {
        if (watch == evt_mon->evtMonWatch) {
            evt_mon->evtMonClosed = true;
        }
        VIR_DEBUG("Got EOF on %d %d", watch, fd);
    }

    VIR_FREE(event_message);
    virSREControllerEvtMonUpdateWatch(evt_mon);
    virMutexUnlock(&lock);
    return;

  error:
    VIR_FREE(event_message);
    virEventRemoveHandle(evt_mon->evtMonWatch);
    evt_mon->evtMonWatch = -1;
    virNetDaemonQuit(evt_mon->daemon);
    virMutexUnlock(&lock);
}


/**
 * sreControllerMain
 * @serverFd: server socket fd to accept client requests
 * @clientFd: initial client which is the libvirtd daemon
 *
 * Processes I/O on consoles and the monitor
 *
 * Returns 0 on success or -1 in case of error
 */
static int
virSREControllerMain(virSREControllerPtr ctrl)
{
    int rc = -1;
    size_t i;

    if (virNetDaemonAddSignalHandler(ctrl->daemon,
                                     SIGCHLD,
                                     virSREControllerSignalChildIO,
                                     ctrl) < 0)
        goto cleanup;

    virResetLastError();

    for (i = 0; i < ctrl->nconsoles; i++) {
        if ((ctrl->consoles[i].epollFd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to create epoll fd"));
            goto cleanup;
        }

        if ((ctrl->consoles[i].epollWatch =
             virEventAddHandle(ctrl->consoles[i].epollFd,
                               VIR_EVENT_HANDLE_READABLE,
                               virSREControllerConsoleEPoll,
                               &(ctrl->consoles[i]), NULL)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to watch epoll FD"));
            goto cleanup;
        }

        if ((ctrl->consoles[i].hostWatch =
             virEventAddHandle(ctrl->consoles[i].hostFd,
                               VIR_EVENT_HANDLE_READABLE,
                               virSREControllerConsoleIO,
                               &(ctrl->consoles[i]), NULL)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to watch host console PTY"));
            goto cleanup;
        }

        if ((ctrl->consoles[i].contWatch =
             virEventAddHandle(ctrl->consoles[i].contFd,
                               VIR_EVENT_HANDLE_READABLE,
                               virSREControllerConsoleIO,
                               &(ctrl->consoles[i]), NULL)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to watch host console PTY"));
            goto cleanup;
        }
    }
    if ((ctrl->evtMon->epollFd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create epoll mon fd"));
        goto cleanup;
    }
    if ((ctrl->evtMon->epollWatch =
         virEventAddHandle(ctrl->evtMon->epollFd,
                           VIR_EVENT_HANDLE_READABLE,
                           virSREControllerEventMonEPoll, ctrl->evtMon,
                           NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to watch epoll FD"));
        goto cleanup;
    }
    if ((ctrl->evtMon->evtMonWatch =
         virEventAddHandle(ctrl->evtMon->evtMonFd,
                           VIR_EVENT_HANDLE_READABLE,
                           virSREControllerEvtMonIO, ctrl->evtMon,
                           NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to watch evt mon fd"));
        goto cleanup;
    }


    virNetDaemonRun(ctrl->daemon);

    if (virGetLastErrorCode() == VIR_ERR_OK) {
        rc = (wantReboot || domainShutdown) ? 1 : 0;
    }
    if (domainShutdown) {
        goto cleanup;
        rc = 1;
    }

  cleanup:
    virSREControllerEvtMonClose(ctrl->evtMon);

    for (i = 0; i < ctrl->nconsoles; i++)
        virSREControllerConsoleClose(&(ctrl->consoles[i]));

    return rc;
}



#ifdef VUB_SUPPORT

/* Connect to sre vub TTY for vm, returning
 * the master in *vubfd and the name of the vub device  in
 * *TTYNAME.  */
static int
sreConnectVUB(virSREControllerPtr ctrl, int *vub_fd,
              char **ttyName, int console_idx)
{
    int ret = -1;

    if (virAsprintf(ttyName, "/dev/ttyVUB%d",
                    ctrl->console_channels[console_idx].vub_channel) < 0)
        goto cleanup;
    if ((*vub_fd = open(*ttyName, O_RDWR | O_NONBLOCK)) < 0) {
        VIR_WARN("FAILED OT OPEN VUB %s", *ttyName);
        goto cleanup;
    }
    ret = 0;

  cleanup:
    if (ret != 0) {
        VIR_FREE(*ttyName);
    }

    return ret;
}
#else

/* Create a private tty using the private devpts at PTMX, returning
 * the master in *TTYMASTER and the name of the slave, _from the
 * perspective of the guest after remounting file systems_, in
 * *TTYNAME.  Heavily borrowed from glibc, but doesn't require that
 * devpts == "/dev/pts" */
static int
sreCreateTty(virSREControllerPtr ctrl, int *ttymaster,
             char **ttyName, char **ttyHostPath)
{
    int ret = -1;
    int ptyno;
    int unlock = 0;

    if ((*ttymaster =
         open(ctrl->devptmx, O_RDWR | O_NOCTTY | O_NONBLOCK)) < 0)
        goto cleanup;

    if (ioctl(*ttymaster, TIOCSPTLCK, &unlock) < 0)
        goto cleanup;

    if (ioctl(*ttymaster, TIOCGPTN, &ptyno) < 0)
        goto cleanup;

    /* If mount() succeeded at honoring newinstance, then the kernel
     * was new enough to also honor the mode=0620,gid=5 options, which
     * guarantee that the new pty already has correct permissions; so
     * while glibc has to fstat(), fchmod(), and fchown() for older
     * kernels, we can skip those steps.  ptyno shouldn't currently be
     * anything other than 0, but let's play it safe.  */
    if ((virAsprintf(ttyName, "/dev/pts/%d", ptyno) < 0) ||
        (virAsprintf(ttyHostPath, "/%s/%s.devpts/%d", SRE_STATE_DIR,
                     ctrl->def->name, ptyno) < 0)) {
        errno = ENOMEM;
        goto cleanup;
    }

    ret = 0;

  cleanup:
    if (ret != 0) {
        VIR_FORCE_CLOSE(*ttymaster);
        VIR_FREE(*ttyName);
    }

    return ret;
}
#endif

static unsigned int
virSREControllerLookupUsernsMap(virDomainIdMapEntryPtr map,
                                int num, unsigned int src)
{
    size_t i;

    for (i = 0; i < num; i++) {
        if (src > map[i].start && src < map[i].start + map[i].count)
            return map[i].target + (src - map[i].start);
    }

    return src;
}

static int
virSREControllerSetupDevPTS(virSREControllerPtr ctrl)
{
    char *mount_options = NULL;
    char *opts = NULL;
    char *devpts = NULL;
    int ret = -1;
    gid_t ptsgid = 5;


    mount_options =
        virSecurityManagerGetMountOptions(ctrl->securityManager,
                                          ctrl->def);

    if (virAsprintf(&devpts, "%s/%s.devpts",
                    SRE_STATE_DIR, ctrl->def->name) < 0 ||
        virAsprintf(&ctrl->devptmx, "%s/%s.devpts/ptmx",
                    SRE_STATE_DIR, ctrl->def->name) < 0)
        goto cleanup;

    if (virFileMakePath(devpts) < 0) {
        virReportSystemError(errno, _("Failed to make path %s"), devpts);
        goto cleanup;
    }

    if (ctrl->def->idmap.ngidmap)
        ptsgid = virSREControllerLookupUsernsMap(ctrl->def->idmap.gidmap,
                                                 ctrl->def->idmap.ngidmap,
                                                 ptsgid);

    /* XXX should we support gid=X for X!=5 for distros which use
     * a different gid for tty?  */
    if (virAsprintf(&opts, "newinstance,ptmxmode=0666,mode=0620,gid=%u%s",
                    ptsgid, (mount_options ? mount_options : "")) < 0)
        goto cleanup;

    if (mount("devpts", devpts, "devpts", MS_NOSUID, opts) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount devpts on %s"), devpts);
        goto cleanup;
    }

    if (access(ctrl->devptmx, R_OK) < 0) {
        virReportSystemError(ENOSYS, "%s",
                             _("Kernel does not support private devpts"));
        goto cleanup;
    }

    ret = 0;

  cleanup:
    VIR_FREE(opts);
    VIR_FREE(devpts);
    VIR_FREE(mount_options);
    return ret;
}


#ifdef VUB_SUPPORT
static int
virSREControllerSetupConsoles(virSREControllerPtr ctrl,
                              char **domainTTYPaths)
{
    size_t i;
    int ret = -1;

    for (i = 0; i < ctrl->nconsoles; i++) {
        VIR_DEBUG("Opening tty on private %s", ctrl->devptmx);
        if (sreConnectVUB(ctrl,
                          &ctrl->consoles[i].contFd,
                          &domainTTYPaths[i], i) < 0) {
            virReportSystemError(errno, "%s",
                                 _
                                 ("Failed to allocate vub on controller"));
            goto cleanup;
        }

    }

    ret = 0;
  cleanup:
    return ret;
}
#else
static int
virSREControllerSetupConsoles(virSREControllerPtr ctrl,
                              char **domainTTYPaths)
{
    size_t i;
    int ret = -1;
    char *ttyHostPath = NULL;

    for (i = 0; i < ctrl->nconsoles; i++) {
        VIR_DEBUG("Opening tty on private %s", ctrl->devptmx);
        if (sreCreateTty(ctrl,
                         &ctrl->consoles[i].contFd,
                         &domainTTYPaths[i], &ttyHostPath) < 0) {
            virReportSystemError(errno, "%s", _("Failed to allocate tty"));
            goto cleanup;
        }


        VIR_FREE(ttyHostPath);
    }

    ret = 0;
  cleanup:
    VIR_FREE(ttyHostPath);
    return ret;
}
#endif

static bool first_event_sent = false;
static void
virSREWriteEventToLog(virDomainObjPtr vm,
                      char *message_str, int message_len)
{
    char *logfile = NULL;
    int logfd = -1;
    int log_mode = 0;

    if (vm->def->serials[0]->source->logfile) {
        if (virAsprintf(&logfile, "%s",
                        vm->def->consoles[0]->source->logfile) < 0)
            goto cleanup;
        if (vm->def->consoles[0]->source->logappend ==
            VIR_TRISTATE_SWITCH_OFF && !first_event_sent) {
            log_mode = O_WRONLY | O_APPEND | O_CREAT;
            first_event_sent = true;
        } else {
            log_mode = O_WRONLY | O_APPEND | O_CREAT;
        }
        if ((logfd = open(logfile, log_mode, S_IRUSR | S_IWUSR)) < 0) {
            virReportSystemError(errno, _("Failed to open '%s'"), logfile);
            goto cleanup;
        }
    } else {
        if (virFileMakePath(SRE_LOG_DIR) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create log directory '%s'"),
                                 SRE_LOG_DIR);
            goto cleanup;
        }

        if (virAsprintf(&logfile, "%s/%s-event.log",
                        SRE_LOG_DIR, vm->def->name) < 0)
            goto cleanup;
        if ((logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
                          S_IRUSR | S_IWUSR)) < 0) {
            virReportSystemError(errno, _("Failed to open '%s'"), logfile);
            goto cleanup;
        }
    }
    if (safewrite(logfd, message_str, message_len) < 0)
        goto cleanup;

  cleanup:
    VIR_FREE(logfile);
}

static void
virSREControllerEventSend(virSREControllerPtr ctrl,
                          int procnr, xdrproc_t proc, void *data)
{
    virNetMessagePtr msg;

    if (!ctrl->client) {
        VIR_WARN("Dropping event %d because libvirtd is not connected",
                 procnr);
        return;
    }

    if (!(msg = virNetMessageNew(false)))
        goto error;

    msg->header.prog = virNetServerProgramGetID(ctrl->prog);
    msg->header.vers = virNetServerProgramGetVersion(ctrl->prog);
    msg->header.proc = procnr;
    msg->header.type = VIR_NET_MESSAGE;
    msg->header.serial = 1;
    msg->header.status = VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    if (virNetMessageEncodePayload(msg, proc, data) < 0)
        goto error;

    if (virNetServerClientSendMessage(ctrl->client, msg) < 0)
        goto error;

    xdr_free(proc, data);
    return;

  error:
    virNetMessageFree(msg);
    xdr_free(proc, data);
}


static int
virSREControllerEventSendShutdown(virSREControllerPtr ctrl, int exitstatus)
{
    virSREMonitorShutdownEventMsg msg;
    char *timestamp = NULL;
    char *evt_msg_str = NULL;
    int ret = -1;

    memset(&msg, 0, sizeof(msg));

    switch (exitstatus) {
        case EVT_VM_SHUTDOWN:
            msg.status = VIR_SRE_MONITOR_SHUTDOWN_STATUS_SHUTDOWN;
            break;
            // case 1: //TODO HANDLE SHUTDOWN SUBTYPE for reboot
            //     msg.status = VIR_SRE_MONITOR_EXIT_STATUS_REBOOT;
            //    break;
        default:
            msg.status = VIR_SRE_MONITOR_SHUTDOWN_STATUS_ERROR;
            break;
    }

    virSREControllerEventSend(ctrl,
                              VIR_SRE_MONITOR_PROC_SHUTDOWN_EVENT,
                              (xdrproc_t)
                              xdr_virSREMonitorShutdownEventMsg,
                              (void *) &msg);
    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;

    if (virAsprintf
        (&evt_msg_str,
         "%s: VM Shutdown event detected, domain id %d  name %s status %d\n",
         timestamp, ctrl->vm->def->id, ctrl->vm->def->name,
         exitstatus) < 0)
        goto cleanup;
    VIR_FREE(timestamp);

    virSREWriteEventToLog(ctrl->vm, evt_msg_str, strlen(evt_msg_str));

    if (ctrl->client) {
        VIR_DEBUG("Waiting for client to complete dispatch");
        ctrl->inShutdown = true;
        virNetServerClientDelayedClose(ctrl->client);
        virNetDaemonRun(ctrl->daemon);
    }
    ret = 0;
  cleanup:
    VIR_FREE(evt_msg_str);
    return ret;
}

static int
virSREControllerEventSendStart(virSREControllerPtr ctrl, pid_t guest_id)
{
    virSREMonitorStartEventMsg msg;
    int ret = -1;
    char *evt_msg_str = NULL;
    char *timestamp = NULL;

    memset(&msg, 0, sizeof(msg));

    msg.guest_id = guest_id;

    virSREControllerEventSend(ctrl,
                              VIR_SRE_MONITOR_PROC_START_EVENT,
                              (xdrproc_t) xdr_virSREMonitorStartEventMsg,
                              (void *) &msg);
    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;

    if (virAsprintf
        (&evt_msg_str,
         "%s: VM Startup event detected, domain id %d  name %s\n",
         timestamp, guest_id, ctrl->vm->def->name) < 0)
        goto cleanup;
    VIR_FREE(timestamp);

    virSREWriteEventToLog(ctrl->vm, evt_msg_str, strlen(evt_msg_str));
    ret = 0;
  cleanup:
    VIR_FREE(evt_msg_str);
    return ret;
}


static int
virSREControllerEventSendPolicy(virSREControllerPtr ctrl,
                                pid_t guest_id,
                                event_message_t * event_message)
{
    virSREMonitorPolicyEventMsg *msg = NULL;
    char *evt_msg_str = NULL;
    char *timestamp = NULL;
    int ret = -1;

    if (VIR_ALLOC(msg) < 0) {
        goto cleanup;
    }

    memset(msg, 0, sizeof(virSREMonitorPolicyEventMsg));

    msg->guest_id = guest_id;
    msg->event_type = event_message->event_type;

    //TODO SUBTYPE currently unsupported
    msg->event_subtype = -1;

    memcpy(msg->data, event_message->message_data,
           event_message->message_len);

    msg->data_len = event_message->message_len;

    virSREControllerEventSend(ctrl,
                              VIR_SRE_MONITOR_PROC_POLICY_EVENT,
                              (xdrproc_t) xdr_virSREMonitorPolicyEventMsg,
                              (void *) msg);
    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;

    if (virAsprintf
        (&evt_msg_str,
         "%s: VM Policy Violation event detected, domain id %d  name %s\n",
         timestamp, guest_id, ctrl->vm->def->name) < 0)
        goto cleanup;

    VIR_FREE(timestamp);
    virSREWriteEventToLog(ctrl->vm, evt_msg_str, strlen(evt_msg_str));

    //write event data 
    virSREWriteEventToLog(ctrl->vm, event_message->message_data,
                          event_message->message_len);

    ret = 0;
  cleanup:
    VIR_FREE(evt_msg_str);
    VIR_FREE(msg);
    return ret;
}


static int
virSREControllerRun(virSREControllerPtr ctrl)
{
    int rc = -1;
    int control[2] = { -1, -1 };

    //event reporter handshake fd
    int eventhandshake[2] = { -1, -1 };

    char **domainTTYPaths = NULL;
    size_t i;

    if (VIR_ALLOC_N(domainTTYPaths, ctrl->nconsoles) < 0)
        goto cleanup;

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, control) < 0) {
        virReportSystemError(errno, "%s", _("sockpair failed"));
        goto cleanup;
    }

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, eventhandshake) < 0) {
        virReportSystemError(errno, "%s", _("socketpair failed"));
        goto cleanup;
    }

    if (virSREControllerSetupDevPTS(ctrl) < 0)
        goto cleanup;


    if (virSREControllerSetupConsoles(ctrl, domainTTYPaths) < 0)
        goto cleanup;


    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(eventhandshake[1]);
    VIR_FORCE_CLOSE(eventhandshake[0]);

    for (i = 0; i < ctrl->nconsoles; i++)
        if (virSREControllerConsoleSetNonblocking(&(ctrl->consoles[i])) <
            0)
            goto cleanup;

    //do handshake with monitor
    if (virSREControllerDaemonHandshake(ctrl) < 0)
        goto cleanup;

    /* We must not hold open a dbus connection for life
     * of SRE instance, since dbus-daemon is limited to
     * only a few 100 connections by default
     */
    virDBusCloseSystemBus();

    rc = virSREControllerMain(ctrl);

  cleanup:
    VIR_FORCE_CLOSE(control[0]);
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(eventhandshake[0]);
    VIR_FORCE_CLOSE(eventhandshake[1]);

    for (i = 0; i < ctrl->nconsoles; i++)
        VIR_FREE(domainTTYPaths[i]);
    VIR_FREE(domainTTYPaths);

    virSREControllerStopInit(ctrl);

    return rc;
}


int
main(int argc, char *argv[])
{
    pid_t pid;
    int rc = -1;
    const char *name = NULL;
    int handshakeFd = -1;
    bool bg = false;

    const struct option options[] = {
        {"background", 0, NULL, 'b'},
        {"name", 1, NULL, 'n'},
        {"console", 1, NULL, 'c'},
        {"handshakefd", 1, NULL, 's'},
        {"security", 1, NULL, 'S'},
        {"help", 0, NULL, 'h'},
        {0, 0, 0, 0},
    };
    int *ttyFDs = NULL;
    size_t nttyFDs = 0;
    virSREControllerPtr ctrl = NULL;
    size_t i;
    const char *securityDriver = "none";

    if (virGettextInitialize() < 0 ||
        virThreadInitialize() < 0 || virErrorInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Initialize logging */
    virLogSetFromEnv();
    while (1) {
        int c;

        c = getopt_long(argc, argv, "dn:v:p:m:c:s:h:S:N:I:U:",
                        options, NULL);

        if (c == -1)
            break;

        switch (c) {
            case 'b':
                bg = true;
                break;

            case 'n':
                name = optarg;
                break;

            case 'c':
                if (VIR_REALLOC_N(ttyFDs, nttyFDs + 1) < 0)
                    goto cleanup;
                if (virStrToLong_i(optarg, NULL, 10, &ttyFDs[nttyFDs++]) <
                    0) {
                    fprintf(stderr, "malformed --console argument '%s'",
                            optarg);
                    goto cleanup;
                }
                break;

            case 's':
                if (virStrToLong_i(optarg, NULL, 10, &handshakeFd) < 0) {
                    fprintf(stderr,
                            "malformed --handshakefd argument '%s'",
                            optarg);
                    goto cleanup;
                }
                break;

            case 'S':
                securityDriver = optarg;
                break;

            case 'h':
            case '?':
                fprintf(stderr, "\n");
                fprintf(stderr, "syntax: %s [OPTIONS]\n", argv[0]);
                fprintf(stderr, "\n");
                fprintf(stderr, "Options\n");
                fprintf(stderr, "\n");
                fprintf(stderr, "  -b, --background\n");
                fprintf(stderr, "  -n NAME, --name NAME\n");
                fprintf(stderr, "  -c FD, --console FD\n");
                fprintf(stderr, "  -s FD, --handshakefd FD\n");
                fprintf(stderr, "  -S NAME, --security NAME\n");
                fprintf(stderr, "  -h, --help\n");
                fprintf(stderr, "\n");
                rc = 0;
                goto cleanup;
        }
    }

    if (name == NULL) {
        fprintf(stderr, "%s: missing --name argument for configuration\n",
                argv[0]);
        goto cleanup;
    }

    if (handshakeFd < 0) {
        fprintf(stderr,
                "%s: missing --handshakefd argument for container PTY\n",
                argv[0]);
        goto cleanup;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s: must be run as the 'root' user\n", argv[0]);
        goto cleanup;
    }

    virEventRegisterDefaultImpl();

    virDBusSetSharedBus(false);

    if (!(ctrl = virSREControllerNew(name)))
        goto cleanup;

    if (VIR_ALLOC(ctrl->evtMon) < 0)
        goto cleanup;
    ctrl->evtMon->daemon = ctrl->daemon;
    ctrl->evtMon->ctrl = ctrl;

    ctrl->handshakeFd = handshakeFd;

    if (!(ctrl->securityManager = virSecurityManagerNew(securityDriver,
                                                        SRE_DRIVER_NAME,
                                                        0)))
        goto cleanup;

    if (ctrl->def->seclabels) {
        VIR_DEBUG("Security model %s type %s label %s imagelabel %s",
                  NULLSTR(ctrl->def->seclabels[0]->model),
                  virDomainSeclabelTypeToString(ctrl->def->seclabels[0]->
                                                type),
                  NULLSTR(ctrl->def->seclabels[0]->label),
                  NULLSTR(ctrl->def->seclabels[0]->imagelabel));
    } else {
        VIR_DEBUG("Security model not initialized");
    }

    for (i = 0; i < nttyFDs; i++) {
        if (virSREControllerAddConsole(ctrl, ttyFDs[i]) < 0)
            goto cleanup;
        ttyFDs[i] = -1;
    }

    if (virSREControllerValidateConsoles(ctrl) < 0)
        goto cleanup;

    if (virSREControllerSetupServer(ctrl) < 0)
        goto cleanup;
    if (virSREControllerSetupEvtMonitor(ctrl) < 0)
        goto cleanup;

    if (bg) {
        if ((pid = fork()) < 0)
            goto cleanup;

        if (pid > 0) {
            if ((rc = virPidFileWrite(SRE_STATE_DIR, name, pid)) < 0) {
                virReportSystemError(-rc,
                                     _
                                     ("Unable to write pid file '%s/%s.pid'"),
                                     SRE_STATE_DIR, name);
                _exit(1);
            }

            /* First child now exits, allowing original caller
             * (ie libvirtd's SRE driver to complete their
             * waitpid & continue */
            _exit(0);
        }

        /* Don't hold on to any cwd we inherit from libvirtd either */
        if (chdir("/") < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to change to root dir"));
            goto cleanup;
        }

        if (setsid() < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to become session leader"));
            goto cleanup;
        }
    }

    rc = virSREControllerRun(ctrl);

  cleanup:
    if (rc < 0) {
        fprintf(stderr,
                _("Failure in libvirt_sre startup: %s\n"),
                virGetLastErrorMessage());
    }

    virPidFileDelete(SRE_STATE_DIR, name);
    for (i = 0; i < nttyFDs; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    VIR_FREE(ttyFDs);

    virSREControllerFree(ctrl);

    return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
