#ifndef SRE_EVT_CTL_SOCKET_H
#define SRE_EVT_CTL_SOCKET_H
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#define GUEST_UUID_SIZE 37

#define LM_EVT_CTL_SOCKET_PATH "/var/run/sre_event_monitor_control.soc"

#define LM_EVT_CTL_SOCKET_TEST_CLIENT1_PATH "/tmp/sre-test-client1.soc"

//#define LM_EVT_CTL_SOCKET_TEST_CLIENT1_UUID "e6b779a3-aa23-4af1-954c-d4f69ae500e0" dom1b
#define LM_EVT_CTL_SOCKET_TEST_CLIENT1_UUID "9f6f07bd-60e6-4f7f-9af1-15e1a43bcbe8"
#define LM_EVT_CTL_SOCKET_TEST_CLIENT1_DOMAIN_ID 1234
#define LM_EVT_CTL_SOCKET_TEST_CLIENT1_MESSAGE "HELLO TEST MESSAGE"

#define TEST_CLIENT_LEN sizeof(LM_EVT_CTL_SOCKET_TEST_CLIENT1_PATH)
#define MAX_PATH_LEN 108        //SUN PATH FROM un.h
#define MAX_MSG_LEN 2048
#define SRE_EVT_MON_CTL_STOP "SRE_EVT_MON_CTL_STOP"

#define EVT_MESSAGE_VERSION 1
#define EVT_CTL_NUM_BLOCKS 2

/******************************************************************************/

/**
 * @brief Definition of the event report type.
 *
 ******************************************************************************/
typedef enum {

    EVT_VM_POLICY = 0,        /**< Event reporter policy violation. */

    EVT_VM_SHUTDOWN = 1,      /**< Event reporter VM shutdown. */

    EVT_MCE = 2,              /**< MCE. */

    EVT_HV_ERR = 3,           /**< Hypervisor error */

    EVT_GEN1 = 4,             /**< Generic event 1. */

    EVT_VM_STARTUP = 5,       /**< VM Startup Event */

    EVT_VTD_FAULT = 6,        /**< VT-d Fault Event */

    EVT_MAX                   /**< Max. */
} evt_type_t;

typedef enum {

    EVT_SUB_VM_SHUTDOWN_OFF = 0,   /**< Shutdown Poweroff. */

    EVT_SUB_VM_SHUTDOWN_POL = 1,   /**< Shutdown Policy Violation */

    EVT_SUB_VM_SHUTDOWN_REBOOT = 2,/**< Shutdown Reboot */

    EVT_SUB_VM_SHUTDOWN_ERR = 3,   /**< Shutdown HV Error */
    EVT_SUB_VM_SHUTDOWN_MAX
} evt_shutdown_subtype_t;


typedef enum {
    EVT_MSG_SOCKET_UNHANDLED = -1,
    EVT_MSG_SOCKET_INIT_CTL = 1,
    EVT_MSG_SOCKET_CLOSE_CTL = 2,
    EVT_MSG_SOCKET_DATA_CTL = 3,
} evt_ctl_socket_message_types_t;

typedef enum {
    EVT_SERVER_CONTROL_TYPE = 1,
    EVT_CLIENT_DATA_TYPE = 2
} evt_ctl_socket_cmd_types_t;

typedef struct evt_ctl_header_struct_t {
    evt_ctl_socket_message_types_t evt_msg_type;
    evt_ctl_socket_cmd_types_t evt_cmd_type;
    int evt_ctl_cmd_version;
} evt_ctl_header_t;

#define CMSG_SIZE sizeof(evt_ctl_header_t)


typedef union {                 /* Ancillary data buffer, wrapped in a union
                                 * in order to ensure it is suitably aligned */
    struct cmsghdr align;
    unsigned char cdata[CMSG_SPACE(sizeof(int))];
} cmsg_evt_header_data;;


typedef struct handshake_message_struct_t {
    char sock_path[MAX_PATH_LEN];
    char uuid[GUEST_UUID_SIZE];
    int guest_id;
} handshake_message_t;

typedef struct event_message_struct_t {
    char uuid[GUEST_UUID_SIZE];
    int guest_id;
    evt_type_t event_type;
    int event_subtype;
    char message_data[MAX_MSG_LEN];
    int message_len;
} event_message_t;


int make_named_socket(const char *filename);

int send_handshake_message_server(handshake_message_t handshake,
                                  const char *target_sock_path);
int send_handshake_message_client(handshake_message_t handshake,
                                  const char *target_sock_path);

int rec_evt_message_server(int fd, char *data_buffer, int buffer_size);
int rec_evt_message_client(int fd, char *data_buffer, int buffer_size);

int send_event_message_server(event_message_t event,
                              const char *target_sock_path);

int _send_evt_message(const char *target_sock_path,
                      char *data_buf,
                      int buf_size,
                      evt_ctl_socket_message_types_t message_type,
                      evt_ctl_socket_cmd_types_t command_type);

#endif
