#include <config.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "sre_evt_ctl_socket.h"
#include<unistd.h>
#define MAX_BUF_SIZE 512
#define MAX_NODES 2

static int __rec_evt_message(int fd, char *data_buffer, int buffer_size,
                             evt_ctl_socket_cmd_types_t message_type);

int
make_named_socket(const char *filename)
{
    struct sockaddr_un name;
    int sock;
    size_t size;

    /* Create the socket. */
    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    /* Bind a name to the socket. */
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, filename, sizeof(name.sun_path));

    /* The size of the address is
     * the offset of the start of the filename,
     * plus its length,
     * plus one for the terminating null byte.
     * Alternatively you can just do:
     * size = SUN_LEN (&name);
     */
    size = (offsetof(struct sockaddr_un, sun_path)
            + strlen(name.sun_path) + 1);

    if (bind(sock, (struct sockaddr *) &name, size) < 0) {
        return -1;
    }

    return sock;
}

int
send_handshake_message_client(handshake_message_t handshake,
                              const char *target_sock_path)
{
    return _send_evt_message(target_sock_path, (char *) &handshake,
                             sizeof(handshake_message_t),
                             EVT_MSG_SOCKET_INIT_CTL,
                             EVT_SERVER_CONTROL_TYPE);
}

int
send_handshake_message_server(handshake_message_t handshake,
                              const char *target_sock_path)
{
    return _send_evt_message(target_sock_path, (char *) &handshake,
                             sizeof(handshake_message_t),
                             EVT_MSG_SOCKET_INIT_CTL,
                             EVT_CLIENT_DATA_TYPE);
}

int
send_event_message_server(event_message_t event,
                          const char *target_sock_path)
{
    return _send_evt_message(target_sock_path, (char *) &event,
                             sizeof(event_message_t),
                             EVT_MSG_SOCKET_DATA_CTL,
                             EVT_CLIENT_DATA_TYPE);
}

//returns message type
int
rec_evt_message_client(int fd, char *data_buffer, int buffer_size)
{
    return __rec_evt_message(fd, data_buffer, buffer_size,
                             EVT_CLIENT_DATA_TYPE);
}

//returns message type
int
rec_evt_message_server(int fd, char *data_buffer, int buffer_size)
{
    return __rec_evt_message(fd, data_buffer, buffer_size,
                             EVT_SERVER_CONTROL_TYPE);

}

int
_send_evt_message(const char *target_sock_path,
                  char *data_buf,
                  int buf_size,
                  evt_ctl_socket_message_types_t message_type,
                  evt_ctl_socket_cmd_types_t command_type)
{
    int ctl_sock;
    struct msghdr message_header;
    struct sockaddr_un ctl_name;
    evt_ctl_header_t header_data;

    header_data.evt_cmd_type = command_type;
    header_data.evt_ctl_cmd_version = EVT_MESSAGE_VERSION;
    header_data.evt_msg_type = message_type;

    struct iovec iov[EVT_CTL_NUM_BLOCKS];

    iov[0].iov_base = &header_data;
    iov[0].iov_len = sizeof(evt_ctl_header_t);
    iov[1].iov_base = data_buf;
    iov[1].iov_len = buf_size;
    /* Create socket on which to send. */
    ctl_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (ctl_sock < 0) {
        printf("ERROR opening socket\n");
        return 0;
    }
    memset(&message_header, 0, sizeof(message_header));
    /* Construct name of socket to send to. */
    ctl_name.sun_family = AF_UNIX;
    strcpy(ctl_name.sun_path, target_sock_path);

    cmsg_evt_header_data cmsg_header;

    memset(&cmsg_header, 0, sizeof(cmsg_evt_header_data));
    // setup_cmsg_buf(&message_header,&cmsg_header,message_type,command_type,ctl_sock);

    message_header.msg_name = &ctl_name;
    message_header.msg_namelen =
        offsetof(struct sockaddr_un, sun_path) + strlen(ctl_name.sun_path);
    message_header.msg_iov = iov;
    message_header.msg_iovlen = 2;
    message_header.msg_control = 0;
    message_header.msg_controllen = 0;
    int ret = -1;

    //do {
    ret = sendmsg(ctl_sock, &message_header, 0);
    if (ret < 0) {
        printf("error sending  message %d %s\n", ret, strerror(errno));
        sleep(5);
    }
    // }while(ret < 0);
    close(ctl_sock);
    return 1;
}

static int
__rec_evt_message(int fd, char *data_buffer, int buffer_size,
                  evt_ctl_socket_cmd_types_t command_type)
{
    struct sockaddr_storage src_addr;
    char buffer[sizeof(event_message_t)];
    evt_ctl_header_t header_data;
    evt_ctl_header_t *control_header = NULL;

    header_data.evt_cmd_type = command_type;
    header_data.evt_ctl_cmd_version = EVT_MESSAGE_VERSION;
    header_data.evt_msg_type = EVT_MSG_SOCKET_UNHANDLED;

    struct iovec iov[EVT_CTL_NUM_BLOCKS];

    iov[0].iov_base = &header_data;
    iov[0].iov_len = sizeof(evt_ctl_header_t);
    iov[1].iov_base = buffer;
    iov[1].iov_len = buffer_size;

    struct msghdr message_header;

    memset(&message_header, 0, sizeof(message_header));
    message_header.msg_name = &src_addr;
    message_header.msg_namelen = sizeof(src_addr);
    message_header.msg_iov = iov;
    message_header.msg_iovlen = 2;
    message_header.msg_control = 0;
    message_header.msg_controllen = 0;

    ssize_t count = recvmsg(fd, &message_header, 0);

    if ((message_header.msg_flags & MSG_TRUNC)
        || (message_header.msg_flags & MSG_CTRUNC)) {
        printf("Error message truncated");
        return 0;
    }

    if (count == -1) {
        printf("Error rec_mesg %s\n", strerror(errno));
        return 0;
    } else {
        control_header = (evt_ctl_header_t *) iov[0].iov_base;
        if (iov[0].iov_len != sizeof(evt_ctl_header_t)) {
            printf("Error unexpected control header size");
            return 0;
        }
        if (buffer_size != (int) iov[1].iov_len) {
            printf("datagram size %d expected given buffer_size %d",
                   (int) message_header.msg_iovlen, buffer_size);
            return 0;
        }
        if (control_header->evt_cmd_type != command_type) {
            printf("Uexpected command type expectedf %d got %d\n",
                   command_type, control_header->evt_cmd_type);
            return 0;
        }
        if (control_header->evt_ctl_cmd_version != EVT_MESSAGE_VERSION) {
            printf("Uexpected command version expectedf %d got %d\n",
                   EVT_MESSAGE_VERSION,
                   control_header->evt_ctl_cmd_version);
            return 0;
        }
        memcpy(data_buffer, buffer, buffer_size);
    }
    return (int) control_header->evt_msg_type;
}

// void sre_event_setup_socket()
// {
//       int test_fd;
//       unlink (path.c_str());
//       test_fd = make_named_socket(path.c_str());
//       handshake_message_t handshake;
//       memset(&handshake,0,sizeof(handshake_message_t));
//       handshake.action = SOCKET_TEST_CTL;
//       memcpy(handshake.sock_path,path.c_str(),TEST_CLIENT_LEN);
//       send_handshake_message(handshake, (char*)LM_EVT_CTL_SOCKET_PATH);

//       dbg("sent client handshake waiting for response on new fd %d\n",test_fd);
//       handshake_message_t response_message;
//       memset(&response_message,0,sizeof(handshake_message_t));

//       int ret = recv(test_fd, &response_message, sizeof(handshake_message_t), 0);
//       if (ret < 0)  
//       {
//         error("ERROR on client responce rec\n");
//       }
//       else
//       {
//         dbg("Recieved client response SUCCESS\n");
//       }
//       unlink (path.c_str());
// }
