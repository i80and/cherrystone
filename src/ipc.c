#include "ipc.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>



ssize_t readMessage(int socket_fd,
    void* out_msg, size_t out_msg_size,
    int* out_fds, size_t out_fds_max, size_t* out_fds_count) {
    struct msghdr msg;
    struct iovec iov;

    // Always initialize to zero. On success we can increase it if needed
    *out_fds_count = 0;

    // Properly aligned buffer for control messages
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(MAX_FDS * sizeof(int))];
    } cmsg_buf;

    memset(&msg, 0, sizeof(msg));
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    // Set up the message buffer to receive the entire packet
    iov.iov_base = out_msg;
    iov.iov_len = out_msg_size;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    ssize_t bytes_received;
    do {
        bytes_received = recvmsg(socket_fd, &msg, 0);
    } while (bytes_received == -1 && errno == EINTR);

    if (bytes_received <= 0 || (size_t)bytes_received < sizeof(size_t)) {
        return IPC_ERROR_SOCKET; // Socket error
    }

    // Extract the message length from the first part of the received data
    size_t msg_len;
    memcpy(&msg_len, out_msg, sizeof(size_t));

    // Verify the message length makes sense
    if (msg_len > out_msg_size - sizeof(size_t)) {
        return IPC_ERROR_BUFFER; // Buffer too small
    }

    if ((size_t)bytes_received != sizeof(size_t) + msg_len) {
        return IPC_ERROR_PROTOCOL; // Protocol error
    }

    // Move the actual message data to the beginning of the buffer
    memmove(out_msg, out_msg + sizeof(size_t), msg_len);

    // Process control messages (file descriptors)
    struct cmsghdr* cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            // Calculate number of file descriptors received
            size_t fd_count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

            // Limit to what we can store
            if (fd_count > out_fds_max) {
                // Close excess file descriptors to prevent leaks
                int* fds = (int*)CMSG_DATA(cmsg);
                for (size_t i = out_fds_max; i < fd_count; i++) {
                    close(fds[i]);
                }
                fd_count = out_fds_max;
            }

            // Copy file descriptors to output buffer
            memcpy(out_fds, CMSG_DATA(cmsg), fd_count * sizeof(int));
            *out_fds_count = fd_count;
            break;
        }
    }

    return msg_len; // Success
}

int writeMessage(int socket_fd, void* msg, size_t msg_count, int* fds, size_t fds_count) {
    struct msghdr msghdr;
    struct iovec iov[2];

    // Properly aligned buffer for control messages
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(MAX_FDS * sizeof(int))];
    } cmsg_buf;

    memset(&msghdr, 0, sizeof(msghdr));
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    // First iov entry contains the message length
    iov[0].iov_base = &msg_count;
    iov[0].iov_len = sizeof(msg_count);

    // Second iov entry contains the actual message data
    iov[1].iov_base = msg;
    iov[1].iov_len = msg_count;

    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 2;

    // Set up control message for file descriptors if any
    if (fds_count > 0) {
        // Check if we have too many file descriptors
        if (fds_count > MAX_FDS) {
            return IPC_ERROR_BUFFER; // Buffer too small (too many fds)
        }

        msghdr.msg_control = &cmsg_buf;
        msghdr.msg_controllen = CMSG_SPACE(fds_count * sizeof(int));

        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msghdr);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(fds_count * sizeof(int));

        // Copy file descriptors to control message
        memcpy(CMSG_DATA(cmsg), fds, fds_count * sizeof(int));
    }

    // Send the message, retrying on EINTR
    ssize_t bytes_sent;
    do {
        bytes_sent = sendmsg(socket_fd, &msghdr, 0);
    } while (bytes_sent == -1 && errno == EINTR);

    if (bytes_sent == -1) {
        return IPC_ERROR_SOCKET; // Socket error (errno is set)
    }

    return 0; // Success
}
