// Zig doesn't have proper CMSG bindings, so rather than try to bolt
// that together, we'll just write our own tiny message passing system in C

#ifndef IPC_H
#define IPC_H

#include <stddef.h>
#include <unistd.h>

// Maximum number of file descriptors we can handle in one message
#define MAX_FDS 20

// Error codes
#define IPC_ERROR_SOCKET -1
#define IPC_ERROR_PROTOCOL -2
#define IPC_ERROR_BUFFER -3

// Return values:
// IPC_SUCCESS: Success
// IPC_ERROR_SOCKET: Socket error (check errno)
// IPC_ERROR_PROTOCOL: Protocol error (invalid message format)
// IPC_ERROR_BUFFER: Buffer too small
ssize_t readMessage(int socket_fd,
    void* out_msg, size_t out_msg_size,
    int* out_fds, size_t out_fds_max, size_t* out_fds_count);
int writeMessage(int socket_fd, void* msg, size_t msg_count, int* fds, size_t fds_count);

#endif
