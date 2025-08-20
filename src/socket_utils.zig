const std = @import("std");
const sys_socket = @cImport({
    @cInclude("sys/socket.h");
});

fn build_cmsg(struct wl_ring_buffer *buffer, const []u8 data, usize *clen) !sys_socket.msghdr {
	struct cmsghdr *cmsg;
	size_t size;

	size = ring_buffer_size(buffer);
	if (size > MAX_FDS_OUT * sizeof(int32_t))
		size = MAX_FDS_OUT * sizeof(int32_t);

	if (size > 0) {
		cmsg = (struct cmsghdr *) data;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(size);
		ring_buffer_copy(buffer, CMSG_DATA(cmsg), size);
		*clen = cmsg->cmsg_len;
	} else {
		*clen = 0;
	}
}


pub fn sendMessage(fd: std.posix.fd_t, data: []const u8, maybe_ancillary_fd: ?std.posix.fd_t) !void {
    if (data.len == 0 and maybe_ancillary_fd != null) {
        std.debug.panic("Cannot send empty data with ancillary data", .{});
    }

    var iov = sys_socket.iovec{
        .iov_base = @constCast(@ptrCast(&data)),
        .iov_len = data.len,
    };

    var msgh = sys_socket.msghdr{
        .msg_name = null,
        .msg_namelen = 0,
        .msg_iov = @ptrCast(&iov),
        .msg_iovlen = 1,
        .msg_control = null,
        .msg_controllen = 0,
        .msg_flags = 0,
    };

    if (maybe_ancillary_fd) |ancillary_fd| {
        const fd_t_sizeof = @sizeOf(std.posix.fd_t);
        const control_buffer: [sys_socket.CMSG_SPACE(fd_t_sizeof)]u8 align(@alignOf(usize)) = std.mem.zeroes([sys_socket.CMSG_SPACE(fd_t_sizeof)]u8);

        msgh.msg_control = @constCast(@ptrCast(&control_buffer));
        msgh.msg_controllen = control_buffer.len;

        //Set message header to describe the ancillary data that we want to send.
        const cmsgp_ptr = sys_socket.CMSG_FIRSTHDR(&msgh);
        if (cmsgp_ptr) |cmsgp| {
            cmsgp.*.cmsg_len = sys_socket.CMSG_LEN(fd_t_sizeof);
            cmsgp.*.cmsg_level = sys_socket.SOL_SOCKET;
            cmsgp.*.cmsg_type = sys_socket.SCM_RIGHTS;

            // CMSG_DATA() seems busted going through cImport, so calculate the data pointer manually
            const cmsg_hdr_size = @sizeOf(sys_socket.cmsghdr);
            const aligned_hdr_size = std.mem.alignForward(usize, cmsg_hdr_size, @alignOf(c_int));
            const data_ptr = @as([*]u8, @ptrCast(cmsgp)) + aligned_hdr_size;
            @memcpy(data_ptr[0..fd_t_sizeof], std.mem.asBytes(&ancillary_fd));
        }
    }

    const bytesWritten = try std.posix.sendmsg(fd, @ptrCast(&msgh), 0);
    std.debug.assert(bytesWritten == data.len);
}

pub fn recvMessage(fd: std.posix.fd_t) !void {
    //
    var buf: [4096]u8 = undefined;

    var iov = sys_socket.iovec{
        .iov_base = &buf,
        .iov_len = buf.len,
    };

    var msgh = sys_socket.msghdr{
        .msg_name = null,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = null,
        .msg_controllen = 0,
        .msg_flags = 0,
    };

    _ = try std.c.recvmsg(fd, @ptrCast(&msgh), 0);
}
