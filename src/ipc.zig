const std = @import("std");
const c = @cImport({
    @cInclude("ipc.h");
    @cInclude("sys/socket.h");
    @cInclude("unistd.h");
});

// Error codes from ipc.h
const IPC_ERROR_SOCKET: c_int = c.IPC_ERROR_SOCKET;
const IPC_ERROR_PROTOCOL: c_int = c.IPC_ERROR_PROTOCOL;
const IPC_ERROR_BUFFER: c_int = c.IPC_ERROR_BUFFER;

// Public error type for IPC operations
pub const IpcError = error{
    SocketError,
    ProtocolError,
    BufferTooSmall,
    UnknownError,
};

// Convert C error code to Zig error
fn cErrorToZigError(err: isize) IpcError {
    return switch (err) {
        IPC_ERROR_SOCKET => IpcError.SocketError,
        IPC_ERROR_PROTOCOL => IpcError.ProtocolError,
        IPC_ERROR_BUFFER => IpcError.BufferTooSmall,
        else => IpcError.UnknownError,
    };
}

/// Read a message along with an associated sequence of FDs into a provided buffer.
/// The socket should be opened std.os.unix.AF.UNIX, std.posix.SOCK.SEQPACKET
pub fn readMessage(socket_fd: std.posix.fd_t, msg_buffer: []u8, fds_buffer: []std.posix.fd_t) IpcError!struct { []u8, []std.posix.fd_t } {
    var fds_count: usize = 0;
    const result = c.readMessage(socket_fd, msg_buffer.ptr, msg_buffer.len, fds_buffer.ptr, fds_buffer.len, &fds_count);
    if (result < 0) {
        return cErrorToZigError(result);
    }

    return struct { []u8, []std.posix.fd_t }{
        msg_buffer[0..@as(usize, @intCast(result))],
        fds_buffer[0..fds_count],
    };
}

/// Write a message along with an associated sequence of FDs.
/// The socket should be opened std.os.unix.AF.UNIX, std.posix.SOCK.SEQPACKET
pub fn writeMessage(socket_fd: std.posix.fd_t, msg: []const u8, fds: []const std.posix.fd_t) IpcError!void {
    const result = c.writeMessage(socket_fd, @ptrCast(@constCast(msg.ptr)), msg.len, @ptrCast(@constCast(fds.ptr)), fds.len);
    if (result != 0) {
        return cErrorToZigError(result);
    }

    return;
}

// Tests
// Test helper functions
/// Builds a socket pair
const TestSocketPair = struct {
    socket_a: c_int,
    socket_b: c_int,

    fn init() !TestSocketPair {
        var sockets: [2]c_int = undefined;
        const result = c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.SEQPACKET, 0, &sockets);
        if (result != 0) {
            return error.SocketError;
        }
        return TestSocketPair{
            .socket_a = sockets[0],
            .socket_b = sockets[1],
        };
    }

    fn deinit(self: TestSocketPair) void {
        _ = c.close(self.socket_a);
        _ = c.close(self.socket_b);
    }
};

const TestPipe = struct {
    read_fd: c_int,
    write_fd: c_int,

    fn init() !TestPipe {
        var pipe: [2]c_int = undefined;
        const result = c.pipe(&pipe);
        if (result != 0) {
            return error.PipeError;
        }
        return TestPipe{
            .read_fd = pipe[0],
            .write_fd = pipe[1],
        };
    }

    fn deinit(self: TestPipe) void {
        _ = c.close(self.read_fd);
        _ = c.close(self.write_fd);
    }
};

fn createMultiplePipes(comptime count: usize) ![count]TestPipe {
    var pipes: [count]TestPipe = undefined;
    for (0..count) |i| {
        pipes[i] = try TestPipe.init();
    }
    return pipes;
}

fn closeMultiplePipes(comptime count: usize, pipes: [count]TestPipe) void {
    for (pipes) |pipe| {
        pipe.deinit();
    }
}

fn closeFds(fds: []const c_int) void {
    for (fds) |fd| {
        _ = c.close(fd);
    }
}

test "Error code conversion" {
    try std.testing.expectEqual(IpcError.SocketError, cErrorToZigError(IPC_ERROR_SOCKET));
    try std.testing.expectEqual(IpcError.ProtocolError, cErrorToZigError(IPC_ERROR_PROTOCOL));
    try std.testing.expectEqual(IpcError.BufferTooSmall, cErrorToZigError(IPC_ERROR_BUFFER));
    try std.testing.expectEqual(IpcError.UnknownError, cErrorToZigError(-999));
}

test "Empty message handling" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const msg = "";
    const fds: []const c_int = &.{};

    try writeMessage(sockets.socket_a, msg, fds);

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;
    const read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);

    try testing.expect(read_result[0].len == 0);
    try testing.expect(read_result[1].len == 0);
}

test "Empty message with fds handling" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const pipe = try TestPipe.init();
    defer pipe.deinit();

    const msg = "";
    const one_fd = &[_]c_int{pipe.read_fd};

    try writeMessage(sockets.socket_a, msg, one_fd);

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;
    const read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);

    try testing.expect(read_result[0].len == 0);
    try testing.expect(read_result[1].len == 1);
}

test "Basic message passing without file descriptors" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const msg = "ping no fds";
    const no_fds: []const c_int = &.{};

    try writeMessage(sockets.socket_a, msg, no_fds);

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;
    const read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);

    try testing.expectEqualSlices(u8, msg, read_result[0]);
    try testing.expect(read_result[1].len == 0);
}

test "Single file descriptor passing" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const pipe = try TestPipe.init();
    defer pipe.deinit();

    const msg = "ping one fd";
    const one_fd = &[_]c_int{pipe.read_fd};

    try writeMessage(sockets.socket_a, msg, one_fd);

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;
    const read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);

    try testing.expectEqualSlices(u8, msg, read_result[0]);
    try testing.expect(read_result[1].len == 1);

    // Close received fd
    closeFds(read_result[1]);
}

test "Multiple file descriptor passing" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const pipes = try createMultiplePipes(2);
    defer closeMultiplePipes(2, pipes);

    const msg = "ping two fds";
    const two_fds = &[_]c_int{ pipes[0].read_fd, pipes[1].read_fd };

    // Write test data to the write ends before sending the read ends
    const test_data = "test data for the fds we send";

    const write_result = c.write(pipes[0].write_fd, test_data.ptr, test_data.len);
    try testing.expect(write_result == test_data.len);

    try writeMessage(sockets.socket_a, msg, two_fds);

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;
    const read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);

    try testing.expectEqualSlices(u8, msg, read_result[0]);
    try testing.expect(read_result[1].len == 2);

    // Verify the received file descriptors are usable by reading the test data
    var read_buffer: [64]u8 = undefined;

    const bytes_read = c.read(read_result[1][0], &read_buffer, read_buffer.len);
    try testing.expect(bytes_read == test_data.len);
    try testing.expectEqualSlices(u8, test_data, read_buffer[0..@intCast(bytes_read)]);

    closeFds(read_result[1]);
}

test "Maximum allowed file descriptors" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const msg = "ping max fds";

    // Create MAX_FDS pipes for testing
    var pipes: [c.MAX_FDS][2]c_int = undefined;
    var max_fds: [c.MAX_FDS]c_int = undefined;

    for (0..c.MAX_FDS) |i| {
        if (c.pipe(&pipes[i]) != 0) {
            return error.PipeError;
        }
        max_fds[i] = pipes[i][0];
    }
    defer {
        for (0..c.MAX_FDS) |i| {
            _ = c.close(pipes[i][0]);
            _ = c.close(pipes[i][1]);
        }
    }

    try writeMessage(sockets.socket_a, msg, &max_fds);

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;
    const read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);

    try testing.expectEqualSlices(u8, msg, read_result[0]);
    try testing.expect(read_result[1].len == c.MAX_FDS);

    closeFds(read_result[1]);
}

test "Excess file descriptors are closed on receipt" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const msg = "ping max fds with small read buffer";

    // Create MAX_FDS pipes for testing
    var pipes: [c.MAX_FDS][2]c_int = undefined;
    var max_fds: [c.MAX_FDS]c_int = undefined;

    for (0..c.MAX_FDS) |i| {
        if (c.pipe(&pipes[i]) != 0) {
            return error.PipeError;
        }
        max_fds[i] = pipes[i][0];
    }
    defer {
        for (0..c.MAX_FDS) |i| {
            _ = c.close(pipes[i][0]);
            _ = c.close(pipes[i][1]);
        }
    }

    // Successfully send MAX_FDS file descriptors
    try writeMessage(sockets.socket_a, msg, &max_fds);

    // Try to read into a smaller buffer (MAX_FDS - 1)
    // The excess fd should be automatically closed by the C implementation
    var msg_buffer: [1024]u8 = undefined;
    var small_fds_buffer: [c.MAX_FDS - 1]c_int = undefined;
    const read_result = try readMessage(sockets.socket_b, &msg_buffer, &small_fds_buffer);

    try testing.expectEqualSlices(u8, msg, read_result[0]);
    // Should only receive MAX_FDS - 1 fds, the excess one is closed automatically
    try testing.expect(read_result[1].len == c.MAX_FDS - 1);

    closeFds(read_result[1]);

    // Note: The excess fd (pipes[MAX_FDS-1][0]) is automatically closed by
    // the C implementation in readMessage() to prevent fd leaks
}

test "Error when sending too many file descriptors" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const msg = "ping too many fds";

    // Create MAX_FDS + 1 pipes for testing
    var pipes: [c.MAX_FDS + 1][2]c_int = undefined;
    var too_many_fds: [c.MAX_FDS + 1]c_int = undefined;

    for (0..c.MAX_FDS + 1) |i| {
        if (c.pipe(&pipes[i]) != 0) {
            return error.PipeError;
        }
        too_many_fds[i] = pipes[i][0];
    }
    defer {
        for (0..c.MAX_FDS + 1) |i| {
            _ = c.close(pipes[i][0]);
            _ = c.close(pipes[i][1]);
        }
    }

    // Should get an error when trying to send too many fds
    const write_result = writeMessage(sockets.socket_a, msg, &too_many_fds);
    try testing.expectError(IpcError.BufferTooSmall, write_result);
}

test "Bidirectional ping-pong with file descriptor forwarding" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const ping_msg = "ping";
    const pong_msg = "pong";

    const pipe = try TestPipe.init();
    defer pipe.deinit();

    // Send ping from A to B with fd
    const ping_fds = &[_]c_int{pipe.read_fd};
    try writeMessage(sockets.socket_a, ping_msg, ping_fds);

    // Receive ping at B
    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;
    var read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, ping_msg, read_result[0]);
    try testing.expect(read_result[1].len == 1);

    // Send pong back from B to A with received fd
    try writeMessage(sockets.socket_b, pong_msg, read_result[1]);

    // Receive pong at A
    read_result = try readMessage(sockets.socket_a, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, pong_msg, read_result[0]);
    try testing.expect(read_result[1].len == 1);

    closeFds(read_result[1]);
}

test "Basic acknowledgment message protocol" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    const request_msg = "REQUEST: process this data";
    const ack_msg = "ACK";

    const pipe = try TestPipe.init();
    defer pipe.deinit();

    // Step 1: Send request from A to B with fd
    const request_fds = &[_]c_int{pipe.read_fd};
    try writeMessage(sockets.socket_a, request_msg, request_fds);

    // Step 2: Receive request at B
    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;
    var read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, request_msg, read_result[0]);
    try testing.expect(read_result[1].len == 1);

    // Step 3: Send ACK back from B to A (no fds needed for ACK)
    const no_fds: []const c_int = &.{};
    try writeMessage(sockets.socket_b, ack_msg, no_fds);

    // Step 4: Receive ACK at A
    read_result = try readMessage(sockets.socket_a, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, ack_msg, read_result[0]);
    try testing.expect(read_result[1].len == 0);

    // Step 5: Send another request from A to B (different message)
    const request_msg2 = "REQUEST: second operation";
    try writeMessage(sockets.socket_a, request_msg2, request_fds);

    // Step 6: Receive second request at B
    read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, request_msg2, read_result[0]);
    try testing.expect(read_result[1].len == 1);

    // Step 7: Send ACK with received fd back from B to A
    try writeMessage(sockets.socket_b, ack_msg, read_result[1]);

    // Step 8: Receive ACK with fd at A
    read_result = try readMessage(sockets.socket_a, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, ack_msg, read_result[0]);
    try testing.expect(read_result[1].len == 1);

    closeFds(read_result[1]);
}

test "Multi-message client-server protocol simulation" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    // Simulate a realistic protocol where:
    // 1. Client sends multiple requests with different fd counts
    // 2. Server acknowledges each with appropriate response
    // 3. Test both successful ACKs and error conditions

    const commands = [_]struct {
        msg: []const u8,
        fd_count: usize,
        expect_ack: []const u8,
    }{
        .{ .msg = "CMD: list files", .fd_count = 0, .expect_ack = "ACK: 5 files found" },
        .{ .msg = "CMD: open file", .fd_count = 1, .expect_ack = "ACK: file opened" },
        .{ .msg = "CMD: create pipes", .fd_count = 2, .expect_ack = "ACK: pipes created" },
        .{ .msg = "CMD: invalid", .fd_count = 0, .expect_ack = "NACK: unknown command" },
    };

    // Create test fds for commands that need them
    var pipes: [3][2]c_int = undefined;
    for (0..3) |i| {
        if (c.pipe(&pipes[i]) != 0) {
            return error.PipeError;
        }
    }
    defer {
        for (0..3) |i| {
            _ = c.close(pipes[i][0]);
            _ = c.close(pipes[i][1]);
        }
    }

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;

    // Process each command
    for (commands) |cmd| {
        // Client sends command
        var send_fds: []const c_int = undefined;
        switch (cmd.fd_count) {
            0 => send_fds = &.{},
            1 => send_fds = &[_]c_int{pipes[0][0]},
            2 => send_fds = &[_]c_int{ pipes[1][0], pipes[2][0] },
            else => unreachable,
        }

        try writeMessage(sockets.socket_a, cmd.msg, send_fds);

        // Server receives command
        const read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);
        try testing.expectEqualSlices(u8, cmd.msg, read_result[0]);
        try testing.expect(read_result[1].len == cmd.fd_count);

        // Server sends ACK/NACK response
        const response_fds: []const c_int = if (cmd.fd_count > 0) read_result[1] else &.{};
        try writeMessage(sockets.socket_b, cmd.expect_ack, response_fds);

        // Client receives ACK/NACK
        const ack_result = try readMessage(sockets.socket_a, &msg_buffer, &fds_buffer);
        try testing.expectEqualSlices(u8, cmd.expect_ack, ack_result[0]);
        try testing.expect(ack_result[1].len == cmd.fd_count);

        // Close any received fds
        closeFds(ack_result[1]);
    }
}

test "Protocol error handling and socket state recovery" {
    const testing = std.testing;
    const sockets = try TestSocketPair.init();
    defer sockets.deinit();

    // Test various error conditions and socket state after failures
    const error_msg = "CMD: cause error";
    const recovery_msg = "CMD: recover";
    const ack_recovery = "ACK: recovered";

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [c.MAX_FDS]c_int = undefined;

    // Send a command that might cause issues
    const no_fds: []const c_int = &.{};
    try writeMessage(sockets.socket_a, error_msg, no_fds);

    // Receive command
    var read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, error_msg, read_result[0]);
    try testing.expect(read_result[1].len == 0);

    // Server decides not to send ACK (simulating error condition)
    // Instead, send recovery command in opposite direction
    try writeMessage(sockets.socket_b, recovery_msg, no_fds);

    // Client receives recovery command
    read_result = try readMessage(sockets.socket_a, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, recovery_msg, read_result[0]);
    try testing.expect(read_result[1].len == 0);

    // Client sends ACK for recovery
    try writeMessage(sockets.socket_a, ack_recovery, no_fds);

    // Server receives recovery ACK
    read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, ack_recovery, read_result[0]);
    try testing.expect(read_result[1].len == 0);

    // Verify socket is still functional with normal ping-pong
    const final_ping = "final ping";
    const final_pong = "final pong";

    try writeMessage(sockets.socket_a, final_ping, no_fds);
    read_result = try readMessage(sockets.socket_b, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, final_ping, read_result[0]);

    try writeMessage(sockets.socket_b, final_pong, no_fds);
    read_result = try readMessage(sockets.socket_a, &msg_buffer, &fds_buffer);
    try testing.expectEqualSlices(u8, final_pong, read_result[0]);
}
