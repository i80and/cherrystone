const std = @import("std");
const ipc = @import("ipc.zig");
const protocol = @import("protocol.zig");

const MESSAGE_BUFFER_SIZE = 8192;

pub const Server = struct {
    allocator: std.mem.Allocator,
    connection: *ipc.IPC,

    pub fn init(allocator: std.mem.Allocator, connection: *ipc.IPC) Server {
        return Server{ .allocator = allocator, .connection = connection };
    }

    pub fn deinit(self: *Server) void {
        self.connection.deinit();
    }

    /// Sends a message and synchronously receive a response if R is not void. The parent is responsible for freeing the response's memory.
    pub fn sendAndReceive(self: *Server, comptime T: type, comptime R: type, parent_allocator: std.mem.Allocator, msg: *const T, fds: []std.posix.fd_t) anyerror!R {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        const serialized = try protocol.serialize(arena_allocator, msg);
        try self.connection.writeMessage(serialized, fds);

        if (R != void) {
            const result_msg_buf = try arena_allocator.alloc(u8, MESSAGE_BUFFER_SIZE);

            const result = try self.connection.readMessage(result_msg_buf, &.{});
            return try protocol.deserialize(R, parent_allocator, result[0]);
        }

        return;
    }

    pub fn loop(self: *Server, comptime T: type, comptime R: type, context: anytype, comptime handle: fn (@TypeOf(context), comptime T: type, allocator: std.mem.Allocator, msg: *const T, fds: []std.posix.fd_t) anyerror!?*R) anyerror!void {
        while (true) {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();

            // No need to free: arena allocation
            const msg_buf = try allocator.alloc(u8, MESSAGE_BUFFER_SIZE);
            const fds_buf = try allocator.alloc(std.posix.fd_t, ipc.MAX_FDS);

            const result = try self.connection.readMessage(msg_buf, fds_buf);
            const obj = try protocol.deserialize(T, allocator, result[0]);

            const returnValue = try handle(context, T, allocator, &obj, result[1]);

            // Close received file descriptors. Cave Johnson, we're done here.
            for (result[1]) |fd| {
                std.posix.close(fd);
            }

            if (returnValue) |value| {
                const serialized = try protocol.serialize(allocator, value);
                std.log.debug("Sending: {s}", .{serialized});
                try self.connection.writeMessage(serialized, &.{});
            }
        }
    }
};
