const std = @import("std");
const landlock = @import("landlock.zig");
const ipc = @import("ipc.zig");
const protocol = @import("protocol.zig");
const ipc_server = @import("ipc_server.zig");

pub fn run(socket: *ipc.IPC) !void {
    var allocator = std.heap.c_allocator;

    var server = ipc_server.Server.init(allocator, socket);
    defer server.deinit();

    // try landlock.setup(&.{"/"});

    {
        var arena = std.heap.ArenaAllocator.init(allocator);
        const arena_allocator = arena.allocator();
        defer arena.deinit();

        const result = try server.sendAndReceive(protocol.Request, protocol.Response, arena_allocator, &protocol.Request{ .engine_info = {} }, &.{});
        std.debug.print("Engine Version: {s}\n", .{result.engine_info.version});
        std.debug.print("# Signatures: {d}\n", .{result.engine_info.num_signatures});
    }

    const msg_buf = try allocator.alloc(u8, 4096);
    defer allocator.free(msg_buf);

    const fds_buf = try allocator.alloc(std.posix.fd_t, 20);
    defer allocator.free(fds_buf);

    _ = try server.sendAndReceive(protocol.Request, void, allocator, &protocol.Request{ .exit = {} }, &.{});
}
