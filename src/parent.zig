const std = @import("std");
const landlock = @import("landlock.zig");
const ipc = @import("ipc.zig");

pub fn run(socket: *ipc.IPC) !void {
    defer socket.deinit();

    try landlock.setup(&.{"/"});

    var msg_buffer: [1024]u8 = undefined;
    var fds_buffer: [ipc.MAX_FDS]c_int = undefined;
    _ = try socket.readMessage(&msg_buffer, &fds_buffer);
}
