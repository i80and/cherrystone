const std = @import("std");
const landlock = @import("landlock.zig");
const ipc = @import("ipc.zig");

pub fn run(socket_fd: c_int) !void {
    try landlock.setup(&.{"/"});

    // Use inherited socket for communication
    const file = std.fs.File{ .handle = socket_fd };
    defer file.close();

    // Send a message to child
    _ = try file.write("Hello from parent");

    // Read response
    var buffer: [1024]u8 = undefined;
    const bytes_read = try file.read(&buffer);
    if (bytes_read > 0) {
        std.log.info("Parent received: {s}", .{buffer[0..bytes_read]});
    }
}
