const std = @import("std");
const ipc = @import("ipc.zig");
const landlock = @import("landlock.zig");

pub fn run(socket_fd: c_int) !void {
    try landlock.setup(&.{"/"});

    // Use inherited socket for communication
    const ipc_file = std.fs.File{ .handle = socket_fd };
    defer ipc_file.close();

    {
        const f = try std.fs.cwd().openFile("clamav-testfile", .{});
        // defer f.close();
        const files = [_]ipc.FileDescription{.{ .path = "clamav-testfile", .fd = f.handle }};
        const request = ipc.Request{ .scan = ipc.ScanFilesRequest{ .files = &files } };
        var writer = ipc_file.writer();
        try std.zon.stringify.serialize(request, .{ .whitespace = false }, writer);
        try writer.writeByte(0);
    }

    {
        const request = ipc.Request.exit;
        var writer = ipc_file.writer();
        try std.zon.stringify.serialize(request, .{ .whitespace = false }, writer);
        try writer.writeByte(0);
    }
}
