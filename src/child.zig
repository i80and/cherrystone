const std = @import("std");
const syscalls = @import("syscalls.zig");
const ipc = @import("ipc.zig");
const clamav = @import("clamav.zig");
const landlock = @import("landlock.zig");
const socket_utils = @import("socket_utils.zig");

pub fn run(socket_fd: c_int, parent_pidfd: c_int) !void {
    // libclamav wants to create temporary files, which... ugh, fine. We have to let it.
    const tmpdir = std.posix.getenv("TMPDIR") orelse "/tmp/";

    // Initialize ClamAV library
    try clamav.ClamAV.init();

    // Get database directory and setup landlock
    const db_dir = clamav.ClamAV.getDefaultDatabasePath();
    try landlock.setup(&.{ db_dir, tmpdir });

    // Create ClamAV scanner instance using the new object-oriented interface
    var scanner = try clamav.ClamAV.create(db_dir);
    defer scanner.deinit();

    const ipc_file = std.fs.File{ .handle = socket_fd };
    defer ipc_file.close();
    var reader = ipc_file.reader();

    while (true) {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var data_buffer = std.ArrayList(u8).init(allocator);
        try reader.streamUntilDelimiter(data_buffer.writer(), 0, ipc.MAX_MESSAGE_SIZE_BYTES);
        const data = try data_buffer.toOwnedSliceSentinel(0);

        // Parse the request. We're using an arena, so don't have zon free on error.
        const parsed_data = try std.zon.parse.fromSlice(ipc.Request, allocator, data, null, .{ .free_on_error = false });
        switch (parsed_data) {
            .scan => |scan_request| {
                for (scan_request.files) |entry| {
                    std.log.info("Scanning file using new ClamAV object... path: {s}, pid: {}", .{ entry.path, entry.fd });
                    const fd = try syscalls.pidfd_getfd(parent_pidfd, entry.fd, 0);
                    defer std.posix.close(fd);
                    const scan_result = try scanner.scanFd(fd, entry.path);
                    if (scan_result) |virus_name| {
                        std.log.warn("VIRUS DETECTED: {s}", .{virus_name});
                    } else {
                        std.log.info("File is clean!", .{});
                    }
                }
            },
            .info => {
                std.log.info("Child process exiting...", .{});
                return;
            },
            .exit => {
                std.c.exit(0);
            },
        }
    }

    std.log.info("Scanning file using new ClamAV object...", .{});
    const scan_result = try scanner.scanFile("clamav-testfile");

    if (scan_result) |virus_name| {
        std.log.warn("VIRUS DETECTED: {s}", .{virus_name});
    } else {
        std.log.info("File is clean!", .{});
    }
}
