const std = @import("std");
const clamav = @import("clamav.zig");
const landlock = @import("landlock.zig");
const ipc = @import("ipc.zig");

pub fn run(socket: *ipc.IPC) !void {
    defer socket.deinit();

    // Initialize ClamAV library
    try clamav.ClamAV.init();

    // Zig demands being able to work in $TMPDIR. Sigh.
    const tmpdir = std.posix.getenv("TMPDIR") orelse "/tmp/";

    // Get database directory and setup landlock
    const db_dir = clamav.ClamAV.getDefaultDatabasePath();
    try landlock.setup(&.{ db_dir, tmpdir });

    // Create ClamAV scanner instance using the new object-oriented interface
    var scanner = try clamav.ClamAV.create(db_dir);
    defer scanner.deinit();

    const msg_buf = try std.heap.page_allocator.alloc(u8, 1024);
    defer std.heap.page_allocator.free(msg_buf);

    const fds_buf = try std.heap.page_allocator.alloc(std.posix.fd_t, 20);
    defer std.heap.page_allocator.free(msg_buf);

    _ = try socket.readMessage(msg_buf, fds_buf);
}
