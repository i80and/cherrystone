const std = @import("std");
const syscalls = @import("syscalls.zig");
const clamav = @import("clamav.zig");
const ipc = @import("ipc.zig");
const landlock = @import("landlock.zig");

fn childProcess(socket_fd: c_int, parent_pid: i32) !void {
    // Initialize ClamAV library
    try clamav.ClamAV.init();

    // Get database directory and setup landlock
    const db_dir = clamav.ClamAV.getDefaultDatabasePath();
    try landlock.setupWithPath(db_dir);

    // Create ClamAV scanner instance using the new object-oriented interface
    var scanner = try clamav.ClamAV.create(db_dir);
    defer scanner.deinit();

    const file = std.fs.File{ .handle = socket_fd };
    defer file.close();

    const parent_pidfd = try syscalls.pidfd_open(parent_pid, 0);
    defer std.posix.close(parent_pidfd);

    const p = try syscalls.pidfd_getfd(parent_pidfd, 0, 0);
    std.log.info("PID: {}", .{p});

    // Simple echo for demonstration
    var buffer: [1024]u8 = undefined;
    const bytes_read = try file.read(&buffer);
    if (bytes_read > 0) {
        std.log.info("Child received: {s}", .{buffer[0..bytes_read]});
        _ = try file.write("ACK from child");
    }

    std.log.info("Scanning file using new ClamAV object...", .{});
    const scan_result = try scanner.scanFile("clamav-testfile");

    if (scan_result) |virus_name| {
        std.log.warn("VIRUS DETECTED: {s}", .{virus_name});
    } else {
        std.log.info("File is clean!", .{});
    }
}

fn parentProcess(socket_fd: c_int) !void {
    try landlock.setupWithPath("/");

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

pub fn main() !void {
    var sockets: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &sockets) != 0) {
        std.log.err("Failed to create socketpair", .{});
        return error.SocketPairFailed;
    }

    const parent_pid = std.c.getpid();
    const pid = try std.posix.fork();

    if (pid == 0) {
        // Child process
        std.posix.close(sockets[0]); // Close parent's end
        try childProcess(sockets[1], parent_pid);
    } else {
        // Parent process
        std.posix.close(sockets[1]); // Close child's end
        defer {
            // Wait for child to exit
            _ = std.posix.waitpid(pid, 0);
        }
        try parentProcess(sockets[0]);
    }
}
