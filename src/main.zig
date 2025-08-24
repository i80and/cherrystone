const std = @import("std");
const c = @cImport({
    @cInclude("sys/syscall.h");
    @cInclude("unistd.h");
});
const clamav = @import("clamav.zig");
const ipc = @import("ipc.zig");
const landlock = @import("landlock.zig");

const PidFdOpenError = error{
    InvalidArgument,
    SystemResources,
    UnsupportedKernel,
} || std.posix.UnexpectedError;

fn pidfd_open(pid: std.posix.pid_t, flags: c_uint) PidFdOpenError!c_int {
    const rc = c.syscall(c.__NR_pidfd_open, pid, flags);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .INVAL => return error.InvalidArgument,
        .MFILE => return error.SystemResources,
        .NFILE => return error.SystemResources,
        .NOMEM => return error.UnsupportedKernel,
        .SRCH => return error.SystemResources,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

const PidFdGetFdError = error{
    InvalidArgument,
    SystemResources,
    ProcessLacksPermissions,
    ProcessDoesNotExist,
} || std.posix.UnexpectedError;

fn pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: c_uint) PidFdGetFdError!c_int {
    const rc = c.syscall(c.__NR_pidfd_open, pidfd, targetfd, flags);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .BADF => return error.InvalidArgument,
        .INVAL => return error.InvalidArgument,
        .MFILE => return error.SystemResources,
        .NFILE => return error.SystemResources,
        .PERM => return error.ProcessLacksPermissions,
        .SRCH => return error.SystemResources,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

fn childProcess(socket_fd: c_int, parent_pid: i32) !void {
    // Initialize ClamAV library
    try clamav.ClamAV.init();

    // Zig demands being able to work in $TMPDIR. Sigh.
    const tmpdir = std.posix.getenv("TMPDIR") orelse "/tmp/";

    // Get database directory and setup landlock
    const db_dir = clamav.ClamAV.getDefaultDatabasePath();
    try landlock.setup(&.{db_dir, tmpdir});

    // Create ClamAV scanner instance using the new object-oriented interface
    var scanner = try clamav.ClamAV.create(db_dir);
    defer scanner.deinit();

    const file = std.fs.File{ .handle = socket_fd };
    defer file.close();

    const parent_pidfd = try pidfd_open(parent_pid, 0);
    defer std.posix.close(parent_pidfd);

    const p = try pidfd_getfd(parent_pidfd, 0, 0);
    std.log.info("PID: {}", .{p});

    // Simple echo for demonstration
    var buffer: [1024]u8 = undefined;
    const bytes_read = try file.read(&buffer);
    if (bytes_read > 0) {
        std.log.info("Child received: {s}", .{buffer[0..bytes_read]});
        _ = try file.write("ACK from child");
    }

    std.log.info("Scanning file using new ClamAV object...", .{});
    const scan_result = scanner.scanFile("build.zig") catch |err| {
        std.log.err("Failed to scan file: {}", .{err});
        return;
    };

    if (scan_result) |virus_name| {
        std.log.warn("VIRUS DETECTED: {s}", .{virus_name});
    } else {
        std.log.info("File is clean!", .{});
    }
}

fn parentProcess(socket_fd: c_int) !void {
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
