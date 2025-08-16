const std = @import("std");
const child = @import("child.zig");
const parent = @import("parent.zig");
const syscalls = @import("syscalls.zig");

pub fn main() !void {
    var sockets: [2]c_int = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &sockets) != 0) {
        std.log.err("Failed to create socketpair", .{});
        return error.SocketPairFailed;
    }

    const parent_pid = std.c.getpid();
    const parent_pidfd = try syscalls.pidfd_open(parent_pid, 0);
    defer std.posix.close(parent_pidfd);

    const pid = try std.posix.fork();

    if (pid == 0) {
        // Child process
        std.posix.close(sockets[0]); // Close parent's end
        try child.run(sockets[1], parent_pidfd);
    } else {
        // Parent process
        std.posix.close(sockets[1]); // Close child's end
        defer {
            // Wait for child to exit
            _ = std.posix.waitpid(pid, 0);
        }
        try parent.run(sockets[0]);
    }
}
