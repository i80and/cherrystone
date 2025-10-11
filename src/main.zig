const std = @import("std");

const child = @import("child.zig");
const parent = @import("parent.zig");
const ipc = @import("ipc.zig");

pub fn main() !void {
    var sockets = try ipc.IPC.createSocketPair();
    const pid = try std.posix.fork();

    if (pid == 0) {
        // Child process
        sockets[0].deinit(); // Close parent's end
        try child.run(&sockets[1]);
    } else {
        // Parent process
        sockets[1].deinit(); // Close child's end
        defer {
            // Wait for child to exit
            _ = std.posix.waitpid(pid, 0);
        }
        try parent.run(&sockets[0]);
    }
}

test {
    std.testing.refAllDecls(@This());
}
