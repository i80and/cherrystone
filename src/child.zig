const std = @import("std");
const clamav = @import("clamav.zig");
const landlock = @import("landlock.zig");
const ipc = @import("ipc.zig");
const ipc_server = @import("ipc_server.zig");
const protocol = @import("protocol.zig");

const Handler = struct {
    scanner: *clamav.ClamAV,

    const Self = @This();

    pub fn init(scanner: *clamav.ClamAV) Self {
        return Self{
            .scanner = scanner,
        };
    }

    pub fn handle(self: *Self, comptime T: type, allocator: std.mem.Allocator, data: *const T, fds: []std.posix.fd_t) anyerror!?*protocol.Response {
        _ = fds;

        switch (data.*) {
            .engine_info => {
                // Create response with ClamAV engine info using the scanner instance
                const response = try allocator.create(protocol.Response);
                response.* = protocol.Response{
                    .engine_info = protocol.EngineInfoResponse{
                        .version = clamav.ClamAV.getEngineVersionString(),
                        .num_signatures = self.scanner.num_signatures,
                    },
                };
                return response;
            },

            .scan_files => |scan_request| {
                // Handle file scanning using the ClamAV scanner
                std.log.info("Scanning files with ClamAV engine", .{});

                // Example of how to use the scanner for file scanning
                // In a real implementation, you would iterate through scan_request.files
                // and scan each one using self.scanner.scanFile() or self.scanner.scanFd()

                // For now, just demonstrate access to the scanner
                _ = scan_request;

                const response = try allocator.create(protocol.Response);
                response.* = protocol.Response{
                    .scan_files = protocol.ScanFilesResponse{},
                };
                return response;
            },

            .exit => {
                std.process.exit(0);
            },
        }

        return null;
    }
};

pub fn run(socket: *ipc.IPC) !void {
    var server = ipc_server.Server.init(std.heap.page_allocator, socket);
    defer server.deinit();

    // Initialize ClamAV library
    try clamav.ClamAV.init();

    // Zig demands being able to work in $TMPDIR. Sigh.
    // const tmpdir = std.posix.getenv("TMPDIR") orelse "/tmp/";

    // Get database directory and setup landlock
    const db_dir = clamav.ClamAV.getDefaultDatabasePath();
    // try landlock.setup(&.{ db_dir, tmpdir });

    // Create ClamAV scanner instance using the new object-oriented interface
    var scanner = try clamav.ClamAV.create(db_dir);
    defer scanner.deinit();

    // Create handler with scanner access
    var handler = Handler.init(&scanner);

    try server.loop(protocol.Request, protocol.Response, &handler, Handler.handle);
}
