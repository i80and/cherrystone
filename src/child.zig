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

                // Appa! Zip zip!
                std.debug.assert(scan_request.files.len == fds.len);

                var viruses: std.ArrayList(protocol.VirusEntry) = .empty;
                // Only free on error since we want to return this slice
                errdefer viruses.deinit(allocator);

                for (scan_request.files, 0..) |file, i| {
                    std.log.info("Scanning: {s}", .{file});
                    const maybe_virus_name = try self.scanner.scanFd(fds[i], file);
                    if (maybe_virus_name) |virus_name| {
                        try viruses.append(allocator, protocol.VirusEntry{
                            .index = @intCast(i),
                            .name = virus_name,
                        });
                    }
                }

                const response = try allocator.create(protocol.Response);
                response.* = protocol.Response{
                    .scan_files = protocol.ScanFilesResponse{
                        .detections = viruses.items,
                    },
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
    const tmpdir = std.posix.getenv("TMPDIR") orelse "/tmp/";

    // Get database directory and setup landlock
    const db_dir = clamav.ClamAV.getDefaultDatabasePath();
    try landlock.setup(&.{ db_dir, tmpdir });

    // Create ClamAV scanner instance using the new object-oriented interface
    var scanner = try clamav.ClamAV.create(db_dir);
    defer scanner.deinit();

    // Create handler with scanner access
    var handler = Handler.init(&scanner);

    try server.loop(protocol.Request, protocol.Response, &handler, Handler.handle);
}
