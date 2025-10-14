const std = @import("std");
const landlock = @import("landlock.zig");
const ipc = @import("ipc.zig");
const protocol = @import("protocol.zig");
const ipc_server = @import("ipc_server.zig");

pub fn run(socket: *ipc.IPC) !void {
    var allocator = std.heap.c_allocator;

    var server = ipc_server.Server.init(allocator, socket);
    defer server.deinit();

    try landlock.setup(&.{"/"});

    {
        var arena = std.heap.ArenaAllocator.init(allocator);
        const arena_allocator = arena.allocator();
        defer arena.deinit();

        const result = try server.sendAndReceive(protocol.Request, protocol.Response, arena_allocator, &protocol.Request{ .engine_info = {} }, &.{});
        std.debug.print("Engine Version: {s}\n", .{result.engine_info.version});
        std.debug.print("# Signatures: {d}\n", .{result.engine_info.num_signatures});
    }

    // Array of file paths to scan
    const file_paths = [_][]const u8{"COPYING.txt"};

    // Open file descriptors and create FileEntry array
    var file_entries = try allocator.alloc([]const u8, file_paths.len);
    defer allocator.free(file_entries);

    var opened_fds = try allocator.alloc(std.posix.fd_t, file_paths.len);
    defer allocator.free(opened_fds);

    for (file_paths, 0..) |path, i| {
        const fd = std.posix.open(path, .{ .ACCMODE = .RDONLY }, 0) catch |err| {
            std.log.err("Failed to open {s}: {}\n", .{ path, err });
            continue;
        };
        opened_fds[i] = fd;
        file_entries[i] = path;
    }

    // Create scan_files request
    const scan_request = protocol.Request{ .scan_files = protocol.ScanFilesRequest{ .files = file_entries } };

    // Send the scan request with file descriptors
    {
        var arena = std.heap.ArenaAllocator.init(allocator);
        const arena_allocator = arena.allocator();
        defer arena.deinit();

        const scan_result = try server.sendAndReceive(protocol.Request, protocol.Response, arena_allocator, &scan_request, opened_fds);

        // Close file descriptors
        for (opened_fds) |fd| {
            std.posix.close(fd);
        }

        std.debug.print("Scan completed. Detections found: {d}\n", .{scan_result.scan_files.detections.len});
        for (scan_result.scan_files.detections) |detection| {
            std.debug.print("Detection - Index: {d}, Name: {s}\n", .{ detection.index, detection.name });
        }
    }

    _ = try server.sendAndReceive(protocol.Request, void, allocator, &protocol.Request{ .exit = {} }, &.{});
}
