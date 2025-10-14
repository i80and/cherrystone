const std = @import("std");
const landlock = @import("landlock.zig");
const ipc = @import("ipc.zig");
const protocol = @import("protocol.zig");
const ipc_server = @import("ipc_server.zig");

const ScanResultEntry = struct { path: []const u8, virus_name: []const u8 };

/// Iterate over a slice in slices of size N or less
fn iterate_chunks(comptime N: usize, data: anytype) ChunkIterator(@TypeOf(data[0]), N) {
    return ChunkIterator(@TypeOf(data[0]), N){
        .data = data[0..],
        .pos = 0,
    };
}

fn ChunkIterator(comptime T: type, comptime N: usize) type {
    return struct {
        data: []const T,
        pos: usize,

        pub fn next(self: *ChunkIterator(T, N)) ?[]const T {
            const len = self.data.len;
            if (self.pos >= len) return null;

            const remaining = len - self.pos;
            const chunk_len = if (remaining < N) remaining else N;
            const chunk = self.data[self.pos .. self.pos + chunk_len];
            self.pos += chunk_len;
            return chunk;
        }
    };
}

test "iterate_chunks" {
    const slice = [_]i32{ 1, 2, 3 };
    var chunks = iterate_chunks(2, &slice);
    try std.testing.expectEqualSlices(i32, &[_]i32{ 1, 2 }, chunks.next().?);
    try std.testing.expectEqualSlices(i32, &[_]i32{3}, chunks.next().?);
    try std.testing.expect(chunks.next() == null);
}

pub fn scan_files(allocator: std.mem.Allocator, server: *ipc_server.Server, paths: []const []const u8) ![]ScanResultEntry {
    // Open file descriptors and create FileEntry array
    var file_entries = try allocator.alloc([]const u8, paths.len);
    defer allocator.free(file_entries);

    var opened_fds = try allocator.alloc(std.posix.fd_t, paths.len);
    defer allocator.free(opened_fds);

    var scan_results: std.ArrayList(ScanResultEntry) = .empty;
    errdefer scan_results.deinit(allocator);

    // We can send at most ipc.MAX_FDS file descriptors at a time due to ancillary data
    // limitations, so chunk our request appropriately.
    var chunk_iterator = iterate_chunks(ipc.MAX_FDS, paths);
    while (chunk_iterator.next()) |chunk| {
        for (chunk, 0..) |path, i| {
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

            const response = try server.sendAndReceive(protocol.Request, protocol.Response, arena_allocator, &scan_request, opened_fds);

            for (response.scan_files.detections) |detection| {
                try scan_results.append(allocator, ScanResultEntry{ .path = paths[detection.index], .virus_name = detection.name });
            }

            // Close file descriptors
            for (opened_fds) |fd| {
                std.posix.close(fd);
            }
        }
    }

    return scan_results.items;
}

pub fn run(socket: *ipc.IPC) !void {
    const allocator = std.heap.c_allocator;

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

    const result = try scan_files(allocator, &server, &file_paths);
    defer allocator.free(result);

    std.debug.print("Scan completed. Detections found: {d}\n", .{result.len});
    for (result) |detection| {
        std.debug.print("Detection - Path: {s}, Name: {s}\n", .{ detection.path, detection.virus_name });
    }

    _ = try server.sendAndReceive(protocol.Request, void, allocator, &protocol.Request{ .exit = {} }, &.{});
}
