const std = @import("std");

pub const VirusEntry = struct { index: u32, name: []const u8 };

pub const EngineInfoResponse = struct { version: []const u8, num_signatures: u32 };
pub const ScanFilesRequest = struct { files: []const []const u8 };
pub const ScanFilesResponse = struct { detections: []const VirusEntry };

pub const RequestTag = enum { engine_info, scan_files, exit };
pub const Request = union(RequestTag) { engine_info: void, scan_files: ScanFilesRequest, exit: void };

pub const Response = union(RequestTag) {
    engine_info: EngineInfoResponse,
    scan_files: ScanFilesResponse,
    exit: void,
};

pub fn serialize(allocator: std.mem.Allocator, value: anytype) ![:0]u8 {
    var writer = std.Io.Writer.Allocating.init(allocator);
    defer writer.deinit();

    try std.zon.stringify.serialize(value, std.zon.stringify.SerializeOptions{ .whitespace = false }, &writer.writer);
    return try allocator.dupeZ(u8, writer.writer.buffered());
}

pub fn deserialize(T: type, allocator: std.mem.Allocator, data: [:0]const u8) !T {
    return std.zon.parse.fromSlice(T, allocator, data, null, std.zon.parse.Options{ .free_on_error = false });
}
