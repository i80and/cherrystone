const RequestTagType = enum { scan, info, exit };
pub const FileDescription = struct { path: []const u8, fd: c_int };
pub const ScanFilesRequest = struct {
    files: []const FileDescription,
};
pub const Request = union(RequestTagType) { scan: ScanFilesRequest, info, exit };

const ResponseTagType = enum { scan, info };
pub const VirusInfo = struct {
    path: []const u8,
    virus_name: []const u8,
};
pub const ScanFilesResponse = struct {
    viruses: []VirusInfo,
};
pub const InfoResponse = struct {
    clamav_version: []const u8,
};
pub const Response = union(ResponseTagType) { scan: ScanFilesResponse, info: InfoResponse };

pub const MAX_MESSAGE_SIZE_BYTES: usize = 1024 * 1024;
