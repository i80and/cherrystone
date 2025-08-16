const std = @import("std");

const c = @cImport({
    @cInclude("linux/landlock.h");
    @cInclude("sys/syscall.h");
    @cInclude("unistd.h");
    @cInclude("fcntl.h");
});

pub const LandlockError = error{
    LandlockRulesetFailed,
    LandlockRuleFailed,
    LandlockRestrictFailed,
    DatabaseDirOpenFailed,
    UnsupportedABI,
};

pub const LandlockConfig = struct {
    /// Allowed filesystem paths
    allowed_paths: []const []const u8 = &.{},
};

fn landlock_create_ruleset(attr: ?*const c.landlock_ruleset_attr, size: usize, flags: u32) c_int {
    return @intCast(c.syscall(c.__NR_landlock_create_ruleset, attr, size, flags));
}

pub fn getABIVersion() c_int {
    return landlock_create_ruleset(null, 0, c.LANDLOCK_CREATE_RULESET_VERSION);
}

fn addFilesystemRule(ruleset_fd: c_int, path: []const u8, access: u64) !void {
    // Convert Zig string to null-terminated string
    var path_buffer: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= path_buffer.len) {
        return error.PathTooLong;
    }
    @memcpy(path_buffer[0..path.len], path);
    path_buffer[path.len] = 0;

    const path_beneath = c.landlock_path_beneath_attr{
        .allowed_access = access,
        .parent_fd = c.open(&path_buffer, c.O_RDONLY | c.O_CLOEXEC),
    };

    if (path_beneath.parent_fd < 0) {
        std.log.err("Failed to open path: {s}", .{path});
        return LandlockError.DatabaseDirOpenFailed;
    }
    defer _ = c.close(path_beneath.parent_fd);

    if (c.syscall(c.__NR_landlock_add_rule, @as(c_int, ruleset_fd), @as(c_uint, c.LANDLOCK_RULE_PATH_BENEATH), &path_beneath, @as(c_ulong, 0)) != 0) {
        std.log.err("Failed to add Landlock filesystem rule for: {s}", .{path});
        return LandlockError.LandlockRuleFailed;
    }

    std.log.debug("Added filesystem rule for: {s}", .{path});
}

fn restrictSelf(ruleset_fd: c_int) !void {
    const result = c.syscall(c.__NR_landlock_restrict_self, @as(c_int, ruleset_fd), @as(c_ulong, 0));
    if (result != 0) {
        std.log.err("Failed to restrict process with Landlock", .{});
        return LandlockError.LandlockRestrictFailed;
    }
}

pub fn setup(allowed_paths: []const []const u8) !void {
    // Enable no_new_privs (required for Landlock)
    _ = try std.posix.prctl(std.os.linux.PR.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });

    const abi = getABIVersion();

    if (abi < 4) {
        std.log.err("Landlock ABI version 4+ required; got {}", .{abi});
        return error.UnsupportedABI;
    }

    // Create ruleset attributes
    var ruleset_attr = c.landlock_ruleset_attr{
        .handled_access_fs = c.LANDLOCK_ACCESS_FS_READ_FILE | c.LANDLOCK_ACCESS_FS_READ_DIR,
        .handled_access_net = c.LANDLOCK_ACCESS_NET_BIND_TCP | c.LANDLOCK_ACCESS_NET_CONNECT_TCP,
    };

    const ruleset_fd = landlock_create_ruleset(&ruleset_attr, @sizeOf(@TypeOf(ruleset_attr)), 0);
    if (ruleset_fd < 0) {
        std.log.err("Failed to create Landlock ruleset", .{});
        return LandlockError.LandlockRulesetFailed;
    }
    defer _ = c.close(ruleset_fd);

    // Add filesystem rules
    for (allowed_paths) |path| {
        try addFilesystemRule(ruleset_fd, path, c.LANDLOCK_ACCESS_FS_READ_FILE | c.LANDLOCK_ACCESS_FS_READ_DIR);
    }

    // Apply restrictions
    try restrictSelf(ruleset_fd);
    std.log.info("Landlock restrictions applied successfully", .{});
}
