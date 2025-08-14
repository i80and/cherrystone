const std = @import("std");
const libclamav = @cImport(@cInclude("clamav.h"));

pub fn init() !void {
    if (libclamav.cl_init(libclamav.CL_INIT_DEFAULT) != libclamav.CL_SUCCESS) {
        std.log.err("Failed to initialize ClamAV", .{});
        return error.InitializationFailed;
    }
}

pub fn getDefaultDatabasePath() ![]const u8 {
    const db_dir = libclamav.cl_retdbdir();
    if (db_dir == null) {
        std.log.err("Failed to get ClamAV database directory", .{});
        return error.DatabaseDirFailed;
    }

    // Convert C string to Zig slice
    const db_path = std.mem.span(db_dir);

    return db_path;
}

pub fn setupClamAV(db_path: []const u8) !*libclamav.struct_cl_engine {
    // Get ClamAV database directory before applying restrictions
    const db_dir = libclamav.cl_retdbdir();
    if (db_dir == null) {
        std.log.err("Failed to get ClamAV database directory", .{});
        return error.DatabaseDirFailed;
    }

    // Continue with ClamAV setup (this should still work as we allowed filesystem access)
    const engine = libclamav.cl_engine_new() orelse {
        std.log.err("Failed to create ClamAV engine", .{});
        return error.EngineCreateFailed;
    };

    if (libclamav.cl_load(db_path.ptr, engine, null, libclamav.CL_DB_STDOPT | libclamav.CL_DB_PUA | libclamav.CL_DB_OFFICIAL_ONLY) != libclamav.CL_SUCCESS) {
        std.log.err("Failed to load ClamAV database", .{});
        return error.DatabaseLoadFailed;
    }

    if (libclamav.cl_engine_compile(engine) != libclamav.CL_SUCCESS) {
        std.log.err("Failed to compile ClamAV engine", .{});
        return error.EngineCompileFailed;
    }

    return engine;
}

pub fn freeClamAV(engine: *libclamav.struct_cl_engine) void {
    _ = libclamav.cl_engine_free(engine);
}
