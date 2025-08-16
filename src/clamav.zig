const std = @import("std");
const libclamav = @cImport(@cInclude("clamav.h"));

pub const ClamAVError = error{
    InitializationFailed,
    EngineCreateFailed,
    DatabaseLoadFailed,
    EngineCompileFailed,
    ScanFailed,
};

pub const ClamAV = struct {
    engine: *libclamav.struct_cl_engine,

    const Self = @This();

    /// Initialize libclamav (must be called before calling any other functions)
    pub fn init() !void {
        if (libclamav.cl_init(libclamav.CL_INIT_DEFAULT) != libclamav.CL_SUCCESS) {
            std.log.err("Failed to initialize ClamAV", .{});
            return ClamAVError.InitializationFailed;
        }
    }

    /// Get the default ClamAV database path
    pub fn getDefaultDatabasePath() []const u8 {
        return std.mem.span(libclamav.cl_retdbdir());
    }

    /// Create a new ClamAV instance with the specified database path
    pub fn create(db_path: []const u8) !Self {
        // Create ClamAV engine
        const engine = libclamav.cl_engine_new() orelse {
            std.log.err("Failed to create ClamAV engine", .{});
            return ClamAVError.EngineCreateFailed;
        };

        // Load the database
        if (libclamav.cl_load(db_path.ptr, engine, null, libclamav.CL_DB_STDOPT | libclamav.CL_DB_PUA | libclamav.CL_DB_OFFICIAL_ONLY) != libclamav.CL_SUCCESS) {
            std.log.err("Failed to load ClamAV database", .{});
            _ = libclamav.cl_engine_free(engine);
            return ClamAVError.DatabaseLoadFailed;
        }

        // Compile the engine
        if (libclamav.cl_engine_compile(engine) != libclamav.CL_SUCCESS) {
            std.log.err("Failed to compile ClamAV engine", .{});
            _ = libclamav.cl_engine_free(engine);
            return ClamAVError.EngineCompileFailed;
        }

        return Self{
            .engine = engine,
        };
    }

    /// Scan a file descriptor for viruses
    pub fn scanFd(self: Self, descriptor: c_int, filename: []const u8) !?[]const u8 {
        var options = std.mem.zeroInit(libclamav.cl_scan_options, .{
            .general = libclamav.CL_SCAN_GENERAL_ALLMATCHES | libclamav.CL_SCAN_GENERAL_HEURISTICS,
            .parse = ~@as(u32, 0),
            .heuristic = libclamav.CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE,
            .mail = 0,
            .dev = 0,
        });

        var virus_name: [*c]const u8 = null;
        const status = libclamav.cl_scandesc(descriptor, filename.ptr, &virus_name, null, self.engine, &options);

        switch (status) {
            libclamav.CL_VIRUS => {
                return std.mem.span(virus_name);
            },
            libclamav.CL_CLEAN => {
                return null;
            },
            else => {
                std.log.err("Failed to scan file", .{});
                return ClamAVError.ScanFailed;
            },
        }
    }

    /// Clean up and free the ClamAV engine
    pub fn deinit(self: Self) void {
        _ = libclamav.cl_engine_free(self.engine);
    }
};
