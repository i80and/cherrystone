const std = @import("std");
const c = @cImport({
    @cInclude("sys/syscall.h");
    @cInclude("unistd.h");
});

pub const PidFdOpenError = error{
    InvalidArgument,
    SystemResources,
    UnsupportedKernel,
} || std.posix.UnexpectedError;

pub fn pidfd_open(pid: std.posix.pid_t, flags: c_uint) PidFdOpenError!c_int {
    const rc = c.syscall(c.__NR_pidfd_open, pid, flags);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .INVAL => return error.InvalidArgument,
        .MFILE => return error.SystemResources,
        .NFILE => return error.SystemResources,
        .NOMEM => return error.UnsupportedKernel,
        .SRCH => return error.SystemResources,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

pub const PidFdGetFdError = error{
    InvalidArgument,
    SystemResources,
    ProcessLacksPermissions,
    ProcessDoesNotExist,
} || std.posix.UnexpectedError;

pub fn pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: c_uint) PidFdGetFdError!c_int {
    const rc = c.syscall(c.__NR_pidfd_open, pidfd, targetfd, flags);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .BADF => return error.InvalidArgument,
        .INVAL => return error.InvalidArgument,
        .MFILE => return error.SystemResources,
        .NFILE => return error.SystemResources,
        .PERM => return error.ProcessLacksPermissions,
        .SRCH => return error.SystemResources,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}
