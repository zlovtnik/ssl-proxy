const std = @import("std");
const logz = @import("logz");

pub const service_name = "zig-coordinator";

pub fn init(io: std.Io, allocator: std.mem.Allocator) !void {
    try logz.setup(io, allocator, .{
        .level = .Debug,
        .pool_size = 128,
        .buffer_size = 4096,
        .large_buffer_count = 8,
        .large_buffer_size = 16384,
        .output = .stdout,
        .encoding = .json,
    });
}

pub fn deinit() void {
    logz.deinit();
}

pub inline fn debug() @TypeOf(logz.debug().stringSafe("service", service_name)) {
    return logz.debug().stringSafe("service", service_name);
}

pub inline fn info() @TypeOf(logz.info().stringSafe("service", service_name)) {
    return logz.info().stringSafe("service", service_name);
}

pub inline fn err() @TypeOf(logz.err().stringSafe("service", service_name)) {
    return logz.err().stringSafe("service", service_name);
}
