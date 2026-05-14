const std = @import("std");
const config = @import("config.zig");
const logging = @import("logging.zig");
const scheduler = @import("scheduler.zig");

var should_shutdown = std.atomic.Value(bool).init(false);
var shutdown_signal = std.atomic.Value(u32).init(0);

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    try logging.init(init.io, allocator);
    defer logging.deinit();

    const cfg = config.load();
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const mode = if (args.next()) |value| value[0..value.len] else "run";

    logging.info()
        .stringSafe("event", "process_start")
        .string("mode", mode)
        .string("stream_name", cfg.stream_name)
        .string("stream_names", cfg.stream_names_csv)
        .string("oracle_stream_names", cfg.oracle_stream_names_csv)
        .string("audit_stream", cfg.audit_stream_name)
        .string("result_stream", cfg.result_stream_name)
        .string("scan_topic", cfg.scan_topic)
        .string("load_topic", cfg.load_topic)
        .string("result_topic", cfg.result_topic)
        .log();

    if (scheduler.invalidOracleStreamName(cfg.stream_names_csv, cfg.oracle_stream_names_csv)) |stream_name| {
        logging.err()
            .stringSafe("event", "config_validation")
            .stringSafe("status", "error")
            .stringSafe("error", "InvalidOracleStreamConfig")
            .string("stream_name", stream_name)
            .string("stream_names", cfg.stream_names_csv)
            .string("oracle_stream_names", cfg.oracle_stream_names_csv)
            .stringSafe("allowed_oracle_stream_names", "proxy.events")
            .log();
        return error.InvalidOracleStreamConfig;
    }

    var service = try scheduler.Service.init(allocator, init.io, cfg);
    defer service.deinit();

    if (std.mem.eql(u8, mode, "healthcheck")) {
        try service.healthcheck();
        logging.info()
            .stringSafe("event", "process_exit")
            .string("mode", mode)
            .stringSafe("status", "ok")
            .log();
        return;
    }

    if (!std.mem.eql(u8, mode, "run")) {
        logging.err()
            .stringSafe("event", "process_start")
            .stringSafe("status", "error")
            .string("mode", mode)
            .stringSafe("error", "InvalidArgument")
            .log();
        logging.err()
            .stringSafe("event", "usage")
            .string("expected", "zig-coordinator <run|healthcheck>")
            .log();
        return error.InvalidArgument;
    }

    try service.bootstrap();
    try service.healthcheck();
    const cursor = try service.ensureCursors();
    defer allocator.free(cursor);

    logging.info()
        .stringSafe("event", "ready")
        .string("mode", "run")
        .string("primary_stream", cfg.stream_name)
        .string("configured_streams", cfg.stream_names_csv)
        .string("oracle_streams", cfg.oracle_stream_names_csv)
        .string("cursor", cursor)
        .fmt("topics", "{s},{s},{s}", .{ cfg.scan_topic, cfg.load_topic, cfg.result_topic })
        .log();

    installSignalHandlers();
    try service.run(&should_shutdown, &shutdown_signal);
}

fn installSignalHandlers() void {
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);
}

fn handleShutdownSignal(sig: std.posix.SIG) callconv(.c) void {
    shutdown_signal.store(@intFromEnum(sig), .release);
    should_shutdown.store(true, .release);
}
