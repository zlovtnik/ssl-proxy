const std = @import("std");
const config = @import("config.zig");
const scheduler = @import("scheduler.zig");

var should_shutdown = std.atomic.Value(bool).init(false);

const HealthcheckError = error{
    MissingDatabaseUrl,
    MissingNatsUrl,
    SchemaApplyFailed,
    NatsCheckFailed,
    InvalidNatsUrl,
    CursorNotFound,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var coordinator = try scheduler.Coordinator.init(arena.allocator());
    defer coordinator.deinit();

    const cfg = config.load();
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const mode = if (args.next()) |value| value[0..value.len] else "run";

    if (std.mem.eql(u8, mode, "healthcheck")) {
        try healthcheck(gpa, init.io, cfg);
        return;
    }

    if (!std.mem.eql(u8, mode, "run")) {
        std.debug.print("usage: zig-coordinator <run|healthcheck>\n", .{});
        return error.InvalidArgument;
    }

    try healthcheck(gpa, init.io, cfg);
    try ensureCursors(&coordinator, cfg.stream_names_csv);
    const cursor = coordinator.loadCursor(cfg.stream_name) orelse return HealthcheckError.CursorNotFound;

    std.debug.print(
        "zig coordinator ready primary_stream={s} configured_streams={s} cursor={s} subjects={s},{s},{s}\n",
        .{ cfg.stream_name, cfg.stream_names_csv, cursor.cursor_value, cfg.scan_subject, cfg.load_subject, cfg.result_subject },
    );

    installSignalHandlers();
    try runCoordinatorLoop(init, &coordinator, cfg, &should_shutdown);
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

fn handleShutdownSignal(_: std.posix.SIG) callconv(.c) void {
    should_shutdown.store(true, .release);
}

fn ensureCursors(coordinator: anytype, stream_names_csv: []const u8) !void {
    var iterator = std.mem.splitScalar(u8, stream_names_csv, ',');
    while (iterator.next()) |raw_name| {
        const stream_name = std.mem.trim(u8, raw_name, " \t\r\n");
        if (stream_name.len == 0) continue;
        if (coordinator.loadCursor(stream_name) == null) {
            try coordinator.saveCursor(stream_name, "0");
        }
    }
}

fn healthcheck(gpa: std.mem.Allocator, io: std.Io, cfg: config.Config) !void {
    if (cfg.database_url.len == 0) return HealthcheckError.MissingDatabaseUrl;
    if (cfg.sync_nats_url.len == 0) return HealthcheckError.MissingNatsUrl;

    try applySchema(gpa, io, cfg.database_url, cfg.sync_schema_file);
    try checkNats(gpa, io, cfg.sync_nats_url);
}

fn applySchema(gpa: std.mem.Allocator, io: std.Io, database_url: []const u8, schema_file: []const u8) !void {
    const argv = [_][]const u8{
        "psql",
        database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-f",
        schema_file,
    };
    try runCommand(gpa, io, &argv, HealthcheckError.SchemaApplyFailed);
}

fn checkNats(gpa: std.mem.Allocator, io: std.Io, nats_url: []const u8) !void {
    const authority = try parseNatsAuthority(gpa, nats_url);
    defer gpa.free(authority);
    const host_start = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
    const host_and_port = authority[host_start..];
    const separator = std.mem.lastIndexOfScalar(u8, host_and_port, ':') orelse return HealthcheckError.InvalidNatsUrl;
    const host = host_and_port[0..separator];
    const port = host_and_port[separator + 1 ..];
    if (host.len == 0 or port.len == 0) return HealthcheckError.InvalidNatsUrl;

    const argv = [_][]const u8{
        "nc",
        "-z",
        host,
        port,
    };
    try runCommand(gpa, io, &argv, HealthcheckError.NatsCheckFailed);
}

fn parseNatsAuthority(gpa: std.mem.Allocator, nats_url: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, nats_url, " \t\r\n");
    const no_scheme = if (std.mem.startsWith(u8, trimmed, "nats://")) trimmed["nats://".len..] else trimmed;
    var iterator = std.mem.splitScalar(u8, no_scheme, '/');
    const authority = iterator.first();
    if (authority.len == 0) return HealthcheckError.InvalidNatsUrl;
    const host_start = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
    const host_and_port = authority[host_start..];
    if (std.mem.lastIndexOfScalar(u8, host_and_port, ':') != null) return gpa.dupe(u8, authority);

    return try std.fmt.allocPrint(gpa, "{s}:4222", .{authority});
}

fn runCoordinatorLoop(init: std.process.Init, coordinator: *scheduler.Coordinator, cfg: config.Config, shutdown: *std.atomic.Value(bool)) !void {
    while (!shutdown.load(.acquire)) {
        const had_work = runCoordinatorIteration(coordinator, cfg) catch |err| {
            std.log.err("coordinator loop iteration failed: {}", .{err});
            sleepUnlessShutdown(init.io, shutdown, 5000);
            continue;
        };
        if (!had_work) {
            sleepUnlessShutdown(init.io, shutdown, 1000);
        }
    }
    std.log.info("coordinator loop shutting down gracefully", .{});
}

fn sleepUnlessShutdown(io: std.Io, shutdown: *std.atomic.Value(bool), total_ms: u64) void {
    var remaining_ms = total_ms;
    while (remaining_ms > 0 and !shutdown.load(.acquire)) {
        const step_ms = @min(remaining_ms, 100);
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(step_ms)), .awake) catch |sleep_err| {
            std.log.warn("sleep failed: {}", .{sleep_err});
            return;
        };
        remaining_ms -= step_ms;
    }
}

fn runCoordinatorIteration(coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    var had_work = false;
    had_work = (try handleCursor(coordinator, cfg)) or had_work;
    had_work = (try processBatches(coordinator, cfg)) or had_work;
    had_work = (try dedupeAndDispatch(coordinator, cfg)) or had_work;
    had_work = (try updateJobState(coordinator, cfg)) or had_work;
    had_work = (try handleResults(coordinator, cfg)) or had_work;
    return had_work;
}

fn handleCursor(coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    _ = cfg;
    return false;
}

fn processBatches(coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    _ = cfg;
    return false;
}

fn dedupeAndDispatch(coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    _ = cfg;
    return false;
}

fn updateJobState(coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    _ = cfg;
    return false;
}

fn handleResults(coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    _ = cfg;
    return false;
}

fn runCommand(
    gpa: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    on_error: anyerror,
) !void {
    const result = std.process.run(gpa, io, .{
        .argv = argv,
        .expand_arg0 = .expand,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch |err| {
        std.debug.print("failed to spawn {s}: {}\n", .{ argv[0], err });
        return on_error;
    };
    defer {
        gpa.free(result.stdout);
        gpa.free(result.stderr);
    }

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("{s} failed: {s}\n", .{ argv[0], result.stderr });
                return on_error;
            }
        },
        else => {
            std.debug.print("{s} terminated unexpectedly\n", .{argv[0]});
            return on_error;
        },
    }
}
