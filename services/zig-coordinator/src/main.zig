const std = @import("std");
const config = @import("config.zig");
const scheduler = @import("scheduler.zig");

var should_shutdown = std.atomic.Value(bool).init(false);

const HealthcheckError = error{
    MissingDatabaseUrl,
    MissingNatsUrl,
    SchemaApplyFailed,
    NatsCheckFailed,
    NatsStreamMissing,
    NatsConsumerMissing,
    IngestProcessFailed,
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
    try checkNatsStream(gpa, io, cfg.sync_nats_url, cfg.audit_stream_name);
    try checkNatsConsumer(gpa, io, cfg.sync_nats_url, cfg.audit_stream_name, cfg.scan_consumer);
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

fn checkNatsStream(gpa: std.mem.Allocator, io: std.Io, nats_url: []const u8, stream_name: []const u8) !void {
    const argv = [_][]const u8{
        "nats",
        "--server",
        nats_url,
        "stream",
        "info",
        stream_name,
    };
    try runCommand(gpa, io, &argv, HealthcheckError.NatsStreamMissing);
}

fn checkNatsConsumer(gpa: std.mem.Allocator, io: std.Io, nats_url: []const u8, stream_name: []const u8, consumer_name: []const u8) !void {
    const argv = [_][]const u8{
        "nats",
        "--server",
        nats_url,
        "consumer",
        "info",
        stream_name,
        consumer_name,
    };
    try runCommand(gpa, io, &argv, HealthcheckError.NatsConsumerMissing);
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
        const had_work = runCoordinatorIteration(init.io, coordinator, cfg) catch |err| {
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

fn runCoordinatorIteration(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    var had_work = false;
    had_work = (try handleCursor(io, coordinator, cfg)) or had_work;
    had_work = (try processBatches(io, coordinator, cfg)) or had_work;
    had_work = (try dedupeAndDispatch(io, coordinator, cfg)) or had_work;
    had_work = (try updateJobState(io, coordinator, cfg)) or had_work;
    had_work = (try handleResults(io, coordinator, cfg)) or had_work;
    return had_work;
}

fn handleCursor(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    return processIngestLedger(io, cfg);
}

fn processIngestLedger(io: std.Io, cfg: config.Config) !bool {
    const sql =
        \\with next_ingest as (
        \\  update sync_scan_ingest
        \\     set status = 'processing',
        \\         attempt_count = attempt_count + 1,
        \\         updated_at = now(),
        \\         last_error = null
        \\   where dedupe_key = (
        \\     select dedupe_key
        \\       from sync_scan_ingest
        \\      where status in ('pending', 'failed')
        \\      order by observed_at asc
        \\      limit 1
        \\      for update skip locked
        \\   )
        \\  returning *
        \\),
        \\job_upsert as (
        \\  insert into sync_job (job_id, stream_name, status, attempt_count, created_at, started_at)
        \\  select sync_stable_uuid(dedupe_key || ':job'), stream_name, 'pending', 0, now(), now()
        \\    from next_ingest
        \\  on conflict (job_id) do nothing
        \\  returning job_id
        \\),
        \\batch_upsert as (
        \\  insert into sync_batch (
        \\    batch_id, job_id, batch_no, payload_ref, status, row_count, checksum,
        \\    attempt_count, last_error, dedupe_key, cursor_start, cursor_end
        \\  )
        \\  select sync_stable_uuid(dedupe_key || ':batch'),
        \\         sync_stable_uuid(dedupe_key || ':job'),
        \\         0,
        \\         payload_ref,
        \\         'pending',
        \\         1,
        \\         payload_sha256,
        \\         0,
        \\         null,
        \\         dedupe_key,
        \\         coalesce((select cursor_value from sync_cursor where stream_name = next_ingest.stream_name), '0'),
        \\         extract(epoch from observed_at)::bigint::text
        \\    from next_ingest
        \\  on conflict (dedupe_key) do nothing
        \\  returning dedupe_key
        \\),
        \\cursor_upsert as (
        \\  insert into sync_cursor (stream_name, cursor_value, updated_at)
        \\  select stream_name, extract(epoch from observed_at)::bigint::text, now()
        \\    from next_ingest
        \\  on conflict (stream_name)
        \\  do update set cursor_value = excluded.cursor_value, updated_at = now()
        \\  returning stream_name
        \\)
        \\update sync_scan_ingest
        \\   set status = 'batched',
        \\       updated_at = now()
        \\ where dedupe_key in (select dedupe_key from next_ingest)
        \\returning dedupe_key;
    ;
    const argv = [_][]const u8{
        "psql",
        cfg.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        sql,
    };
    return runCommandForWork(std.heap.page_allocator, io, &argv, HealthcheckError.IngestProcessFailed);
}

fn processBatches(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = io;
    _ = coordinator;
    _ = cfg;
    return false;
}

fn dedupeAndDispatch(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = io;
    _ = coordinator;
    _ = cfg;
    return false;
}

fn updateJobState(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = io;
    _ = coordinator;
    _ = cfg;
    return false;
}

fn handleResults(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = io;
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

fn runCommandForWork(
    gpa: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    on_error: anyerror,
) !bool {
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

    return std.mem.trim(u8, result.stdout, " \t\r\n").len > 0;
}
