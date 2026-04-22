const std = @import("std");
const config = @import("config.zig");
const scheduler = @import("scheduler.zig");

const SERVICE_NAME = "zig-coordinator";
const HEARTBEAT_INTERVAL_MS: u64 = 300 * 1000;

var should_shutdown = std.atomic.Value(bool).init(false);
var shutdown_signal = std.atomic.Value(u32).init(0);

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

    std.debug.print(
        "service={s} event=process_start mode={s} stream_name={s} stream_names={s} scan_subject={s} load_subject={s} result_subject={s}\n",
        .{ SERVICE_NAME, mode, cfg.stream_name, cfg.stream_names_csv, cfg.scan_subject, cfg.load_subject, cfg.result_subject },
    );

    if (std.mem.eql(u8, mode, "healthcheck")) {
        try healthcheck(gpa, init.io, cfg);
        std.debug.print("service={s} event=process_exit mode=healthcheck status=ok\n", .{SERVICE_NAME});
        return;
    }

    if (!std.mem.eql(u8, mode, "run")) {
        std.debug.print("service={s} event=process_start status=error mode={s} error=InvalidArgument\n", .{ SERVICE_NAME, mode });
        std.debug.print("usage: zig-coordinator <run|healthcheck>\n", .{});
        return error.InvalidArgument;
    }

    try healthcheck(gpa, init.io, cfg);
    try ensureCursors(&coordinator, cfg.stream_names_csv);
    const cursor = coordinator.loadCursor(cfg.stream_name) orelse return HealthcheckError.CursorNotFound;

    std.debug.print(
        "service={s} event=ready mode=run primary_stream={s} configured_streams={s} cursor={s} subjects={s},{s},{s}\n",
        .{ SERVICE_NAME, cfg.stream_name, cfg.stream_names_csv, cursor.cursor_value, cfg.scan_subject, cfg.load_subject, cfg.result_subject },
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

fn handleShutdownSignal(sig: std.posix.SIG) callconv(.c) void {
    shutdown_signal.store(@intFromEnum(sig), .release);
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
    const start_ts = std.Io.Timestamp.now(io, .awake);
    std.debug.print("service={s} event=healthcheck status=start\n", .{SERVICE_NAME});
    if (cfg.database_url.len == 0) {
        std.debug.print(
            "service={s} event=healthcheck status=error duration_ms={d} error=MissingDatabaseUrl\n",
            .{ SERVICE_NAME, elapsedMs(start_ts, io) },
        );
        return HealthcheckError.MissingDatabaseUrl;
    }
    if (cfg.sync_nats_url.len == 0) {
        std.debug.print(
            "service={s} event=healthcheck status=error duration_ms={d} error=MissingNatsUrl\n",
            .{ SERVICE_NAME, elapsedMs(start_ts, io) },
        );
        return HealthcheckError.MissingNatsUrl;
    }

    const apply_schema_started_ts = std.Io.Timestamp.now(io, .awake);
    std.debug.print("service={s} event=healthcheck_step status=start step=apply_schema\n", .{SERVICE_NAME});
    applySchema(gpa, io, cfg.database_url, cfg.sync_schema_file) catch |err| {
        std.debug.print(
            "service={s} event=healthcheck_step status=error step=apply_schema duration_ms={d} error={}\n",
            .{ SERVICE_NAME, elapsedMs(apply_schema_started_ts, io), err },
        );
        std.debug.print(
            "service={s} event=healthcheck status=error duration_ms={d} failed_step=apply_schema\n",
            .{ SERVICE_NAME, elapsedMs(start_ts, io) },
        );
        return err;
    };
    std.debug.print(
        "service={s} event=healthcheck_step status=ok step=apply_schema duration_ms={d}\n",
        .{ SERVICE_NAME, elapsedMs(apply_schema_started_ts, io) },
    );

    const check_nats_started_ts = std.Io.Timestamp.now(io, .awake);
    std.debug.print("service={s} event=healthcheck_step status=start step=check_nats\n", .{SERVICE_NAME});
    checkNats(gpa, io, cfg.sync_nats_url) catch |err| {
        std.debug.print(
            "service={s} event=healthcheck_step status=error step=check_nats duration_ms={d} error={}\n",
            .{ SERVICE_NAME, elapsedMs(check_nats_started_ts, io), err },
        );
        std.debug.print(
            "service={s} event=healthcheck status=error duration_ms={d} failed_step=check_nats\n",
            .{ SERVICE_NAME, elapsedMs(start_ts, io) },
        );
        return err;
    };
    std.debug.print(
        "service={s} event=healthcheck_step status=ok step=check_nats duration_ms={d}\n",
        .{ SERVICE_NAME, elapsedMs(check_nats_started_ts, io) },
    );

    const check_stream_started_ts = std.Io.Timestamp.now(io, .awake);
    std.debug.print("service={s} event=healthcheck_step status=start step=check_nats_stream\n", .{SERVICE_NAME});
    checkNatsStream(gpa, io, cfg.sync_nats_url, cfg.audit_stream_name) catch |err| {
        std.debug.print(
            "service={s} event=healthcheck_step status=warn step=check_nats_stream stream={s} duration_ms={d} error={}\n",
            .{ SERVICE_NAME, cfg.audit_stream_name, elapsedMs(check_stream_started_ts, io), err },
        );
    };
    std.debug.print(
        "service={s} event=healthcheck_step status=ok step=check_nats_stream duration_ms={d}\n",
        .{ SERVICE_NAME, elapsedMs(check_stream_started_ts, io) },
    );

    const check_consumer_started_ts = std.Io.Timestamp.now(io, .awake);
    std.debug.print("service={s} event=healthcheck_step status=start step=check_nats_consumer\n", .{SERVICE_NAME});
    checkNatsConsumer(gpa, io, cfg.sync_nats_url, cfg.audit_stream_name, cfg.scan_consumer) catch |err| {
        std.debug.print(
            "service={s} event=healthcheck_step status=warn step=check_nats_consumer stream={s} consumer={s} duration_ms={d} error={}\n",
            .{ SERVICE_NAME, cfg.audit_stream_name, cfg.scan_consumer, elapsedMs(check_consumer_started_ts, io), err },
        );
    };
    std.debug.print(
        "service={s} event=healthcheck_step status=ok step=check_nats_consumer duration_ms={d}\n",
        .{ SERVICE_NAME, elapsedMs(check_consumer_started_ts, io) },
    );
    std.debug.print("service={s} event=healthcheck status=ok duration_ms={d}\n", .{ SERVICE_NAME, elapsedMs(start_ts, io) });
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
    const start_ts = std.Io.Timestamp.now(init.io, .awake);
    var last_heartbeat_ts = start_ts;
    var last_shadow_audit_ts: ?std.Io.Timestamp = null;
    while (!shutdown.load(.acquire)) {
        const had_work = runCoordinatorIteration(init.io, coordinator, cfg, &last_shadow_audit_ts) catch |err| {
            std.debug.print("service={s} event=coordinator_iteration status=error error={}\n", .{ SERVICE_NAME, err });
            sleepUnlessShutdown(init.io, shutdown, 5000);
            maybeLogHeartbeat(start_ts, &last_heartbeat_ts, init.io);
            continue;
        };
        if (had_work) {
            std.debug.print("service={s} event=coordinator_iteration status=ok work_detected=true\n", .{SERVICE_NAME});
        }
        if (!had_work) {
            sleepUnlessShutdown(init.io, shutdown, 1000);
        }
        maybeLogHeartbeat(start_ts, &last_heartbeat_ts, init.io);
    }
    const signal = shutdown_signal.load(.acquire);
    if (signal != 0) {
        std.debug.print("service={s} event=signal_received signal={d}\n", .{ SERVICE_NAME, signal });
    }
    std.debug.print(
        "service={s} event=shutdown status=graceful uptime_s={d}\n",
        .{ SERVICE_NAME, elapsedMs(start_ts, init.io) / 1000 },
    );
}

fn sleepUnlessShutdown(io: std.Io, shutdown: *std.atomic.Value(bool), total_ms: u64) void {
    var remaining_ms = total_ms;
    while (remaining_ms > 0 and !shutdown.load(.acquire)) {
        const step_ms = @min(remaining_ms, 100);
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(step_ms)), .awake) catch |sleep_err| {
            std.debug.print("service={s} event=sleep status=error error={}\n", .{ SERVICE_NAME, sleep_err });
            return;
        };
        remaining_ms -= step_ms;
    }
}

fn runCoordinatorIteration(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config, last_shadow_audit_ts: *?std.Io.Timestamp) !bool {
    var had_work = false;
    had_work = (try handleCursor(io, coordinator, cfg)) or had_work;
    had_work = (try processBatches(io, coordinator, cfg)) or had_work;
    had_work = (try dedupeAndDispatch(io, coordinator, cfg)) or had_work;
    had_work = (try updateJobState(io, coordinator, cfg)) or had_work;
    had_work = (try handleResults(io, coordinator, cfg)) or had_work;
    had_work = (try runShadowAudit(io, cfg, last_shadow_audit_ts)) or had_work;
    return had_work;
}

fn handleCursor(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    return processIngestLedger(io, cfg);
}

fn processIngestLedger(io: std.Io, cfg: config.Config) !bool {
    const mark_sql =
        \\update sync_scan_ingest ingest
        \\   set status = 'batched',
        \\       updated_at = now()
        \\ where status = 'processing'
        \\   and exists (select 1 from sync_batch batch where batch.dedupe_key = ingest.dedupe_key)
        \\returning dedupe_key;
    ;
    const mark_argv = [_][]const u8{
        "psql",
        cfg.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        mark_sql,
    };
    var had_work = runCommandForWork(std.heap.page_allocator, io, &mark_argv, HealthcheckError.IngestProcessFailed) catch false;

    const quoted_stream_names = try sqlQuoteLiteral(std.heap.page_allocator, cfg.stream_names_csv);
    defer std.heap.page_allocator.free(quoted_stream_names);

    const ingest_sql = try std.fmt.allocPrint(std.heap.page_allocator,
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
        \\        and stream_name = any(string_to_array({s}, ','))
        \\        and attempt_count < {d}
        \\        and (
        \\              status = 'pending'
        \\              or observed_at <= now() - make_interval(secs => (greatest(attempt_count, 1) * {d}))
        \\            )
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
        \\),
        \\mark_batched as (
        \\  update sync_scan_ingest ingest
        \\     set status = 'batched',
        \\         updated_at = now()
        \\    from batch_upsert
        \\   where ingest.dedupe_key = batch_upsert.dedupe_key
        \\  returning ingest.dedupe_key
        \\)
        \\select dedupe_key from mark_batched;
    , .{ quoted_stream_names, cfg.scan_max_attempts, cfg.scan_retry_backoff_seconds });
    defer std.heap.page_allocator.free(ingest_sql);

    const ingest_argv = [_][]const u8{
        "psql",
        cfg.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        ingest_sql,
    };
    had_work = (try runCommandForWork(std.heap.page_allocator, io, &ingest_argv, HealthcheckError.IngestProcessFailed)) or had_work;
    return had_work;
}

fn sqlQuoteLiteral(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var length: usize = 2;
    for (value) |byte| {
        length += 1;
        if (byte == 39) length += 1;
    }

    const quoted = try allocator.alloc(u8, length);
    var index: usize = 0;
    quoted[index] = 39;
    index += 1;

    for (value) |byte| {
        quoted[index] = byte;
        index += 1;
        if (byte == 39) {
            quoted[index] = 39;
            index += 1;
        }
    }

    quoted[index] = 39;
    return quoted;
}

fn processBatches(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = io;
    _ = coordinator;
    _ = cfg;
    return false;
}

fn dedupeAndDispatch(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    const sql =
        \\with picked as (
        \\  select batch.batch_id
        \\    from sync_batch batch
        \\   where batch.status = 'pending'
        \\   order by batch.batch_id
        \\   limit 1
        \\   for update skip locked
        \\),
        \\updated as (
        \\  update sync_batch batch
        \\     set status = 'dispatched',
        \\         attempt_count = batch.attempt_count + 1,
        \\         last_error = null,
        \\         updated_at = now()
        \\    from picked
        \\   where batch.batch_id = picked.batch_id
        \\  returning batch.batch_id, batch.job_id, batch.batch_no, batch.payload_ref,
        \\            batch.cursor_start, batch.cursor_end, batch.attempt_count
        \\),
        \\job_mark as (
        \\  update sync_job job
        \\     set status = 'running',
        \\         started_at = coalesce(job.started_at, now())
        \\    from updated
        \\   where job.job_id = updated.job_id
        \\  returning job.job_id, job.stream_name
        \\)
        \\select json_build_object(
        \\  'job_id', updated.job_id::text,
        \\  'batch_id', updated.batch_id::text,
        \\  'batch_no', updated.batch_no,
        \\  'stream_name', job_mark.stream_name,
        \\  'payload_ref', updated.payload_ref,
        \\  'cursor_start', updated.cursor_start,
        \\  'cursor_end', updated.cursor_end,
        \\  'attempt', updated.attempt_count
        \\)::text
        \\from updated
        \\join job_mark on job_mark.job_id = updated.job_id;
    ;
    const query_argv = [_][]const u8{
        "psql",
        cfg.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        sql,
    };
    const payload = (try runCommandOutput(std.heap.page_allocator, io, &query_argv, HealthcheckError.IngestProcessFailed)) orelse return false;
    defer std.heap.page_allocator.free(payload);

    const pub_argv = [_][]const u8{
        "nats",
        "--server",
        cfg.sync_nats_url,
        "pub",
        cfg.load_subject,
        payload,
    };
    try runCommand(std.heap.page_allocator, io, &pub_argv, HealthcheckError.IngestProcessFailed);
    return true;
}

fn updateJobState(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = io;
    _ = coordinator;
    _ = cfg;
    return false;
}

fn runShadowAudit(io: std.Io, cfg: config.Config, last_shadow_audit_ts: *?std.Io.Timestamp) !bool {
    const now = std.Io.Timestamp.now(io, .awake);
    if (last_shadow_audit_ts.*) |last_run| {
        if (last_run.durationTo(now).toMilliseconds() < 10_000) {
            return false;
        }
    }
    last_shadow_audit_ts.* = now;

    const script =
        \\set -eu
        \\tmp="$(mktemp)"
        \\psql "$2" -v ON_ERROR_STOP=1 -qAt -c "
        \\with wireless as (
        \\  select
        \\    observed_at,
        \\    lower(source_mac) as source_mac,
        \\    lower(coalesce(destination_bssid, bssid)) as destination_bssid,
        \\    ssid,
        \\    signal_dbm,
        \\    payload->>'sensor_id' as sensor_id,
        \\    payload->>'location_id' as location_id
        \\  from sync_scan_ingest
        \\  where stream_name = 'wireless.audit'
        \\    and observed_at >= now() - interval '60 seconds'
        \\    and source_mac is not null
        \\    and signal_dbm >= -50
        \\),
        \\candidates as (
        \\  select distinct on (source_mac, destination_bssid, coalesce(location_id, ''))
        \\    md5(source_mac || '|' || coalesce(destination_bssid, '') || '|' || coalesce(location_id, '') || '|' || date_trunc('minute', observed_at)::text) as dedupe_key,
        \\    observed_at,
        \\    source_mac,
        \\    destination_bssid,
        \\    ssid,
        \\    sensor_id,
        \\    location_id,
        \\    signal_dbm,
        \\    'strong_wireless_without_proxy_presence'::text as reason,
        \\    jsonb_build_object(
        \\      'window_seconds', 60,
        \\      'signal_threshold_dbm', -50,
        \\      'presence_window_seconds', 300
        \\    ) as evidence
        \\  from wireless w
        \\  where not exists (
        \\    select 1
        \\    from authorized_wireless_networks awn
        \\    where awn.enabled
        \\      and (awn.location_id is null or awn.location_id = w.location_id)
        \\      and (awn.ssid is null or (w.ssid is not null and lower(awn.ssid) = lower(w.ssid)))
        \\      and (awn.bssid is null or (w.destination_bssid is not null and lower(awn.bssid) = w.destination_bssid))
        \\      and (awn.ssid is not null or awn.bssid is not null)
        \\  )
        \\    and not exists (
        \\      select 1
        \\      from devices d
        \\      where d.mac_hint is not null
        \\        and lower(d.mac_hint) = w.source_mac
        \\        and d.last_seen >= now() - interval '5 minutes'
        \\    )
        \\    and not exists (
        \\      select 1
        \\      from sync_scan_ingest proxy
        \\      join devices d on d.device_id = proxy.payload->>'device_id'
        \\      where proxy.stream_name = 'proxy.events'
        \\        and proxy.observed_at >= now() - interval '5 minutes'
        \\        and d.mac_hint is not null
        \\        and lower(d.mac_hint) = w.source_mac
        \\    )
        \\  order by source_mac, destination_bssid, coalesce(location_id, ''), observed_at desc
        \\),
        \\inserted as (
        \\  insert into shadow_it_alerts (
        \\    dedupe_key, observed_at, source_mac, destination_bssid, ssid, sensor_id,
        \\    location_id, signal_dbm, reason, evidence, created_at, updated_at
        \\  )
        \\  select
        \\    dedupe_key, observed_at, source_mac, destination_bssid, ssid, sensor_id,
        \\    location_id, signal_dbm, reason, evidence, now(), now()
        \\  from candidates
        \\  on conflict (dedupe_key) do nothing
        \\  returning *
        \\)
        \\select json_build_object(
        \\  'event_type', 'shadow_device',
        \\  'observed_at', observed_at,
        \\  'source_mac', source_mac,
        \\  'destination_bssid', destination_bssid,
        \\  'ssid', ssid,
        \\  'sensor_id', sensor_id,
        \\  'location_id', location_id,
        \\  'signal_dbm', signal_dbm,
        \\  'reason', reason,
        \\  'evidence', evidence
        \\)::text
        \\from inserted;
        \\" > "$tmp"
        \\if [ -s "$tmp" ]; then
        \\  while IFS= read -r line; do
        \\    [ -n "$line" ] || continue
        \\    nats --server "$1" pub audit.threat.shadow_device "$line" >/dev/null
        \\  done < "$tmp"
        \\  echo work
        \\fi
        \\rm -f "$tmp"
    ;
    const argv = [_][]const u8{
        "sh",
        "-c",
        script,
        "zig-coordinator-shadow-audit",
        cfg.sync_nats_url,
        cfg.database_url,
    };
    return runCommandForWork(std.heap.page_allocator, io, &argv, HealthcheckError.IngestProcessFailed);
}

fn handleResults(io: std.Io, coordinator: *scheduler.Coordinator, cfg: config.Config) !bool {
    _ = coordinator;
    const script =
        \\set -eu
        \\tmp="$(mktemp)"
        \\had=0
        \\if nats --server "$1" consumer next "$2" "$3" --batch 50 --expires 250ms --raw > "$tmp" 2>/dev/null; then
        \\  while IFS= read -r line; do
        \\    [ -n "$line" ] || continue
        \\    psql "$4" -v ON_ERROR_STOP=1 -v result="$line" -qAt -c "
        \\with result as (
        \\  select :'result'::jsonb as payload
        \\),
        \\batch_update as (
        \\  update sync_batch batch
        \\     set status = case result.payload->>'status'
        \\                    when 'success' then 'completed'
        \\                    when 'completed' then 'completed'
        \\                    else 'failed'
        \\                  end,
        \\         row_count = coalesce((result.payload->>'row_count')::integer, row_count),
        \\         checksum = nullif(result.payload->>'checksum', ''),
        \\         last_error = nullif(result.payload->>'error_text', ''),
        \\         updated_at = now()
        \\    from result
        \\   where batch.batch_id = (result.payload->>'batch_id')::uuid
        \\  returning batch.job_id, batch.batch_id, batch.status, batch.last_error
        \\),
        \\error_insert as (
        \\  insert into sync_error (job_id, batch_id, error_class, error_text)
        \\  select job_id, batch_id, coalesce(nullif((select payload->>'error_class' from result), ''), 'unknown'),
        \\         coalesce(last_error, 'oracle load failed')
        \\    from batch_update
        \\   where status = 'failed'
        \\  returning id
        \\),
        \\job_done as (
        \\  update sync_job job
        \\     set status = case
        \\                    when exists (select 1 from sync_batch b where b.job_id = job.job_id and b.status = 'failed') then 'failed'
        \\                    else 'completed'
        \\                  end,
        \\         finished_at = now()
        \\   where job.job_id in (select job_id from batch_update)
        \\     and not exists (
        \\       select 1 from sync_batch b
        \\        where b.job_id = job.job_id
        \\          and b.status not in ('completed', 'failed')
        \\     )
        \\  returning job_id
        \\)
        \\select coalesce((select batch_id::text from batch_update limit 1), '');
        \\"
        \\    had=1
        \\  done < "$tmp"
        \\fi
        \\rm -f "$tmp"
        \\if [ "$had" = "1" ]; then echo work; fi
    ;
    const argv = [_][]const u8{
        "sh",
        "-c",
        script,
        "zig-coordinator-results",
        cfg.sync_nats_url,
        cfg.audit_stream_name,
        cfg.result_consumer,
        cfg.database_url,
    };
    return runCommandForWork(std.heap.page_allocator, io, &argv, HealthcheckError.IngestProcessFailed);
}

fn runCommand(
    gpa: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    on_error: anyerror,
) !void {
    const start_ts = std.Io.Timestamp.now(io, .awake);
    std.debug.print(
        "service={s} event=command_execution status=start command={s} arg_count={d}\n",
        .{ SERVICE_NAME, argv[0], argv.len },
    );
    const result = std.process.run(gpa, io, .{
        .argv = argv,
        .expand_arg0 = .expand,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch |err| {
        std.debug.print(
            "service={s} event=command_execution status=error command={s} duration_ms={d} error={}\n",
            .{ SERVICE_NAME, argv[0], elapsedMs(start_ts, io), err },
        );
        return on_error;
    };
    defer {
        gpa.free(result.stdout);
        gpa.free(result.stderr);
    }

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                var stderr_buffer: [256]u8 = undefined;
                const stderr_snippet = sanitizeSnippet(&stderr_buffer, result.stderr);
                std.debug.print(
                    "service={s} event=command_execution status=error command={s} exit_code={d} duration_ms={d} stderr=\"{s}\"\n",
                    .{ SERVICE_NAME, argv[0], code, elapsedMs(start_ts, io), stderr_snippet },
                );
                return on_error;
            }
            std.debug.print(
                "service={s} event=command_execution status=ok command={s} exit_code={d} duration_ms={d}\n",
                .{ SERVICE_NAME, argv[0], code, elapsedMs(start_ts, io) },
            );
        },
        else => {
            std.debug.print(
                "service={s} event=command_execution status=error command={s} duration_ms={d} error=TerminatedUnexpectedly\n",
                .{ SERVICE_NAME, argv[0], elapsedMs(start_ts, io) },
            );
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
    const start_ts = std.Io.Timestamp.now(io, .awake);
    const result = std.process.run(gpa, io, .{
        .argv = argv,
        .expand_arg0 = .expand,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch |err| {
        std.debug.print(
            "service={s} event=command_execution status=error command={s} duration_ms={d} error={}\n",
            .{ SERVICE_NAME, argv[0], elapsedMs(start_ts, io), err },
        );
        return on_error;
    };
    defer {
        gpa.free(result.stdout);
        gpa.free(result.stderr);
    }

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                var stderr_buffer: [256]u8 = undefined;
                const stderr_snippet = sanitizeSnippet(&stderr_buffer, result.stderr);
                std.debug.print(
                    "service={s} event=command_execution status=error command={s} exit_code={d} duration_ms={d} stderr=\"{s}\"\n",
                    .{ SERVICE_NAME, argv[0], code, elapsedMs(start_ts, io), stderr_snippet },
                );
                return on_error;
            }
        },
        else => {
            std.debug.print(
                "service={s} event=command_execution status=error command={s} duration_ms={d} error=TerminatedUnexpectedly\n",
                .{ SERVICE_NAME, argv[0], elapsedMs(start_ts, io) },
            );
            return on_error;
        },
    }

    const work_detected = std.mem.trim(u8, result.stdout, " \t\r\n").len > 0;
    if (work_detected) {
        std.debug.print(
            "service={s} event=command_output status=ok command={s} work_detected=true duration_ms={d}\n",
            .{ SERVICE_NAME, argv[0], elapsedMs(start_ts, io) },
        );
    }
    return work_detected;
}

fn runCommandOutput(
    gpa: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    on_error: anyerror,
) !?[]u8 {
    const start_ts = std.Io.Timestamp.now(io, .awake);
    const result = std.process.run(gpa, io, .{
        .argv = argv,
        .expand_arg0 = .expand,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch |err| {
        std.debug.print(
            "service={s} event=command_execution status=error command={s} duration_ms={d} error={}\n",
            .{ SERVICE_NAME, argv[0], elapsedMs(start_ts, io), err },
        );
        return on_error;
    };
    defer {
        gpa.free(result.stdout);
        gpa.free(result.stderr);
    }

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                var stderr_buffer: [256]u8 = undefined;
                const stderr_snippet = sanitizeSnippet(&stderr_buffer, result.stderr);
                std.debug.print(
                    "service={s} event=command_execution status=error command={s} exit_code={d} duration_ms={d} stderr=\"{s}\"\n",
                    .{ SERVICE_NAME, argv[0], code, elapsedMs(start_ts, io), stderr_snippet },
                );
                return on_error;
            }
        },
        else => {
            std.debug.print(
                "service={s} event=command_execution status=error command={s} duration_ms={d} error=TerminatedUnexpectedly\n",
                .{ SERVICE_NAME, argv[0], elapsedMs(start_ts, io) },
            );
            return on_error;
        },
    }

    const output = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (output.len == 0) return null;
    return try gpa.dupe(u8, output);
}

fn elapsedMs(start_ts: std.Io.Timestamp, io: std.Io) u64 {
    const duration = start_ts.untilNow(io, .awake);
    const elapsed_ms = duration.toMilliseconds();
    if (elapsed_ms <= 0) return 0;
    return @intCast(elapsed_ms);
}

fn maybeLogHeartbeat(start_ts: std.Io.Timestamp, last_heartbeat_ts: *std.Io.Timestamp, io: std.Io) void {
    const now = std.Io.Timestamp.now(io, .awake);
    const since_last_ms = last_heartbeat_ts.*.durationTo(now).toMilliseconds();
    if (since_last_ms < @as(i64, @intCast(HEARTBEAT_INTERVAL_MS))) return;

    std.debug.print(
        "service={s} event=heartbeat uptime_s={d} interval_s=300\n",
        .{ SERVICE_NAME, elapsedMs(start_ts, io) / 1000 },
    );
    last_heartbeat_ts.* = now;
}

fn sanitizeSnippet(buffer: []u8, raw: []const u8) []const u8 {
    var in_index: usize = 0;
    var out_index: usize = 0;

    while (in_index < raw.len and out_index < buffer.len) : (in_index += 1) {
        const byte = raw[in_index];
        if (byte == '\n' or byte == '\r' or byte == '\t') {
            buffer[out_index] = ' ';
        } else {
            buffer[out_index] = byte;
        }
        out_index += 1;
    }

    return std.mem.trim(u8, buffer[0..out_index], " ");
}
