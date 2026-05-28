const std = @import("std");
const config = @import("config.zig");
const db = @import("db.zig");
const db_sync = @import("db_sync.zig");
const logging = @import("logging.zig");
const redpanda_health = @import("redpanda_health.zig");
const topic_manifest = @import("topic_manifest.zig");
const sync_handlers = @import("sync_handlers.zig");
const wireless_handlers = @import("wireless_handlers.zig");

const HEARTBEAT_INTERVAL_MS: u64 = 300 * 1000;
const SHADOW_AUDIT_INTERVAL_MS: i64 = 10_000;

pub const Error = error{
    MissingDatabaseUrl,
    MissingRedpandaUrl,
    InvalidRedpandaUrl,
    RedpandaCheckFailed,
    RedpandaStreamMissing,
    RedpandaStreamTopicMissing,
    RedpandaConsumerMissing,
    RedpandaConsumerFilterMismatch,
    CursorNotFound,
    ScanFetchFailed,
    ScanIngestFailed,
    PayloadResolveFailed,
    BatchDispatchFailed,
    ResultFetchFailed,
    AlertPublishFailed,
    BacklogOperationFailed,
    MacLookupFailed,
    NetworksListFailed,
    ProbeFlushFailed,
    WirelessMessageFailed,
} || db.Error || redpanda_health.Error;

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    database: db.Client,
    last_shadow_audit_ts: ?std.Io.Timestamp,
    inflight: u64,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        cfg: config.Config,
    ) !Service {
        return .{
            .allocator = allocator,
            .io = io,
            .cfg = cfg,
            .database = db.Client.init(allocator, io, cfg.database_url, cfg.sync_schema_file),
            .last_shadow_audit_ts = null,
            .inflight = 0,
        };
    }

    pub fn deinit(self: *Service) void {
        _ = self;
    }

    pub fn healthcheck(self: *Service) Error!void {
        const start_ts = std.Io.Timestamp.now(self.io, .awake);
        logging.info().stringSafe("event", "healthcheck").stringSafe("status", "start").log();

        if (self.cfg.database_url.len == 0) {
            logging.err()
                .stringSafe("event", "healthcheck")
                .stringSafe("status", "error")
                .stringSafe("error", "MissingDatabaseUrl")
                .int("duration_ms", elapsedMs(start_ts, self.io))
                .log();
            return error.MissingDatabaseUrl;
        }
        if (self.cfg.sync_redpanda_url.len == 0) {
            logging.err()
                .stringSafe("event", "healthcheck")
                .stringSafe("status", "error")
                .stringSafe("error", "MissingRedpandaUrl")
                .int("duration_ms", elapsedMs(start_ts, self.io))
                .log();
            return error.MissingRedpandaUrl;
        }

        try self.runLoggedStep("healthcheck_step", "check_postgres", Service.checkDatabaseConnectivity);
        try self.runLoggedStep("healthcheck_step", "check_redpanda", Service.checkRedpandaConnectivity);
        try self.runLoggedStep("healthcheck_step", "check_redpanda_streams", Service.checkRedpandaStreams);
        try self.runLoggedStep("healthcheck_step", "check_redpanda_consumers", Service.checkRedpandaConsumers);

        logging.info()
            .stringSafe("event", "healthcheck")
            .stringSafe("status", "ok")
            .int("duration_ms", elapsedMs(start_ts, self.io))
            .log();
    }

    pub fn bootstrap(self: *Service) Error!void {
        const start_ts = std.Io.Timestamp.now(self.io, .awake);
        logging.info().stringSafe("event", "bootstrap").stringSafe("status", "start").log();

        try self.runLoggedStep("bootstrap_step", "apply_schema", Service.applySchema);

        logging.info()
            .stringSafe("event", "bootstrap")
            .stringSafe("status", "ok")
            .int("duration_ms", elapsedMs(start_ts, self.io))
            .log();
    }

    pub fn ensureCursors(self: *Service) Error![]u8 {
        var primary_cursor: ?[]u8 = null;
        var iterator = std.mem.splitScalar(u8, self.cfg.stream_names_csv, ',');
        while (iterator.next()) |raw_name| {
            const stream_name = std.mem.trim(u8, raw_name, " \t\r\n");
            if (stream_name.len == 0) continue;

            const ensured = try self.database.ensureCursor(stream_name);
            if (std.mem.eql(u8, stream_name, self.cfg.stream_name)) {
                primary_cursor = ensured;
            } else {
                self.allocator.free(ensured);
            }
        }

        return primary_cursor orelse error.CursorNotFound;
    }

    pub fn run(self: *Service, shutdown: *std.atomic.Value(bool), shutdown_signal: *std.atomic.Value(u32)) !void {
        const start_ts = std.Io.Timestamp.now(self.io, .awake);
        var last_heartbeat_ts = start_ts;
        var consecutive_idle: u32 = 0;

        while (!shutdown.load(.acquire)) {
            const had_work = self.runIteration() catch |err| {
                logging.err().stringSafe("event", "iteration_failure").err(err).log();
                sleepUnlessShutdown(self.io, shutdown, 5000);
                maybeLogHeartbeat(start_ts, &last_heartbeat_ts, self.io);
                continue;
            };

            logging.debug()
                .stringSafe("event", "iteration_status")
                .boolean("work_detected", had_work)
                .log();

            if (!had_work) {
                consecutive_idle += 1;
                const sleep_ms = if (consecutive_idle >= 3) self.cfg.idle_sleep_backoff_ms else self.cfg.idle_sleep_ms;
                sleepUnlessShutdown(self.io, shutdown, sleep_ms);
            } else {
                consecutive_idle = 0;
            }
            maybeLogHeartbeat(start_ts, &last_heartbeat_ts, self.io);
        }

        const signal = shutdown_signal.load(.acquire);
        if (signal != 0) {
            logging.info().stringSafe("event", "signal_received").int("signal", signal).log();
        }
        logging.info()
            .stringSafe("event", "shutdown")
            .stringSafe("status", "graceful")
            .int("uptime_s", elapsedMs(start_ts, self.io) / 1000)
            .log();
    }

    fn runIteration(self: *Service) Error!bool {
        var had_work = false;

        // DB-driven backpressure — skip scan pull when ingest queue is too long.
        const budget: u64 = @as(u64, self.cfg.ingest_batch_size) * 2;
        const pending_count = db_sync.pendingLedgerCount(&self.database) catch 0;

        // Adaptive pull window — shrink fetch_count when DB is falling behind.
        const effective_scan_count: usize = if (pending_count >= budget)
            @max(1, budget -| pending_count)
        else
            self.cfg.scan_fetch_count;

        if (pending_count >= budget) {
            logging.info()
                .stringSafe("event", "backpressure")
                .stringSafe("status", "throttled")
                .int("pending_count", pending_count)
                .int("budget", budget)
                .int("effective_scan_count", effective_scan_count)
                .int("inflight", self.inflight)
                .log();
        }

        had_work = (try sync_handlers.drainScanRequests(self.allocator, self.io, self.cfg, &self.database, effective_scan_count, &self.inflight)) or had_work;
        had_work = (try db_sync.processIngestLedger(
            &self.database,
            self.cfg.stream_names_csv,
            self.cfg.oracle_stream_names_csv,
            self.cfg.scan_max_attempts,
            self.cfg.scan_retry_backoff_seconds,
            self.cfg.ingest_batch_size,
        )) or had_work;
        had_work = (try sync_handlers.recoverStaleDispatchedBatches(self.cfg, &self.database)) or had_work;
        had_work = (try sync_handlers.dispatchNextBatch(self.allocator, self.io, self.cfg, &self.database)) or had_work;
        had_work = (try sync_handlers.handleResults(self.allocator, self.io, self.cfg, &self.database)) or had_work;
        had_work = (try sync_handlers.runShadowAudit(self.allocator, self.io, self.cfg, &self.database, &self.last_shadow_audit_ts, SHADOW_AUDIT_INTERVAL_MS)) or had_work;
        had_work = (try wireless_handlers.run(self.allocator, self.io, self.cfg, &self.database)) or had_work;
        return had_work;
    }

    fn applySchema(self: *Service) Error!void {
        try self.database.applySchema();
    }

    fn checkDatabaseConnectivity(self: *Service) Error!void {
        try self.database.checkConnectivity();
    }

    fn checkRedpandaConnectivity(self: *Service) Error!void {
        try redpanda_health.checkConnectivity(self.allocator, self.io, self.cfg);
    }

    fn checkRedpandaStreams(self: *Service) Error!void {
        try redpanda_health.checkStreams(self.allocator, self.io, self.cfg);
    }

    fn checkRedpandaConsumers(self: *Service) Error!void {
        try redpanda_health.checkConsumers(self.allocator, self.io, self.cfg);
    }

    fn runLoggedStep(
        self: *Service,
        event_name: []const u8,
        step_name: []const u8,
        comptime step_fn: fn (*Service) Error!void,
    ) Error!void {
        const started_ts = std.Io.Timestamp.now(self.io, .awake);
        logging.info()
            .stringSafe("event", event_name)
            .stringSafe("status", "start")
            .string("step", step_name)
            .log();

        step_fn(self) catch |err| {
            logging.err()
                .stringSafe("event", event_name)
                .stringSafe("status", "error")
                .string("step", step_name)
                .int("duration_ms", elapsedMs(started_ts, self.io))
                .err(err)
                .log();
            return err;
        };

        logging.info()
            .stringSafe("event", event_name)
            .stringSafe("status", "ok")
            .string("step", step_name)
            .int("duration_ms", elapsedMs(started_ts, self.io))
            .log();
    }
};

fn sleepUnlessShutdown(io: std.Io, shutdown: *std.atomic.Value(bool), total_ms: u64) void {
    var remaining_ms = total_ms;
    while (remaining_ms > 0 and !shutdown.load(.acquire)) {
        const step_ms = @min(remaining_ms, 100);
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(step_ms)), .awake) catch |err| {
            logging.err().stringSafe("event", "sleep_failure").err(err).log();
            return;
        };
        remaining_ms -= step_ms;
    }
}

fn maybeLogHeartbeat(start_ts: std.Io.Timestamp, last_heartbeat_ts: *std.Io.Timestamp, io: std.Io) void {
    const now = std.Io.Timestamp.now(io, .awake);
    const since_last_ms = last_heartbeat_ts.*.durationTo(now).toMilliseconds();
    if (since_last_ms < @as(i64, @intCast(HEARTBEAT_INTERVAL_MS))) return;

    logging.info()
        .stringSafe("event", "heartbeat")
        .int("uptime_s", elapsedMs(start_ts, io) / 1000)
        .int("interval_s", HEARTBEAT_INTERVAL_MS / 1000)
        .log();
    last_heartbeat_ts.* = now;
}

fn elapsedMs(start_ts: std.Io.Timestamp, io: std.Io) u64 {
    const duration = start_ts.untilNow(io, .awake);
    const elapsed_ms = duration.toMilliseconds();
    if (elapsed_ms <= 0) return 0;
    return @intCast(elapsed_ms);
}

pub const invalidOracleStreamName = topic_manifest.invalidOracleStreamName;
