const std = @import("std");
const command = @import("command.zig");
const config = @import("config.zig");
const db = @import("db.zig");
const logging = @import("logging.zig");

const HEARTBEAT_INTERVAL_MS: u64 = 300 * 1000;
const SHADOW_AUDIT_INTERVAL_MS: i64 = 10_000;
const SHADOW_ALERT_SUBJECT = "audit.threat.shadow_device";

pub const Error = error{
    MissingDatabaseUrl,
    MissingNatsUrl,
    InvalidNatsUrl,
    NatsCheckFailed,
    NatsStreamMissing,
    NatsConsumerMissing,
    CursorNotFound,
    BatchDispatchFailed,
    ResultFetchFailed,
    AlertPublishFailed,
} || db.Error;

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    database: db.Client,
    last_shadow_audit_ts: ?std.Io.Timestamp,

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
        if (self.cfg.sync_nats_url.len == 0) {
            logging.err()
                .stringSafe("event", "healthcheck")
                .stringSafe("status", "error")
                .stringSafe("error", "MissingNatsUrl")
                .int("duration_ms", elapsedMs(start_ts, self.io))
                .log();
            return error.MissingNatsUrl;
        }

        try self.runHealthcheckStep("apply_schema", Service.applySchema);
        try self.runHealthcheckStep("check_nats", Service.checkNatsConnectivity);
        try self.runHealthcheckStep("check_nats_streams", Service.checkNatsStreams);
        try self.runHealthcheckStep("check_nats_consumers", Service.checkNatsConsumers);

        logging.info()
            .stringSafe("event", "healthcheck")
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
                sleepUnlessShutdown(self.io, shutdown, 1000);
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
        had_work = (try self.database.processIngestLedger(
            self.cfg.stream_names_csv,
            self.cfg.scan_max_attempts,
            self.cfg.scan_retry_backoff_seconds,
        )) or had_work;
        had_work = (try self.dispatchNextBatch()) or had_work;
        had_work = (try self.handleResults()) or had_work;
        had_work = (try self.runShadowAudit()) or had_work;
        return had_work;
    }

    fn dispatchNextBatch(self: *Service) Error!bool {
        const payload = try self.database.getNextBatch();
        defer if (payload) |value| self.allocator.free(value);

        if (payload) |value| {
            try self.publish(self.cfg.load_subject, value, error.BatchDispatchFailed);
            return true;
        }
        return false;
    }

    fn handleResults(self: *Service) Error!bool {
        const output = try self.pullResultMessages();
        defer if (output) |value| self.allocator.free(value);

        if (output == null) return false;

        var had_work = false;
        var iterator = std.mem.splitScalar(u8, output.?, '\n');
        while (iterator.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r\n");
            if (line.len == 0) continue;

            try self.database.processBatchResult(line);
            had_work = true;
        }
        return had_work;
    }

    fn runShadowAudit(self: *Service) Error!bool {
        const now = std.Io.Timestamp.now(self.io, .awake);
        if (self.last_shadow_audit_ts) |last_run| {
            if (last_run.durationTo(now).toMilliseconds() < SHADOW_AUDIT_INTERVAL_MS) {
                return false;
            }
        }

        const output = try self.database.generateShadowAlerts();
        defer if (output) |value| self.allocator.free(value);

        self.last_shadow_audit_ts = now;
        if (output == null) return false;

        var had_work = false;
        var iterator = std.mem.splitScalar(u8, output.?, '\n');
        while (iterator.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r\n");
            if (line.len == 0) continue;

            try self.publish(SHADOW_ALERT_SUBJECT, line, error.AlertPublishFailed);
            had_work = true;
        }
        return had_work;
    }

    fn applySchema(self: *Service) Error!void {
        try self.database.applySchema();
    }

    fn checkNatsConnectivity(self: *Service) Error!void {
        const authority = try parseNatsAuthority(self.allocator, self.cfg.sync_nats_url);
        defer self.allocator.free(authority);

        const host_start = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
        const host_and_port = authority[host_start..];
        const separator = std.mem.lastIndexOfScalar(u8, host_and_port, ':') orelse return error.InvalidNatsUrl;
        const host = host_and_port[0..separator];
        const port = host_and_port[separator + 1 ..];
        if (host.len == 0 or port.len == 0) return error.InvalidNatsUrl;

        const argv = [_][]const u8{
            "nc",
            "-z",
            host,
            port,
        };
        try self.runRequiredCommand(&argv, "nc", error.NatsCheckFailed);
    }

    fn checkNatsStreams(self: *Service) Error!void {
        try self.checkNatsStream(self.cfg.audit_stream_name);
        try self.checkNatsStream(self.cfg.result_stream_name);
    }

    fn checkNatsConsumers(self: *Service) Error!void {
        try self.checkNatsConsumer(self.cfg.audit_stream_name, self.cfg.scan_consumer);
        try self.checkNatsConsumer(self.cfg.audit_stream_name, self.cfg.load_consumer);
        try self.checkNatsConsumer(self.cfg.result_stream_name, self.cfg.result_consumer);
    }

    fn checkNatsStream(self: *Service, stream_name: []const u8) Error!void {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "stream",
            "info",
            stream_name,
        };
        try self.runRequiredCommand(&argv, "nats", error.NatsStreamMissing);
    }

    fn checkNatsConsumer(self: *Service, stream_name: []const u8, consumer_name: []const u8) Error!void {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "consumer",
            "info",
            stream_name,
            consumer_name,
        };
        try self.runRequiredCommand(&argv, "nats", error.NatsConsumerMissing);
    }

    fn pullResultMessages(self: *Service) Error!?[]u8 {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "consumer",
            "next",
            self.cfg.result_stream_name,
            self.cfg.result_consumer,
            "--count",
            "50",
            "--expires",
            "250ms",
            "--raw",
        };

        var result = command.exec(self.allocator, self.io, &argv) catch {
            return error.ResultFetchFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            if (looksLikeNoMessage(result.stderr)) return null;
            command.logFailure("nats", result);
            return error.ResultFetchFailed;
        }

        command.logOutput("nats", result.stdout);
        const output = command.trimmedOutput(result.stdout);
        if (output.len == 0) return null;
        return self.allocator.dupe(u8, output) catch error.ResultFetchFailed;
    }

    fn publish(self: *Service, subject: []const u8, payload: []const u8, on_error: Error) Error!void {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "pub",
            subject,
            payload,
        };
        try self.runRequiredCommand(&argv, "nats", on_error);
    }

    fn runRequiredCommand(self: *Service, argv: []const []const u8, command_name: []const u8, on_error: Error) Error!void {
        var result = command.exec(self.allocator, self.io, argv) catch {
            return on_error;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure(command_name, result);
            return on_error;
        }

        command.logOutput(command_name, result.stdout);
    }

    fn runHealthcheckStep(
        self: *Service,
        step_name: []const u8,
        comptime step_fn: fn (*Service) Error!void,
    ) Error!void {
        const started_ts = std.Io.Timestamp.now(self.io, .awake);
        logging.info()
            .stringSafe("event", "healthcheck_step")
            .stringSafe("status", "start")
            .string("step", step_name)
            .log();

        step_fn(self) catch |err| {
            logging.err()
                .stringSafe("event", "healthcheck_step")
                .stringSafe("status", "error")
                .string("step", step_name)
                .int("duration_ms", elapsedMs(started_ts, self.io))
                .err(err)
                .log();
            return err;
        };

        logging.info()
            .stringSafe("event", "healthcheck_step")
            .stringSafe("status", "ok")
            .string("step", step_name)
            .int("duration_ms", elapsedMs(started_ts, self.io))
            .log();
    }
};

fn parseNatsAuthority(allocator: std.mem.Allocator, nats_url: []const u8) Error![]u8 {
    const trimmed = std.mem.trim(u8, nats_url, " \t\r\n");
    const no_scheme = if (std.mem.startsWith(u8, trimmed, "nats://")) trimmed["nats://".len..] else trimmed;
    var iterator = std.mem.splitScalar(u8, no_scheme, '/');
    const authority = iterator.first();
    if (authority.len == 0) return error.InvalidNatsUrl;

    const host_start = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
    const host_and_port = authority[host_start..];
    if (std.mem.lastIndexOfScalar(u8, host_and_port, ':') != null) {
        return allocator.dupe(u8, authority) catch error.InvalidNatsUrl;
    }

    return std.fmt.allocPrint(allocator, "{s}:4222", .{authority}) catch error.InvalidNatsUrl;
}

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

fn looksLikeNoMessage(stderr: []const u8) bool {
    return containsAsciiCaseInsensitive(stderr, "timeout") or
        containsAsciiCaseInsensitive(stderr, "timed out") or
        containsAsciiCaseInsensitive(stderr, "no messages");
}

fn containsAsciiCaseInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        var matched = true;
        var offset: usize = 0;
        while (offset < needle.len) : (offset += 1) {
            if (std.ascii.toLower(haystack[index + offset]) != std.ascii.toLower(needle[offset])) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }

    return false;
}

test "containsAsciiCaseInsensitive matches mixed case substrings" {
    try std.testing.expect(containsAsciiCaseInsensitive("Timed Out Waiting For Message", "timed out"));
    try std.testing.expect(!containsAsciiCaseInsensitive("all good", "timeout"));
}
