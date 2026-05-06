const std = @import("std");
const command = @import("command.zig");
const config = @import("config.zig");
const db = @import("db.zig");
const logging = @import("logging.zig");

const HEARTBEAT_INTERVAL_MS: u64 = 300 * 1000;
const SHADOW_AUDIT_INTERVAL_MS: i64 = 10_000;
const SHADOW_ALERT_SUBJECT = "audit.threat.shadow_device";
const INLINE_PAYLOAD_REF_PREFIX = "inline://json/";
const OUTBOX_PAYLOAD_REF_PREFIX = "outbox://";
const MAX_SCAN_PAYLOAD_BYTES = 16 * 1024 * 1024;
const MAX_SCAN_PAYLOAD_SQL_BYTES = 64 * 1024;

const ScanRequest = struct {
    stream_name: []const u8,
    dedupe_key: []const u8,
    payload_ref: []const u8,
    observed_at: []const u8,
};

pub const Error = error{
    MissingDatabaseUrl,
    MissingNatsUrl,
    InvalidNatsUrl,
    NatsCheckFailed,
    NatsStreamMissing,
    NatsConsumerMissing,
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

        try self.runLoggedStep("healthcheck_step", "check_postgres", Service.checkDatabaseConnectivity);
        try self.runLoggedStep("healthcheck_step", "check_nats", Service.checkNatsConnectivity);
        try self.runLoggedStep("healthcheck_step", "check_nats_streams", Service.checkNatsStreams);
        try self.runLoggedStep("healthcheck_step", "check_nats_consumers", Service.checkNatsConsumers);

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
        had_work = (try self.drainScanRequests()) or had_work;
        had_work = (try self.database.processIngestLedger(
            self.cfg.stream_names_csv,
            self.cfg.oracle_stream_names_csv,
            self.cfg.scan_max_attempts,
            self.cfg.scan_retry_backoff_seconds,
        )) or had_work;
        had_work = (try self.dispatchNextBatch()) or had_work;
        had_work = (try self.handleResults()) or had_work;
        had_work = (try self.runShadowAudit()) or had_work;
        if (try self.wirelessConsumerHasBacklog(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_save_consumer)) {
            had_work = (try self.handleBacklogSave()) or had_work;
        }
        if (try self.wirelessConsumerHasBacklog(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_list_consumer)) {
            had_work = (try self.handleBacklogList()) or had_work;
        }
        if (try self.wirelessConsumerHasBacklog(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_synced_consumer)) {
            had_work = (try self.handleBacklogSynced()) or had_work;
        }
        if (try self.wirelessConsumerHasBacklog(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_prune_consumer)) {
            had_work = (try self.handleBacklogPrune()) or had_work;
        }
        if (try self.wirelessConsumerHasBacklog(self.cfg.wireless_mac_stream_name, self.cfg.wireless_mac_lookup_consumer)) {
            had_work = (try self.handleMacLookup()) or had_work;
        }
        if (try self.wirelessConsumerHasBacklog(self.cfg.wireless_networks_stream_name, self.cfg.wireless_networks_authorized_consumer)) {
            had_work = (try self.handleNetworksAuthorized()) or had_work;
        }
        if (try self.wirelessConsumerHasBacklog(self.cfg.wireless_probe_stream_name, self.cfg.wireless_probe_flush_consumer)) {
            had_work = (try self.handleProbeFlush()) or had_work;
        }
        return had_work;
    }

    fn drainScanRequests(self: *Service) Error!bool {
        var had_work = false;
        var pulls: usize = 0;
        while (pulls < 50) : (pulls += 1) {
            if (!(try self.scanConsumerHasBacklog())) break;

            const output = try self.pullScanMessage();
            defer if (output) |value| self.allocator.free(value);
            if (output == null) break;

            var iterator = std.mem.splitScalar(u8, output.?, '\n');
            while (iterator.next()) |raw_line| {
                const line = std.mem.trim(u8, raw_line, " \t\r\n");
                if (line.len == 0) continue;

                if (try self.recordScanRequest(line)) {
                    had_work = true;
                }
            }
        }

        return had_work;
    }

    fn recordScanRequest(self: *Service, raw_json: []const u8) Error!bool {
        var parsed = std.json.parseFromSlice(ScanRequest, self.allocator, raw_json, .{
            .ignore_unknown_fields = true,
        }) catch |err| {
            logging.err()
                .stringSafe("event", "scan_request_ingest")
                .stringSafe("status", "error")
                .stringSafe("error", "InvalidScanRequestJson")
                .err(err)
                .log();
            return error.ScanIngestFailed;
        };
        defer parsed.deinit();

        const request = parsed.value;
        if (!streamNameIsConfigured(self.cfg.stream_names_csv, request.stream_name)) {
            logging.info()
                .stringSafe("event", "scan_request_ingest")
                .stringSafe("status", "ignored")
                .string("stream_name", request.stream_name)
                .log();
            return false;
        }

        const payload = resolvePayloadRef(self.allocator, self.io, self.cfg.sync_outbox_dir, request.payload_ref) catch |err| {
            logging.err()
                .stringSafe("event", "scan_request_ingest")
                .stringSafe("status", "error")
                .string("dedupe_key", request.dedupe_key)
                .stringSafe("error", "PayloadResolveFailed")
                .err(err)
                .log();
            return error.PayloadResolveFailed;
        };
        defer self.allocator.free(payload);

        const payload_sha256 = sha256Hex(payload);
        const payload_for_sql: ?[]const u8 = if (payload.len <= MAX_SCAN_PAYLOAD_SQL_BYTES) payload else null;
        try self.database.recordScanRequest(raw_json, payload_for_sql, &payload_sha256, self.cfg.stream_names_csv);
        logging.info()
            .stringSafe("event", "scan_request_ingest")
            .stringSafe("status", "recorded")
            .string("dedupe_key", request.dedupe_key)
            .string("stream_name", request.stream_name)
            .int("payload_bytes", payload.len)
            .boolean("payload_stored", payload_for_sql != null)
            .log();
        return true;
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
        var had_work = false;
        var pulls: usize = 0;
        while (pulls < 50) : (pulls += 1) {
            if (!(try self.resultConsumerHasBacklog())) break;

            const output = try self.pullResultMessage();
            defer if (output) |value| self.allocator.free(value);
            if (output == null) break;

            var iterator = std.mem.splitScalar(u8, output.?, '\n');
            while (iterator.next()) |raw_line| {
                const line = std.mem.trim(u8, raw_line, " \t\r\n");
                if (line.len == 0) continue;

                try self.database.processBatchResult(line);
                had_work = true;
            }
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

    fn handleBacklogSave(self: *Service) Error!bool {
        const msg = try self.pullWirelessMessage(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_save_consumer);
        defer if (msg) |m| self.allocator.free(m);
        if (msg) |payload| {
            self.database.saveBacklogEntry(payload) catch |err| {
                logging.err()
                    .stringSafe("event", "backlog_save")
                    .stringSafe("status", "error")
                    .err(err)
                    .log();
                return error.BacklogOperationFailed;
            };
            logging.info()
                .stringSafe("event", "backlog_save")
                .stringSafe("status", "ok")
                .log();
            return true;
        }
        return false;
    }

    fn handleBacklogList(self: *Service) Error!bool {
        const req = try self.pullWirelessMessage(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_list_consumer);
        defer if (req) |m| self.allocator.free(m);
        if (req != null) {
            const list = self.database.listPendingBacklog() catch |err| {
                logging.err()
                    .stringSafe("event", "backlog_list")
                    .stringSafe("status", "error")
                    .err(err)
                    .log();
                return error.BacklogOperationFailed;
            };
            defer if (list) |l| self.allocator.free(l);
            if (list) |payload| {
                try self.publish(self.cfg.wireless_backlog_list_reply_subject, payload, error.AlertPublishFailed);
                logging.info()
                    .stringSafe("event", "backlog_list")
                    .stringSafe("status", "ok")
                    .int("payload_bytes", payload.len)
                    .log();
            }
            return true;
        }
        return false;
    }

    fn handleBacklogSynced(self: *Service) Error!bool {
        const msg = try self.pullWirelessMessage(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_synced_consumer);
        defer if (msg) |m| self.allocator.free(m);
        if (msg) |payload| {
            var parsed = std.json.parseFromSlice(
                struct { dedupe_key: []const u8 },
                self.allocator,
                payload,
                .{ .ignore_unknown_fields = true },
            ) catch |err| {
                logging.err()
                    .stringSafe("event", "backlog_synced")
                    .stringSafe("status", "error")
                    .stringSafe("error", "InvalidJson")
                    .err(err)
                    .log();
                return error.BacklogOperationFailed;
            };
            defer parsed.deinit();
            self.database.markBacklogSynced(parsed.value.dedupe_key) catch |err| {
                logging.err()
                    .stringSafe("event", "backlog_synced")
                    .stringSafe("status", "error")
                    .err(err)
                    .log();
                return error.BacklogOperationFailed;
            };
            logging.info()
                .stringSafe("event", "backlog_synced")
                .stringSafe("status", "ok")
                .string("dedupe_key", parsed.value.dedupe_key)
                .log();
            return true;
        }
        return false;
    }

    fn handleBacklogPrune(self: *Service) Error!bool {
        const msg = try self.pullWirelessMessage(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_prune_consumer);
        defer if (msg) |m| self.allocator.free(m);
        if (msg != null) {
            const deleted = self.database.pruneBacklog() catch |err| {
                logging.err()
                    .stringSafe("event", "backlog_prune")
                    .stringSafe("status", "error")
                    .err(err)
                    .log();
                return error.BacklogOperationFailed;
            };
            defer if (deleted) |d| self.allocator.free(d);
            const count = if (deleted) |d| std.fmt.parseInt(i64, d, 10) catch 0 else 0;
            const reply = std.fmt.allocPrint(self.allocator, "{{\"pruned\":{d}}}", .{count}) catch {
                return error.BacklogOperationFailed;
            };
            defer self.allocator.free(reply);
            try self.publish(self.cfg.wireless_backlog_prune_reply_subject, reply, error.AlertPublishFailed);
            logging.info()
                .stringSafe("event", "backlog_prune")
                .stringSafe("status", "ok")
                .int("deleted_count", count)
                .log();
            return true;
        }
        return false;
    }

    fn handleMacLookup(self: *Service) Error!bool {
        const req = try self.pullWirelessMessage(self.cfg.wireless_mac_stream_name, self.cfg.wireless_mac_lookup_consumer);
        defer if (req) |m| self.allocator.free(m);
        if (req) |payload| {
            var parsed = std.json.parseFromSlice(
                struct { mac: []const u8 },
                self.allocator,
                payload,
                .{ .ignore_unknown_fields = true },
            ) catch |err| {
                logging.err()
                    .stringSafe("event", "mac_lookup")
                    .stringSafe("status", "error")
                    .stringSafe("error", "InvalidMacLookupJson")
                    .err(err)
                    .log();
                return error.MacLookupFailed;
            };
            defer parsed.deinit();
            const result = self.database.lookupDeviceByMac(parsed.value.mac) catch |err| {
                logging.err()
                    .stringSafe("event", "mac_lookup")
                    .stringSafe("status", "error")
                    .err(err)
                    .log();
                return error.MacLookupFailed;
            };
            defer if (result) |r| self.allocator.free(r);
            const reply = result orelse "null";
            try self.publish(self.cfg.wireless_mac_lookup_reply_subject, reply, error.AlertPublishFailed);
            logging.info()
                .stringSafe("event", "mac_lookup")
                .stringSafe("status", "ok")
                .string("mac", parsed.value.mac)
                .boolean("found", result != null)
                .log();
            return true;
        }
        return false;
    }

    fn handleNetworksAuthorized(self: *Service) Error!bool {
        const req = try self.pullWirelessMessage(self.cfg.wireless_networks_stream_name, self.cfg.wireless_networks_authorized_consumer);
        defer if (req) |m| self.allocator.free(m);
        if (req != null) {
            const list = self.database.listAuthorizedNetworks() catch |err| {
                logging.err()
                    .stringSafe("event", "networks_authorized")
                    .stringSafe("status", "error")
                    .err(err)
                    .log();
                return error.NetworksListFailed;
            };
            defer if (list) |l| self.allocator.free(l);
            if (list) |payload| {
                try self.publish(self.cfg.wireless_networks_authorized_reply_subject, payload, error.AlertPublishFailed);
                logging.info()
                    .stringSafe("event", "networks_authorized")
                    .stringSafe("status", "ok")
                    .int("payload_bytes", payload.len)
                    .log();
            }
            return true;
        }
        return false;
    }

    fn handleProbeFlush(self: *Service) Error!bool {
        const msg = try self.pullWirelessMessage(self.cfg.wireless_probe_stream_name, self.cfg.wireless_probe_flush_consumer);
        defer if (msg) |m| self.allocator.free(m);
        if (msg) |payload| {
            self.database.flushProbeBatch(payload) catch |err| {
                logging.err()
                    .stringSafe("event", "probe_flush")
                    .stringSafe("status", "error")
                    .err(err)
                    .log();
                return error.ProbeFlushFailed;
            };
            logging.info()
                .stringSafe("event", "probe_flush")
                .stringSafe("status", "ok")
                .int("payload_bytes", payload.len)
                .log();
            return true;
        }
        return false;
    }

    fn pullWirelessMessage(self: *Service, stream: []const u8, consumer: []const u8) Error!?[]u8 {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "consumer",
            "next",
            stream,
            consumer,
            "--count",
            "1",
            "--raw",
        };

        var result = command.exec(self.allocator, self.io, &argv) catch {
            return error.WirelessMessageFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            if (looksLikeNoMessage(result.stderr)) return null;
            command.logFailure("nats", result);
            return error.WirelessMessageFailed;
        }

        const output = command.trimmedOutput(result.stdout);
        if (output.len == 0) return null;
        return self.allocator.dupe(u8, output) catch error.WirelessMessageFailed;
    }

    fn wirelessConsumerHasBacklog(self: *Service, stream: []const u8, consumer: []const u8) Error!bool {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "consumer",
            "info",
            stream,
            consumer,
        };

        var result = command.exec(self.allocator, self.io, &argv) catch {
            return error.WirelessMessageFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure("nats", result);
            return error.WirelessMessageFailed;
        }

        return consumerInfoHasBacklog(result.stdout);
    }

    fn applySchema(self: *Service) Error!void {
        try self.database.applySchema();
    }

    fn checkDatabaseConnectivity(self: *Service) Error!void {
        try self.database.checkConnectivity();
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
        try self.checkNatsStream(self.cfg.wireless_backlog_stream_name);
        try self.checkNatsStream(self.cfg.wireless_mac_stream_name);
        try self.checkNatsStream(self.cfg.wireless_networks_stream_name);
        try self.checkNatsStream(self.cfg.wireless_probe_stream_name);
    }

    fn checkNatsConsumers(self: *Service) Error!void {
        try self.checkNatsConsumer(self.cfg.audit_stream_name, self.cfg.scan_consumer);
        try self.checkNatsConsumer(self.cfg.audit_stream_name, self.cfg.load_consumer);
        try self.checkNatsConsumer(self.cfg.result_stream_name, self.cfg.result_consumer);
        try self.checkNatsConsumer(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_save_consumer);
        try self.checkNatsConsumer(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_list_consumer);
        try self.checkNatsConsumer(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_synced_consumer);
        try self.checkNatsConsumer(self.cfg.wireless_backlog_stream_name, self.cfg.wireless_backlog_prune_consumer);
        try self.checkNatsConsumer(self.cfg.wireless_mac_stream_name, self.cfg.wireless_mac_lookup_consumer);
        try self.checkNatsConsumer(self.cfg.wireless_networks_stream_name, self.cfg.wireless_networks_authorized_consumer);
        try self.checkNatsConsumer(self.cfg.wireless_probe_stream_name, self.cfg.wireless_probe_flush_consumer);
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

    fn scanConsumerHasBacklog(self: *Service) Error!bool {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "consumer",
            "info",
            self.cfg.audit_stream_name,
            self.cfg.scan_consumer,
        };

        var result = command.exec(self.allocator, self.io, &argv) catch {
            return error.ScanFetchFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure("nats", result);
            return error.ScanFetchFailed;
        }

        return consumerInfoHasBacklog(result.stdout);
    }

    fn pullScanMessage(self: *Service) Error!?[]u8 {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "consumer",
            "next",
            self.cfg.audit_stream_name,
            self.cfg.scan_consumer,
            "--count",
            "1",
            "--raw",
        };

        var result = command.exec(self.allocator, self.io, &argv) catch {
            return error.ScanFetchFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            if (looksLikeNoMessage(result.stderr)) return null;
            command.logFailure("nats", result);
            return error.ScanFetchFailed;
        }

        const output = command.trimmedOutput(result.stdout);
        if (output.len == 0) return null;
        return self.allocator.dupe(u8, output) catch error.ScanFetchFailed;
    }

    fn resultConsumerHasBacklog(self: *Service) Error!bool {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "consumer",
            "info",
            self.cfg.result_stream_name,
            self.cfg.result_consumer,
        };

        var result = command.exec(self.allocator, self.io, &argv) catch {
            return error.ResultFetchFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure("nats", result);
            return error.ResultFetchFailed;
        }

        return consumerInfoHasBacklog(result.stdout);
    }

    fn pullResultMessage(self: *Service) Error!?[]u8 {
        const argv = [_][]const u8{
            "nats",
            "--server",
            self.cfg.sync_nats_url,
            "consumer",
            "next",
            self.cfg.result_stream_name,
            self.cfg.result_consumer,
            "--count",
            "1",
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

fn resolvePayloadRef(
    allocator: std.mem.Allocator,
    io: std.Io,
    outbox_dir: []const u8,
    payload_ref: []const u8,
) Error![]u8 {
    if (std.mem.startsWith(u8, payload_ref, INLINE_PAYLOAD_REF_PREFIX)) {
        const encoded = payload_ref[INLINE_PAYLOAD_REF_PREFIX.len..];
        const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) catch {
            return error.PayloadResolveFailed;
        };
        const decoded = allocator.alloc(u8, decoded_len) catch return error.PayloadResolveFailed;
        errdefer allocator.free(decoded);
        std.base64.url_safe_no_pad.Decoder.decode(decoded, encoded) catch {
            return error.PayloadResolveFailed;
        };
        return decoded;
    }

    if (std.mem.startsWith(u8, payload_ref, OUTBOX_PAYLOAD_REF_PREFIX)) {
        const locator = payload_ref[OUTBOX_PAYLOAD_REF_PREFIX.len..];
        if (!isSafeOutboxLocator(locator)) return error.PayloadResolveFailed;

        var dir = if (std.fs.path.isAbsolute(outbox_dir))
            std.Io.Dir.openDirAbsolute(io, outbox_dir, .{}) catch return error.PayloadResolveFailed
        else
            std.Io.Dir.openDir(.cwd(), io, outbox_dir, .{}) catch return error.PayloadResolveFailed;
        defer dir.close(io);

        return dir.readFileAlloc(io, locator, allocator, .limited(MAX_SCAN_PAYLOAD_BYTES)) catch {
            return error.PayloadResolveFailed;
        };
    }

    return error.PayloadResolveFailed;
}

fn isSafeOutboxLocator(locator: []const u8) bool {
    if (locator.len == 0) return false;
    if (std.fs.path.isAbsolute(locator)) return false;
    if (std.mem.indexOfScalar(u8, locator, '\\') != null) return false;

    var parts = std.mem.splitScalar(u8, locator, '/');
    while (parts.next()) |part| {
        if (part.len == 0) return false;
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn sha256Hex(payload: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
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

fn consumerInfoHasBacklog(stdout: []const u8) bool {
    return labeledCountIsPositive(stdout, "Pending Messages:") or
        labeledCountIsPositive(stdout, "Unprocessed Messages:");
}

fn streamNameIsConfigured(stream_names_csv: []const u8, stream_name: []const u8) bool {
    var iterator = std.mem.splitScalar(u8, stream_names_csv, ',');
    while (iterator.next()) |raw_name| {
        const configured = std.mem.trim(u8, raw_name, " \t\r\n");
        if (std.mem.eql(u8, configured, stream_name)) return true;
    }
    return false;
}

pub fn invalidOracleStreamName(stream_names_csv: []const u8, oracle_stream_names_csv: []const u8) ?[]const u8 {
    var iterator = std.mem.splitScalar(u8, oracle_stream_names_csv, ',');
    while (iterator.next()) |raw_name| {
        const stream_name = std.mem.trim(u8, raw_name, " \t\r\n");
        if (stream_name.len == 0) continue;
        if (!std.mem.eql(u8, stream_name, "proxy.events")) return stream_name;
        if (!streamNameIsConfigured(stream_names_csv, stream_name)) return stream_name;
    }
    return null;
}

fn labeledCountIsPositive(stdout: []const u8, label: []const u8) bool {
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (!std.mem.startsWith(u8, line, label)) continue;

        var digits_buffer: [32]u8 = undefined;
        var digits_len: usize = 0;
        var index: usize = label.len;
        while (index < line.len and std.ascii.isWhitespace(line[index])) : (index += 1) {}
        while (index < line.len) : (index += 1) {
            const byte = line[index];
            if (std.ascii.isDigit(byte)) {
                if (digits_len < digits_buffer.len) {
                    digits_buffer[digits_len] = byte;
                    digits_len += 1;
                }
                continue;
            }
            if (byte == ',') continue;
            break;
        }

        if (digits_len == 0) return false;
        const count = std.fmt.parseInt(u64, digits_buffer[0..digits_len], 10) catch return false;
        return count > 0;
    }

    return false;
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

test "streamNameIsConfigured matches trimmed CSV entries" {
    try std.testing.expect(streamNameIsConfigured("proxy.events, wireless.audit", "proxy.events"));
    try std.testing.expect(streamNameIsConfigured("proxy.events, wireless.audit", "wireless.audit"));
    try std.testing.expect(!streamNameIsConfigured("proxy.events, wireless.audit", "unknown"));
}

test "invalidOracleStreamName accepts proxy events only" {
    try std.testing.expect(invalidOracleStreamName("proxy.events, wireless.audit", "proxy.events") == null);
    try std.testing.expect(invalidOracleStreamName("proxy.events, wireless.audit", "") == null);
}

test "invalidOracleStreamName rejects wireless audit Oracle dispatch" {
    const invalid = invalidOracleStreamName("proxy.events, wireless.audit", "proxy.events, wireless.audit").?;
    try std.testing.expectEqualStrings("wireless.audit", invalid);
}

test "invalidOracleStreamName rejects Oracle stream outside configured streams" {
    const invalid = invalidOracleStreamName("wireless.audit", "proxy.events").?;
    try std.testing.expectEqualStrings("proxy.events", invalid);
}

test "resolvePayloadRef decodes inline JSON payloads" {
    const payload = try resolvePayloadRef(
        std.testing.allocator,
        std.testing.io,
        "/sync-outbox",
        "inline://json/eyJvayI6dHJ1ZX0",
    );
    defer std.testing.allocator.free(payload);

    try std.testing.expectEqualStrings("{\"ok\":true}", payload);
    try std.testing.expectEqualStrings(
        "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93",
        &sha256Hex(payload),
    );
}

test "resolvePayloadRef rejects outbox path traversal" {
    try std.testing.expectError(
        error.PayloadResolveFailed,
        resolvePayloadRef(std.testing.allocator, std.testing.io, "/sync-outbox", "outbox://../escape.json"),
    );
    try std.testing.expectError(
        error.PayloadResolveFailed,
        resolvePayloadRef(std.testing.allocator, std.testing.io, "/sync-outbox", "outbox:///escape.json"),
    );
}

test "resolvePayloadRef reads safe outbox locators" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "event.json",
        .data = "{\"type\":\"tunnel_open\",\"host\":\"example.com\"}",
    });
    const outbox_dir = try std.fmt.allocPrint(
        std.testing.allocator,
        ".zig-cache/tmp/{s}",
        .{tmp.sub_path},
    );
    defer std.testing.allocator.free(outbox_dir);

    const payload = try resolvePayloadRef(
        std.testing.allocator,
        std.testing.io,
        outbox_dir,
        "outbox://event.json",
    );
    defer std.testing.allocator.free(payload);

    try std.testing.expectEqualStrings("{\"type\":\"tunnel_open\",\"host\":\"example.com\"}", payload);
}
