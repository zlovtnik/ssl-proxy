const std = @import("std");
const config = @import("config.zig");
const db = @import("db.zig");
const db_sync = @import("db_sync.zig");
const logging = @import("logging.zig");
const redpanda = @import("redpanda.zig");
const service_redpanda = @import("service_redpanda.zig");
const topic_manifest = @import("topic_manifest.zig");

const SHADOW_ALERT_TOPIC = "audit.threat.shadow_device";
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

const DispatchPayload = struct {
    job_id: []const u8 = "",
    batch_id: []const u8,
    stream_name: []const u8 = "",
    attempt: i64 = 0,
};

pub fn drainScanRequests(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    var had_work = false;
    const batch = try service_redpanda.pullScanBatch(allocator, io, cfg, cfg.scan_fetch_count);
    if (batch.items.len == 0) return false;
    defer service_redpanda.freeBatch(allocator, batch);

    for (batch.items) |raw_line| {
        if (try recordScanRequest(allocator, io, cfg, database, raw_line)) had_work = true;
    }
    return had_work;
}

pub fn dispatchNextBatch(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    var had_work = false;
    var dispatched: usize = 0;
    const dispatch_limit: usize = @max(@as(usize, @intCast(cfg.dispatch_batch_size)), 1);
    while (dispatched < dispatch_limit) {
        const payload = try db_sync.getNextBatch(database, cfg.oracle_stream_names_csv);
        defer if (payload) |value| allocator.free(value);

        if (payload) |value| {
            var parsed_payload = std.json.parseFromSlice(DispatchPayload, allocator, value, .{ .ignore_unknown_fields = true }) catch null;
            defer if (parsed_payload) |*parsed| parsed.deinit();
            logDispatch("selected", value, parsed_payload);

            service_redpanda.publishWithMode(allocator, io, cfg, cfg.load_topic, value, .redpanda_ack, error.BatchDispatchFailed) catch |err| {
                var error_buffer: [128]u8 = undefined;
                const error_text = dispatchPublishErrorText(&error_buffer, err);
                const summary = db_sync.markBatchDispatchFailed(database, value, error_text, cfg.batch_max_attempts) catch |mark_err| {
                    logging.err().stringSafe("event", "batch_dispatch").stringSafe("status", "mark_failed_error").err(mark_err).log();
                    return err;
                };
                defer if (summary) |summary_json| allocator.free(summary_json);
                logDispatchFailure(summary, err);
                return err;
            };

            logDispatch("published", value, parsed_payload);
            dispatched += 1;
            had_work = true;
        } else {
            break;
        }
    }
    return had_work;
}

pub fn recoverStaleDispatchedBatches(cfg: config.Config, database: *db.Client) !bool {
    const recovered = try db_sync.recoverStaleDispatchedBatches(
        database,
        cfg.oracle_stream_names_csv,
        cfg.batch_dispatch_lease_seconds,
        cfg.batch_max_attempts,
    );
    if (recovered == 0) return false;

    logging.info()
        .stringSafe("event", "stale_batch_dispatch_recovery")
        .stringSafe("status", "recovered")
        .int("batch_count", recovered)
        .int("lease_seconds", cfg.batch_dispatch_lease_seconds)
        .int("max_attempts", cfg.batch_max_attempts)
        .log();
    return true;
}

pub fn handleResults(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    var had_work = false;
    const batch = try service_redpanda.pullResultBatch(allocator, io, cfg, cfg.result_fetch_count);
    if (batch.items.len == 0) return false;
    defer service_redpanda.freeBatch(allocator, batch);

    for (batch.items) |raw_line| {
        try db_sync.processBatchResult(database, raw_line);
        had_work = true;
    }
    return had_work;
}

pub fn runShadowAudit(
    allocator: std.mem.Allocator,
    io: std.Io,
    cfg: config.Config,
    database: *db.Client,
    last_shadow_audit_ts: *?std.Io.Timestamp,
    interval_ms: i64,
) !bool {
    const now = std.Io.Timestamp.now(io, .awake);
    if (last_shadow_audit_ts.*) |last_run| {
        if (last_run.durationTo(now).toMilliseconds() < interval_ms) return false;
    }

    const output = try db_sync.generateShadowAlerts(database);
    defer if (output) |value| allocator.free(value);

    last_shadow_audit_ts.* = now;
    if (output == null) return false;

    var had_work = false;
    var iterator = std.mem.splitScalar(u8, output.?, '\n');
    while (iterator.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0) continue;
        try service_redpanda.publish(allocator, io, cfg, SHADOW_ALERT_TOPIC, line, error.AlertPublishFailed);
        had_work = true;
    }
    return had_work;
}

fn recordScanRequest(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client, raw_json: []const u8) !bool {
    var parsed = std.json.parseFromSlice(ScanRequest, allocator, raw_json, .{ .ignore_unknown_fields = true }) catch |err| {
        logging.err().stringSafe("event", "scan_request_ingest").stringSafe("status", "error").stringSafe("error", "InvalidScanRequestJson").err(err).log();
        return error.ScanIngestFailed;
    };
    defer parsed.deinit();

    const request = parsed.value;
    if (!topic_manifest.streamNameIsConfigured(cfg.stream_names_csv, request.stream_name)) {
        logging.info().stringSafe("event", "scan_request_ingest").stringSafe("status", "ignored").string("stream_name", request.stream_name).log();
        return false;
    }

    const payload = resolvePayloadRef(allocator, io, cfg.sync_outbox_dir, request.payload_ref) catch |err| {
        logging.err().stringSafe("event", "scan_request_ingest").stringSafe("status", "error").string("dedupe_key", request.dedupe_key).stringSafe("error", "PayloadResolveFailed").err(err).log();
        return error.PayloadResolveFailed;
    };
    defer allocator.free(payload);

    const payload_sha256 = sha256Hex(payload);
    const payload_for_sql: ?[]const u8 = if (payload.len <= MAX_SCAN_PAYLOAD_SQL_BYTES) payload else null;
    try db_sync.recordScanRequest(database, raw_json, payload_for_sql, &payload_sha256, cfg.stream_names_csv);
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

fn resolvePayloadRef(allocator: std.mem.Allocator, io: std.Io, outbox_dir: []const u8, payload_ref: []const u8) ![]u8 {
    if (std.mem.startsWith(u8, payload_ref, INLINE_PAYLOAD_REF_PREFIX)) {
        const encoded = payload_ref[INLINE_PAYLOAD_REF_PREFIX.len..];
        const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) catch return error.PayloadResolveFailed;
        const decoded = allocator.alloc(u8, decoded_len) catch return error.PayloadResolveFailed;
        errdefer allocator.free(decoded);
        std.base64.url_safe_no_pad.Decoder.decode(decoded, encoded) catch return error.PayloadResolveFailed;
        validateJsonPayload(allocator, decoded) catch return error.PayloadResolveFailed;
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
        const payload = dir.readFileAlloc(io, locator, allocator, .limited(MAX_SCAN_PAYLOAD_BYTES)) catch return error.PayloadResolveFailed;
        errdefer allocator.free(payload);
        validateJsonPayload(allocator, payload) catch return error.PayloadResolveFailed;
        return payload;
    }

    return error.PayloadResolveFailed;
}

fn validateJsonPayload(allocator: std.mem.Allocator, payload: []const u8) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return error.PayloadResolveFailed;
    defer parsed.deinit();
}

fn isSafeOutboxLocator(locator: []const u8) bool {
    if (locator.len == 0 or std.fs.path.isAbsolute(locator)) return false;
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

fn dispatchPublishErrorText(buffer: *[128]u8, err: anyerror) []const u8 {
    return std.fmt.bufPrint(buffer, "sync.oracle.load publish failed: {s}", .{@errorName(err)}) catch "sync.oracle.load publish failed";
}

fn logDispatch(comptime status: []const u8, value: []const u8, parsed_payload: ?std.json.Parsed(DispatchPayload)) void {
    if (parsed_payload) |parsed| {
        logging.info().stringSafe("event", "batch_dispatch").stringSafe("status", status).string("batch_id", parsed.value.batch_id).string("job_id", parsed.value.job_id).string("stream_name", parsed.value.stream_name).int("attempt", parsed.value.attempt).log();
    } else {
        logging.info().stringSafe("event", "batch_dispatch").stringSafe("status", status).int("payload_bytes", value.len).log();
    }
}

fn logDispatchFailure(summary: ?[]u8, err: anyerror) void {
    var event = logging.err().stringSafe("event", "batch_dispatch").stringSafe("status", "publish_failed_requeued").err(err);
    if (summary) |summary_json| event = event.string("summary", summary_json);
    event.log();
}

test "resolvePayloadRef decodes inline JSON payloads" {
    const payload = try resolvePayloadRef(std.testing.allocator, std.testing.io, "/sync-outbox", "inline://json/eyJvayI6dHJ1ZX0");
    defer std.testing.allocator.free(payload);
    try std.testing.expectEqualStrings("{\"ok\":true}", payload);
    try std.testing.expectEqualStrings("4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93", &sha256Hex(payload));
}

test "resolvePayloadRef rejects inline non-JSON payloads" {
    try std.testing.expectError(
        error.PayloadResolveFailed,
        resolvePayloadRef(std.testing.allocator, std.testing.io, "/sync-outbox", "inline://json/bm90IGpzb24"),
    );
}

test "resolvePayloadRef rejects outbox non-JSON payloads" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "bad.json", .data = "not json" });

    const outbox_dir = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path[0..]});
    defer std.testing.allocator.free(outbox_dir);

    try std.testing.expectError(
        error.PayloadResolveFailed,
        resolvePayloadRef(std.testing.allocator, std.testing.io, outbox_dir, "outbox://bad.json"),
    );
}

test "isSafeOutboxLocator rejects traversal" {
    try std.testing.expect(isSafeOutboxLocator("aa/bb/payload.json"));
    try std.testing.expect(!isSafeOutboxLocator("../payload.json"));
    try std.testing.expect(!isSafeOutboxLocator("/tmp/payload.json"));
    try std.testing.expect(!isSafeOutboxLocator("aa//payload.json"));
}

test "dispatch publish error text preserves publish phase error" {
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings("sync.oracle.load publish failed: PublishAckFailed", dispatchPublishErrorText(&buffer, error.PublishAckFailed));
}
