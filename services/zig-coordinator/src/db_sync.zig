const std = @import("std");
const db = @import("db.zig");

const SQL_ARRAY_CHUNK_SIZE = 500;

pub const ScanRequestRecord = struct {
    request_json: []const u8,
    payload_json: ?[]const u8,
    payload_sha256: []const u8,
};

pub fn processIngestLedger(
    client: *db.Client,
    stream_names_csv: []const u8,
    oracle_stream_names_csv: []const u8,
    max_attempts: u32,
    backoff_secs: u32,
    ingest_batch_size: u32,
) db.Error!bool {
    const normalized_stream_names = try client.normalizedCsv(stream_names_csv);
    defer client.allocator.free(normalized_stream_names);
    const normalized_oracle_stream_names = try client.normalizedCsv(oracle_stream_names_csv);
    defer client.allocator.free(normalized_oracle_stream_names);
    const stream_names_literal = try client.sqlLiteral(normalized_stream_names);
    defer client.allocator.free(stream_names_literal);
    const oracle_stream_names_literal = try client.sqlLiteral(normalized_oracle_stream_names);
    defer client.allocator.free(oracle_stream_names_literal);
    const batch_size = @max(ingest_batch_size, 1);
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.process_ingest_ledger(string_to_array({s}, ','), string_to_array({s}, ','), {d}::integer, {d}::integer, {d}::integer)::text;",
        .{ stream_names_literal, oracle_stream_names_literal, max_attempts, backoff_secs, batch_size },
    );
    defer client.allocator.free(query);

    var argv = try std.ArrayList([]const u8).initCapacity(client.allocator, 8);
    defer argv.deinit(client.allocator);
    try argv.appendSlice(client.allocator, &.{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        query,
    });

    const output = client.runScalar(argv.items, "psql", error.IngestProcessFailed, false) catch |err| return err;
    defer if (output) |value| client.allocator.free(value);

    if (output) |value| {
        const count = std.fmt.parseInt(i64, value, 10) catch return error.IngestProcessFailed;
        return count > 0;
    }
    return false;
}

pub fn recordScanRequests(
    client: *db.Client,
    records: []const ScanRequestRecord,
    stream_names_csv: []const u8,
) db.Error!usize {
    if (records.len == 0) return 0;

    const normalized_stream_names = try client.normalizedCsv(stream_names_csv);
    defer client.allocator.free(normalized_stream_names);
    const stream_names_literal = try client.sqlLiteral(normalized_stream_names);
    defer client.allocator.free(stream_names_literal);

    var total_recorded: usize = 0;
    var start: usize = 0;
    while (start < records.len) {
        const end = @min(start + SQL_ARRAY_CHUNK_SIZE, records.len);
        const query = try buildRecordScanRequestsQuery(client, records[start..end], stream_names_literal);
        defer client.allocator.free(query);

        const output = client.runScalarSql(query, "psql", error.ScanRecordFailed, false) catch |err| return err;
        defer if (output) |value| client.allocator.free(value);

        if (output) |value| {
            total_recorded += std.fmt.parseInt(usize, value, 10) catch return error.ScanRecordFailed;
        }
        start = end;
    }

    return total_recorded;
}

pub fn recordScanRequest(
    client: *db.Client,
    request_json: []const u8,
    payload_json: ?[]const u8,
    payload_sha256: []const u8,
    stream_names_csv: []const u8,
) db.Error!void {
    _ = try recordScanRequests(client, &.{
        .{
            .request_json = request_json,
            .payload_json = payload_json,
            .payload_sha256 = payload_sha256,
        },
    }, stream_names_csv);
}

pub fn getNextBatch(client: *db.Client, oracle_stream_names_csv: []const u8) db.Error!?[]u8 {
    const normalized_oracle_stream_names = try client.normalizedCsv(oracle_stream_names_csv);
    defer client.allocator.free(normalized_oracle_stream_names);
    const oracle_stream_names_literal = try client.sqlLiteral(normalized_oracle_stream_names);
    defer client.allocator.free(oracle_stream_names_literal);
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.get_next_batch(string_to_array({s}, ','))::text;",
        .{oracle_stream_names_literal},
    );
    defer client.allocator.free(query);

    const argv = [_][]const u8{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        query,
    };
    return client.runScalar(&argv, "psql", error.NextBatchFetchFailed, false);
}

pub fn recoverStaleDispatchedBatches(
    client: *db.Client,
    oracle_stream_names_csv: []const u8,
    lease_seconds: u32,
    max_attempts: u32,
) db.Error!usize {
    const normalized_oracle_stream_names = try client.normalizedCsv(oracle_stream_names_csv);
    defer client.allocator.free(normalized_oracle_stream_names);
    const oracle_stream_names_literal = try client.sqlLiteral(normalized_oracle_stream_names);
    defer client.allocator.free(oracle_stream_names_literal);
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.recover_stale_dispatched_batches(string_to_array({s}, ','), {d}::integer, {d}::integer)::text;",
        .{ oracle_stream_names_literal, lease_seconds, max_attempts },
    );
    defer client.allocator.free(query);

    const argv = [_][]const u8{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        query,
    };
    const output = client.runScalar(&argv, "psql", error.BatchDispatchRecoveryFailed, false) catch |err| return err;
    defer if (output) |value| client.allocator.free(value);

    if (output) |value| {
        return std.fmt.parseInt(usize, value, 10) catch error.BatchDispatchRecoveryFailed;
    }
    return 0;
}

pub fn markBatchDispatchFailed(
    client: *db.Client,
    load_json: []const u8,
    error_text: []const u8,
    max_attempts: u32,
) db.Error!?[]u8 {
    const load_literal = try client.sqlLiteral(load_json);
    defer client.allocator.free(load_literal);
    const error_literal = try client.sqlLiteral(error_text);
    defer client.allocator.free(error_literal);
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.mark_batch_dispatch_failed({s}::jsonb, {s}, {d}::integer)::text;",
        .{ load_literal, error_literal, max_attempts },
    );
    defer client.allocator.free(query);

    const argv = [_][]const u8{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        query,
    };
    return client.runScalar(&argv, "psql", error.BatchDispatchMarkFailed, false);
}

pub fn releaseBatchDispatch(
    client: *db.Client,
    load_json: []const u8,
    error_text: []const u8,
) db.Error!?[]u8 {
    const load_literal = try client.sqlLiteral(load_json);
    defer client.allocator.free(load_literal);
    const error_literal = try client.sqlLiteral(error_text);
    defer client.allocator.free(error_literal);
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.release_batch_dispatch({s}::jsonb, {s})::text;",
        .{ load_literal, error_literal },
    );
    defer client.allocator.free(query);

    const argv = [_][]const u8{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        query,
    };
    return client.runScalar(&argv, "psql", error.BatchDispatchReleaseFailed, false);
}

pub fn generateShadowAlerts(client: *db.Client) db.Error!?[]u8 {
    const argv = [_][]const u8{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        "select coordinator.generate_shadow_alerts()::text;",
    };
    return client.runScalar(&argv, "psql", error.ShadowAuditFailed, false);
}

pub fn processBatchResults(client: *db.Client, result_jsons: []const []const u8) db.Error!usize {
    if (result_jsons.len == 0) return 0;

    var total_processed: usize = 0;
    var start: usize = 0;
    while (start < result_jsons.len) {
        const end = @min(start + SQL_ARRAY_CHUNK_SIZE, result_jsons.len);
        const query = try buildProcessBatchResultsQuery(client, result_jsons[start..end]);
        defer client.allocator.free(query);

        const output = client.runScalarSql(query, "psql", error.BatchResultFailed, false) catch |err| return err;
        defer if (output) |value| client.allocator.free(value);

        if (output) |value| {
            total_processed += std.fmt.parseInt(usize, value, 10) catch return error.BatchResultFailed;
        }
        start = end;
    }

    return total_processed;
}

pub fn processBatchResult(client: *db.Client, result_json: []const u8) db.Error!void {
    _ = try processBatchResults(client, &.{result_json});
}

fn buildRecordScanRequestsQuery(
    client: *db.Client,
    records: []const ScanRequestRecord,
    stream_names_literal: []const u8,
) db.Error![]u8 {
    var request_array = std.ArrayList(u8).empty;
    defer request_array.deinit(client.allocator);
    var payload_array = std.ArrayList(u8).empty;
    defer payload_array.deinit(client.allocator);
    var sha_array = std.ArrayList(u8).empty;
    defer sha_array.deinit(client.allocator);

    try appendSqlArrayPrefix(client.allocator, &request_array);
    try appendSqlArrayPrefix(client.allocator, &payload_array);
    try appendSqlArrayPrefix(client.allocator, &sha_array);

    for (records, 0..) |record, idx| {
        if (idx > 0) {
            try request_array.append(client.allocator, ',');
            try payload_array.append(client.allocator, ',');
            try sha_array.append(client.allocator, ',');
        }

        const request_literal = try client.sqlLiteral(record.request_json);
        defer client.allocator.free(request_literal);
        try request_array.appendSlice(client.allocator, request_literal);

        if (record.payload_json) |payload_json| {
            const payload_literal = try client.sqlLiteral(payload_json);
            defer client.allocator.free(payload_literal);
            try payload_array.appendSlice(client.allocator, payload_literal);
        } else {
            try payload_array.appendSlice(client.allocator, "null");
        }

        const sha_literal = try client.sqlLiteral(record.payload_sha256);
        defer client.allocator.free(sha_literal);
        try sha_array.appendSlice(client.allocator, sha_literal);
    }

    try request_array.appendSlice(client.allocator, "]::jsonb[]");
    try payload_array.appendSlice(client.allocator, "]::jsonb[]");
    try sha_array.appendSlice(client.allocator, "]::text[]");

    return std.fmt.allocPrint(
        client.allocator,
        "select coordinator.record_scan_request_batch({s}, {s}, {s}, string_to_array({s}, ','))::text;",
        .{ request_array.items, payload_array.items, sha_array.items, stream_names_literal },
    );
}

fn buildProcessBatchResultsQuery(client: *db.Client, result_jsons: []const []const u8) db.Error![]u8 {
    var result_array = std.ArrayList(u8).empty;
    defer result_array.deinit(client.allocator);

    try appendSqlArrayPrefix(client.allocator, &result_array);
    for (result_jsons, 0..) |result_json, idx| {
        if (idx > 0) try result_array.append(client.allocator, ',');
        const result_literal = try client.sqlLiteral(result_json);
        defer client.allocator.free(result_literal);
        try result_array.appendSlice(client.allocator, result_literal);
    }
    try result_array.appendSlice(client.allocator, "]::jsonb[]");

    return std.fmt.allocPrint(
        client.allocator,
        "select coordinator.process_batch_results({s})::text;",
        .{result_array.items},
    );
}

fn appendSqlArrayPrefix(allocator: std.mem.Allocator, array: *std.ArrayList(u8)) !void {
    try array.appendSlice(allocator, "array[");
}
