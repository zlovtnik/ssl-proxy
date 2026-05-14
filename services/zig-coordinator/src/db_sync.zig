const std = @import("std");
const command = @import("command.zig");
const db = @import("db.zig");

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

pub fn recordScanRequest(
    client: *db.Client,
    request_json: []const u8,
    payload_json: ?[]const u8,
    payload_sha256: []const u8,
    stream_names_csv: []const u8,
) db.Error!void {
    const request_literal = try client.sqlLiteral(request_json);
    defer client.allocator.free(request_literal);
    const payload_literal = if (payload_json) |payload| try client.sqlLiteral(payload) else null;
    defer if (payload_literal) |literal| client.allocator.free(literal);
    const sha_literal = try client.sqlLiteral(payload_sha256);
    defer client.allocator.free(sha_literal);
    const normalized_stream_names = try client.normalizedCsv(stream_names_csv);
    defer client.allocator.free(normalized_stream_names);
    const stream_names_literal = try client.sqlLiteral(normalized_stream_names);
    defer client.allocator.free(stream_names_literal);
    const payload_expr = payload_literal orelse "null";
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.record_scan_request({s}::jsonb, {s}::jsonb, {s}, string_to_array({s}, ','))::text;",
        .{ request_literal, payload_expr, sha_literal, stream_names_literal },
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

    var exec_result = command.exec(client.allocator, client.io, argv.items) catch {
        return error.ScanRecordFailed;
    };
    defer exec_result.deinit(client.allocator);

    if (!command.isSuccess(exec_result)) {
        command.logFailure("psql", exec_result);
        return error.ScanRecordFailed;
    }
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

pub fn processBatchResult(client: *db.Client, result_json: []const u8) db.Error!void {
    const result_literal = try client.sqlLiteral(result_json);
    defer client.allocator.free(result_literal);
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.process_batch_result({s}::jsonb)::text;",
        .{result_literal},
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

    var exec_result = command.exec(client.allocator, client.io, argv.items) catch {
        return error.BatchResultFailed;
    };
    defer exec_result.deinit(client.allocator);

    if (!command.isSuccess(exec_result)) {
        command.logFailure("psql", exec_result);
        return error.BatchResultFailed;
    }
}
