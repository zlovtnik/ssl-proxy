const std = @import("std");
const command = @import("command.zig");

pub const Error = error{
    OutOfMemory,
    DatabaseCheckFailed,
    SchemaApplyFailed,
    CursorEnsureFailed,
    CursorLookupFailed,
    IngestProcessFailed,
    ScanRecordFailed,
    NextBatchFetchFailed,
    BatchDispatchRecoveryFailed,
    BatchDispatchMarkFailed,
    BatchDispatchReleaseFailed,
    ShadowAuditFailed,
    BatchResultFailed,
    BacklogOperationFailed,
    MacLookupFailed,
    NetworksListFailed,
    ProbeFlushFailed,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    database_url: []const u8,
    schema_file: []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        database_url: []const u8,
        schema_file: []const u8,
    ) Client {
        return .{
            .allocator = allocator,
            .io = io,
            .database_url = database_url,
            .schema_file = schema_file,
        };
    }

    pub fn applySchema(self: *Client) Error!void {
        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            self.schema_file,
        };
        var result = command.exec(self.allocator, self.io, &argv) catch {
            return error.SchemaApplyFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure("psql", result);
            return error.SchemaApplyFailed;
        }
    }

    pub fn checkConnectivity(self: *Client) Error!void {
        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            "select 1;",
        };
        const output = self.runScalar(&argv, "psql", error.DatabaseCheckFailed, false) catch |err| return err;
        defer if (output) |value| self.allocator.free(value);

        if (output == null or !std.mem.eql(u8, output.?, "1")) return error.DatabaseCheckFailed;
    }

    pub fn ensureCursor(self: *Client, stream_name: []const u8) Error![]u8 {
        const stream_literal = try self.sqlLiteral(stream_name);
        defer self.allocator.free(stream_literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.ensure_cursor({s})::text;",
            .{stream_literal},
        );
        defer self.allocator.free(query);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 8);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        });

        var result = command.exec(self.allocator, self.io, argv.items) catch {
            return error.CursorEnsureFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure("psql", result);
            return error.CursorEnsureFailed;
        }

        const output = command.trimmedOutput(result.stdout);
        if (output.len == 0) return error.CursorEnsureFailed;
        return self.allocator.dupe(u8, output) catch error.CursorEnsureFailed;
    }

    pub fn processIngestLedger(
        self: *Client,
        stream_names_csv: []const u8,
        oracle_stream_names_csv: []const u8,
        max_attempts: u32,
        backoff_secs: u32,
        ingest_batch_size: u32,
    ) Error!bool {
        const normalized_stream_names = try self.normalizedCsv(stream_names_csv);
        defer self.allocator.free(normalized_stream_names);
        const normalized_oracle_stream_names = try self.normalizedCsv(oracle_stream_names_csv);
        defer self.allocator.free(normalized_oracle_stream_names);
        const stream_names_literal = try self.sqlLiteral(normalized_stream_names);
        defer self.allocator.free(stream_names_literal);
        const oracle_stream_names_literal = try self.sqlLiteral(normalized_oracle_stream_names);
        defer self.allocator.free(oracle_stream_names_literal);
        const batch_size = @max(ingest_batch_size, 1);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.process_ingest_ledger(string_to_array({s}, ','), string_to_array({s}, ','), {d}::integer, {d}::integer, {d}::integer)::text;",
            .{ stream_names_literal, oracle_stream_names_literal, max_attempts, backoff_secs, batch_size },
        );
        defer self.allocator.free(query);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 8);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        });

        const output = self.runScalar(argv.items, "psql", error.IngestProcessFailed, false) catch |err| return err;
        defer if (output) |value| self.allocator.free(value);

        if (output) |value| {
            const count = std.fmt.parseInt(i64, value, 10) catch return error.IngestProcessFailed;
            return count > 0;
        }
        return false;
    }

    pub fn recordScanRequest(
        self: *Client,
        request_json: []const u8,
        payload_json: ?[]const u8,
        payload_sha256: []const u8,
        stream_names_csv: []const u8,
    ) Error!void {
        const request_literal = try self.sqlLiteral(request_json);
        defer self.allocator.free(request_literal);
        const payload_literal = if (payload_json) |payload| try self.sqlLiteral(payload) else null;
        defer if (payload_literal) |literal| self.allocator.free(literal);
        const sha_literal = try self.sqlLiteral(payload_sha256);
        defer self.allocator.free(sha_literal);
        const normalized_stream_names = try self.normalizedCsv(stream_names_csv);
        defer self.allocator.free(normalized_stream_names);
        const stream_names_literal = try self.sqlLiteral(normalized_stream_names);
        defer self.allocator.free(stream_names_literal);
        const payload_expr = payload_literal orelse "null";
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.record_scan_request({s}::jsonb, {s}::jsonb, {s}, string_to_array({s}, ','))::text;",
            .{ request_literal, payload_expr, sha_literal, stream_names_literal },
        );
        defer self.allocator.free(query);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 8);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        });

        var exec_result = command.exec(self.allocator, self.io, argv.items) catch {
            return error.ScanRecordFailed;
        };
        defer exec_result.deinit(self.allocator);

        if (!command.isSuccess(exec_result)) {
            command.logFailure("psql", exec_result);
            return error.ScanRecordFailed;
        }
    }

    pub fn getNextBatch(self: *Client, oracle_stream_names_csv: []const u8) Error!?[]u8 {
        const normalized_oracle_stream_names = try self.normalizedCsv(oracle_stream_names_csv);
        defer self.allocator.free(normalized_oracle_stream_names);
        const oracle_stream_names_literal = try self.sqlLiteral(normalized_oracle_stream_names);
        defer self.allocator.free(oracle_stream_names_literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.get_next_batch(string_to_array({s}, ','))::text;",
            .{oracle_stream_names_literal},
        );
        defer self.allocator.free(query);

        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        };
        return self.runScalar(&argv, "psql", error.NextBatchFetchFailed, false);
    }

    pub fn recoverStaleDispatchedBatches(
        self: *Client,
        oracle_stream_names_csv: []const u8,
        lease_seconds: u32,
        max_attempts: u32,
    ) Error!usize {
        const normalized_oracle_stream_names = try self.normalizedCsv(oracle_stream_names_csv);
        defer self.allocator.free(normalized_oracle_stream_names);
        const oracle_stream_names_literal = try self.sqlLiteral(normalized_oracle_stream_names);
        defer self.allocator.free(oracle_stream_names_literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.recover_stale_dispatched_batches(string_to_array({s}, ','), {d}::integer, {d}::integer)::text;",
            .{ oracle_stream_names_literal, lease_seconds, max_attempts },
        );
        defer self.allocator.free(query);

        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        };
        const output = self.runScalar(&argv, "psql", error.BatchDispatchRecoveryFailed, false) catch |err| return err;
        defer if (output) |value| self.allocator.free(value);

        if (output) |value| {
            return std.fmt.parseInt(usize, value, 10) catch error.BatchDispatchRecoveryFailed;
        }
        return 0;
    }

    pub fn markBatchDispatchFailed(
        self: *Client,
        load_json: []const u8,
        error_text: []const u8,
        max_attempts: u32,
    ) Error!?[]u8 {
        const load_literal = try self.sqlLiteral(load_json);
        defer self.allocator.free(load_literal);
        const error_literal = try self.sqlLiteral(error_text);
        defer self.allocator.free(error_literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.mark_batch_dispatch_failed({s}::jsonb, {s}, {d}::integer)::text;",
            .{ load_literal, error_literal, max_attempts },
        );
        defer self.allocator.free(query);

        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        };
        return self.runScalar(&argv, "psql", error.BatchDispatchMarkFailed, false);
    }

    pub fn releaseBatchDispatch(
        self: *Client,
        load_json: []const u8,
        error_text: []const u8,
    ) Error!?[]u8 {
        const load_literal = try self.sqlLiteral(load_json);
        defer self.allocator.free(load_literal);
        const error_literal = try self.sqlLiteral(error_text);
        defer self.allocator.free(error_literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.release_batch_dispatch({s}::jsonb, {s})::text;",
            .{ load_literal, error_literal },
        );
        defer self.allocator.free(query);

        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        };
        return self.runScalar(&argv, "psql", error.BatchDispatchReleaseFailed, false);
    }

    pub fn generateShadowAlerts(self: *Client) Error!?[]u8 {
        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            "select coordinator.generate_shadow_alerts()::text;",
        };
        return self.runScalar(&argv, "psql", error.ShadowAuditFailed, false);
    }

    pub fn processBatchResult(self: *Client, result_json: []const u8) Error!void {
        const result_literal = try self.sqlLiteral(result_json);
        defer self.allocator.free(result_literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.process_batch_result({s}::jsonb)::text;",
            .{result_literal},
        );
        defer self.allocator.free(query);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 8);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        });

        var exec_result = command.exec(self.allocator, self.io, argv.items) catch {
            return error.BatchResultFailed;
        };
        defer exec_result.deinit(self.allocator);

        if (!command.isSuccess(exec_result)) {
            command.logFailure("psql", exec_result);
            return error.BatchResultFailed;
        }
    }

    pub fn saveBacklogEntry(self: *Client, payload_json: []const u8) Error!void {
        const literal = try self.sqlLiteral(payload_json);
        defer self.allocator.free(literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.save_backlog_entry({s}::jsonb);",
            .{literal},
        );
        defer self.allocator.free(query);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 8);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        });

        var result = command.exec(self.allocator, self.io, argv.items) catch {
            return error.BacklogOperationFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure("psql", result);
            return error.BacklogOperationFailed;
        }
    }

    pub fn listPendingBacklog(self: *Client) Error!?[]u8 {
        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            "select coordinator.list_pending_backlog()::text;",
        };
        return self.runScalar(&argv, "psql", error.BacklogOperationFailed, false);
    }

    pub fn markBacklogSynced(self: *Client, dedupe_key: []const u8) Error!void {
        const literal = try self.sqlLiteral(dedupe_key);
        defer self.allocator.free(literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.mark_backlog_synced({s});",
            .{literal},
        );
        defer self.allocator.free(query);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 8);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        });

        var result = command.exec(self.allocator, self.io, argv.items) catch {
            return error.BacklogOperationFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure("psql", result);
            return error.BacklogOperationFailed;
        }
    }

    pub fn pruneBacklog(self: *Client) Error!?[]u8 {
        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            "select coordinator.prune_backlog()::text;",
        };
        return self.runScalar(&argv, "psql", error.BacklogOperationFailed, false);
    }

    pub fn lookupDeviceByMac(self: *Client, mac: []const u8) Error!?[]u8 {
        const literal = try self.sqlLiteral(mac);
        defer self.allocator.free(literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.lookup_device_by_mac({s})::text;",
            .{literal},
        );
        defer self.allocator.free(query);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 8);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        });

        return self.runScalar(argv.items, "psql", error.MacLookupFailed, false);
    }

    pub fn listAuthorizedNetworks(self: *Client) Error!?[]u8 {
        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            "select coordinator.list_authorized_networks()::text;",
        };
        return self.runScalar(&argv, "psql", error.NetworksListFailed, false);
    }

    pub fn flushProbeBatch(self: *Client, probes_json: []const u8) Error!void {
        const literal = try self.sqlLiteral(probes_json);
        defer self.allocator.free(literal);
        const query = try std.fmt.allocPrint(
            self.allocator,
            "select coordinator.flush_probe_batch({s}::jsonb);",
            .{literal},
        );
        defer self.allocator.free(query);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 8);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            query,
        });

        var result = command.exec(self.allocator, self.io, argv.items) catch {
            return error.ProbeFlushFailed;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure("psql", result);
            return error.ProbeFlushFailed;
        }
    }

    fn runScalar(
        self: *Client,
        argv: []const []const u8,
        command_name: []const u8,
        on_error: Error,
        log_output: bool,
    ) Error!?[]u8 {
        var result = command.exec(self.allocator, self.io, argv) catch {
            return on_error;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure(command_name, result);
            return on_error;
        }

        if (log_output) command.logOutput(command_name, result.stdout);
        const output = command.trimmedOutput(result.stdout);
        if (output.len == 0) return null;
        return self.allocator.dupe(u8, output) catch on_error;
    }

    fn sqlLiteral(self: *Client, value: []const u8) Error![]u8 {
        var literal = try std.ArrayList(u8).initCapacity(self.allocator, value.len + 2);
        defer literal.deinit(self.allocator);

        try literal.append(self.allocator, '\'');
        for (value) |byte| {
            if (byte == '\'') {
                try literal.appendSlice(self.allocator, "''");
            } else {
                try literal.append(self.allocator, byte);
            }
        }
        try literal.append(self.allocator, '\'');

        return literal.toOwnedSlice(self.allocator);
    }

    fn normalizedCsv(self: *Client, raw: []const u8) Error![]u8 {
        var normalized = try std.ArrayList(u8).initCapacity(self.allocator, raw.len);
        defer normalized.deinit(self.allocator);

        var iterator = std.mem.splitScalar(u8, raw, ',');
        var first = true;
        while (iterator.next()) |part| {
            const item = std.mem.trim(u8, part, " \t\r\n");
            if (item.len == 0) continue;
            if (!first) try normalized.append(self.allocator, ',');
            try normalized.appendSlice(self.allocator, item);
            first = false;
        }

        return normalized.toOwnedSlice(self.allocator);
    }
};
