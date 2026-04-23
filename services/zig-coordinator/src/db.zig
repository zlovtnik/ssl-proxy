const std = @import("std");
const command = @import("command.zig");

pub const Error = error{
    OutOfMemory,
    SchemaApplyFailed,
    CursorEnsureFailed,
    CursorLookupFailed,
    IngestProcessFailed,
    NextBatchFetchFailed,
    ShadowAuditFailed,
    BatchResultFailed,
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

    pub fn ensureCursor(self: *Client, stream_name: []const u8) Error![]u8 {
        const stream_arg = try std.fmt.allocPrint(self.allocator, "stream_name={s}", .{stream_name});
        defer self.allocator.free(stream_arg);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 10);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-v",
            stream_arg,
            "-c",
            "select coordinator.ensure_cursor(:'stream_name')::text;",
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
        max_attempts: u32,
        backoff_secs: u32,
    ) Error!bool {
        const stream_names_arg = try std.fmt.allocPrint(self.allocator, "stream_names_csv={s}", .{stream_names_csv});
        defer self.allocator.free(stream_names_arg);
        const attempts_arg = try std.fmt.allocPrint(self.allocator, "max_attempts={d}", .{max_attempts});
        defer self.allocator.free(attempts_arg);
        const backoff_arg = try std.fmt.allocPrint(self.allocator, "backoff_secs={d}", .{backoff_secs});
        defer self.allocator.free(backoff_arg);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 14);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-v",
            stream_names_arg,
            "-v",
            attempts_arg,
            "-v",
            backoff_arg,
            "-c",
            "select coordinator.process_ingest_ledger(string_to_array(:'stream_names_csv', ','), :'max_attempts'::integer, :'backoff_secs'::integer)::text;",
        });

        const output = self.runScalar(argv.items, "psql", error.IngestProcessFailed) catch |err| return err;
        defer if (output) |value| self.allocator.free(value);

        if (output) |value| {
            const count = std.fmt.parseInt(i64, value, 10) catch return error.IngestProcessFailed;
            return count > 0;
        }
        return false;
    }

    pub fn getNextBatch(self: *Client) Error!?[]u8 {
        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-c",
            "select coordinator.get_next_batch()::text;",
        };
        return self.runScalar(&argv, "psql", error.NextBatchFetchFailed);
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
        return self.runScalar(&argv, "psql", error.ShadowAuditFailed);
    }

    pub fn processBatchResult(self: *Client, result_json: []const u8) Error!void {
        const result_arg = try std.fmt.allocPrint(self.allocator, "result_json={s}", .{result_json});
        defer self.allocator.free(result_arg);

        var argv = try std.ArrayList([]const u8).initCapacity(self.allocator, 10);
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-v",
            result_arg,
            "-c",
            "select coordinator.process_batch_result(:'result_json'::jsonb)::text;",
        });

        var exec_result = command.exec(self.allocator, self.io, argv.items) catch {
            return error.BatchResultFailed;
        };
        defer exec_result.deinit(self.allocator);

        if (!command.isSuccess(exec_result)) {
            command.logFailure("psql", exec_result);
            return error.BatchResultFailed;
        }

        command.logOutput("psql", exec_result.stdout);
    }

    fn runScalar(
        self: *Client,
        argv: []const []const u8,
        command_name: []const u8,
        on_error: Error,
    ) Error!?[]u8 {
        var result = command.exec(self.allocator, self.io, argv) catch {
            return on_error;
        };
        defer result.deinit(self.allocator);

        if (!command.isSuccess(result)) {
            command.logFailure(command_name, result);
            return on_error;
        }

        command.logOutput(command_name, result.stdout);
        const output = command.trimmedOutput(result.stdout);
        if (output.len == 0) return null;
        return self.allocator.dupe(u8, output) catch on_error;
    }
};
