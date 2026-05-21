const std = @import("std");
const command = @import("command.zig");

const INLINE_SQL_ARG_LIMIT = 96 * 1024;

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

    pub fn runScalarSql(
        self: *Client,
        query: []const u8,
        command_name: []const u8,
        on_error: Error,
        log_output: bool,
    ) Error!?[]u8 {
        if (query.len <= INLINE_SQL_ARG_LIMIT) {
            const argv = [_][]const u8{
                "psql",
                self.database_url,
                "-v",
                "ON_ERROR_STOP=1",
                "-qAt",
                "-c",
                query,
            };
            return self.runScalar(&argv, command_name, on_error, log_output);
        }

        var random_bytes: [16]u8 = undefined;
        const seed: u64 = @truncate(@as(u96, @bitCast(std.Io.Timestamp.now(self.io, .awake).toNanoseconds())));
        var prng = std.Random.DefaultPrng.init(seed);
        prng.random().bytes(&random_bytes);
        const random_hex = std.fmt.bytesToHex(random_bytes, .lower);
        const sql_path = try std.fmt.allocPrint(
            self.allocator,
            "/tmp/zig-coordinator-query-{s}.sql",
            .{&random_hex},
        );
        defer self.allocator.free(sql_path);

        var atomic_file = std.Io.Dir.cwd().createFileAtomic(self.io, sql_path, .{
            .replace = true,
            .permissions = .fromMode(0o600),
        }) catch return on_error;
        defer atomic_file.deinit(self.io);

        atomic_file.file.writeStreamingAll(self.io, query) catch return on_error;
        atomic_file.replace(self.io) catch return on_error;
        defer std.Io.Dir.deleteFile(.cwd(), self.io, sql_path) catch {};

        const argv = [_][]const u8{
            "psql",
            self.database_url,
            "-v",
            "ON_ERROR_STOP=1",
            "-qAt",
            "-f",
            sql_path,
        };
        return self.runScalar(&argv, command_name, on_error, log_output);
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

    pub fn runScalar(
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

    pub fn sqlLiteral(self: *Client, value: []const u8) Error![]u8 {
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

    pub fn normalizedCsv(self: *Client, raw: []const u8) Error![]u8 {
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
