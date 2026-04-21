const std = @import("std");
const config = @import("config.zig");
const scheduler = @import("scheduler.zig");

const HealthcheckError = error{
    MissingDatabaseUrl,
    MissingNatsUrl,
    SchemaApplyFailed,
    NatsCheckFailed,
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

    if (std.mem.eql(u8, mode, "healthcheck")) {
        try healthcheck(gpa, init.io, cfg);
        return;
    }

    if (!std.mem.eql(u8, mode, "run")) {
        std.debug.print("usage: zig-coordinator <run|healthcheck>\n", .{});
        return error.InvalidArgument;
    }

    try healthcheck(gpa, init.io, cfg);
    try ensureCursors(&coordinator, cfg.stream_names_csv);
    const cursor = coordinator.loadCursor(cfg.stream_name) orelse return HealthcheckError.CursorNotFound;

    std.debug.print(
        "zig coordinator ready primary_stream={s} configured_streams={s} cursor={s} subjects={s},{s},{s}\n",
        .{ cfg.stream_name, cfg.stream_names_csv, cursor.cursor_value, cfg.scan_subject, cfg.load_subject, cfg.result_subject },
    );

    while (true) {
        try std.Io.sleep(init.io, std.Io.Duration.fromSeconds(60), .awake);
    }
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
    if (cfg.database_url.len == 0) return HealthcheckError.MissingDatabaseUrl;
    if (cfg.sync_nats_url.len == 0) return HealthcheckError.MissingNatsUrl;

    try applySchema(gpa, io, cfg.database_url, cfg.sync_schema_file);
    try checkNats(gpa, io, cfg.sync_nats_url);
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
    const separator = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return HealthcheckError.InvalidNatsUrl;
    const host = authority[0..separator];
    const port = authority[separator + 1 ..];
    if (host.len == 0 or port.len == 0) return HealthcheckError.InvalidNatsUrl;

    const argv = [_][]const u8{
        "nc",
        "-z",
        host,
        port,
    };
    try runCommand(gpa, io, &argv, HealthcheckError.NatsCheckFailed);
}

fn parseNatsAuthority(gpa: std.mem.Allocator, nats_url: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, nats_url, " \t\r\n");
    const no_scheme = if (std.mem.startsWith(u8, trimmed, "nats://")) trimmed["nats://".len..] else trimmed;
    var iterator = std.mem.splitScalar(u8, no_scheme, '/');
    const authority = iterator.first();
    if (authority.len == 0) return HealthcheckError.InvalidNatsUrl;
    if (std.mem.lastIndexOfScalar(u8, authority, ':') != null) return gpa.dupe(u8, authority);

    return try std.fmt.allocPrint(gpa, "{s}:4222", .{authority});
}

fn runCommand(
    gpa: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    on_error: anyerror,
) !void {
    const result = std.process.run(gpa, io, .{
        .argv = argv,
        .expand_arg0 = .expand,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch |err| {
        std.debug.print("failed to spawn {s}: {}\n", .{ argv[0], err });
        return on_error;
    };
    defer {
        gpa.free(result.stdout);
        gpa.free(result.stderr);
    }

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("{s} failed: {s}\n", .{ argv[0], result.stderr });
                return on_error;
            }
        },
        else => {
            std.debug.print("{s} terminated unexpectedly\n", .{argv[0]});
            return on_error;
        },
    }
}
