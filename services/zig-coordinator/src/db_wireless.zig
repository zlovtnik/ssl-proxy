const std = @import("std");
const command = @import("command.zig");
const db = @import("db.zig");

pub fn saveBacklogEntry(client: *db.Client, payload_json: []const u8) db.Error!void {
    try execStoredProc(client, "save_backlog_entry", payload_json, "::jsonb", error.BacklogOperationFailed);
}

pub fn listPendingBacklog(client: *db.Client) db.Error!?[]u8 {
    const argv = [_][]const u8{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        "select coordinator.list_pending_backlog()::text;",
    };
    return client.runScalar(&argv, "psql", error.BacklogOperationFailed, false);
}

pub fn markBacklogSynced(client: *db.Client, dedupe_key: []const u8) db.Error!void {
    try execStoredProc(client, "mark_backlog_synced", dedupe_key, "", error.BacklogOperationFailed);
}

pub fn pruneBacklog(client: *db.Client) db.Error!?[]u8 {
    const argv = [_][]const u8{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        "select coordinator.prune_backlog()::text;",
    };
    return client.runScalar(&argv, "psql", error.BacklogOperationFailed, false);
}

pub fn lookupDeviceByMac(client: *db.Client, mac: []const u8) db.Error!?[]u8 {
    const literal = try client.sqlLiteral(mac);
    defer client.allocator.free(literal);
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.lookup_device_by_mac({s})::text;",
        .{literal},
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

    return client.runScalar(argv.items, "psql", error.MacLookupFailed, false);
}

pub fn listAuthorizedNetworks(client: *db.Client) db.Error!?[]u8 {
    const argv = [_][]const u8{
        "psql",
        client.database_url,
        "-v",
        "ON_ERROR_STOP=1",
        "-qAt",
        "-c",
        "select coordinator.list_authorized_networks()::text;",
    };
    return client.runScalar(&argv, "psql", error.NetworksListFailed, false);
}

pub fn flushProbeBatch(client: *db.Client, probes_json: []const u8) db.Error!void {
    try execStoredProc(client, "flush_probe_batch", probes_json, "::jsonb", error.ProbeFlushFailed);
}

fn execStoredProc(
    client: *db.Client,
    proc_name: []const u8,
    arg_value: []const u8,
    arg_cast: []const u8,
    on_error: db.Error,
) db.Error!void {
    const literal = try client.sqlLiteral(arg_value);
    defer client.allocator.free(literal);
    const query = try std.fmt.allocPrint(
        client.allocator,
        "select coordinator.{s}({s}{s});",
        .{ proc_name, literal, arg_cast },
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

    var result = command.exec(client.allocator, client.io, argv.items) catch {
        return on_error;
    };
    defer result.deinit(client.allocator);

    if (!command.isSuccess(result)) {
        command.logFailure("psql", result);
        return on_error;
    }
}
