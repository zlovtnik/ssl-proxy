const std = @import("std");
const config = @import("config.zig");
const db = @import("db.zig");
const db_wireless = @import("db_wireless.zig");
const logging = @import("logging.zig");
const service_redpanda = @import("service_redpanda.zig");

const ReplyRequest = struct {
    operation: []const u8,
    reply_topic: ?[]const u8 = null,
};

pub fn run(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    var had_work = false;
    if (try service_redpanda.wirelessConsumerHasBacklog(allocator, io, cfg, cfg.wireless_backlog_stream_name, cfg.wireless_backlog_save_consumer)) had_work = (try handleBacklogSave(allocator, io, cfg, database)) or had_work;
    if (try service_redpanda.wirelessConsumerHasBacklog(allocator, io, cfg, cfg.wireless_backlog_stream_name, cfg.wireless_backlog_list_consumer)) had_work = (try handleBacklogList(allocator, io, cfg, database)) or had_work;
    if (try service_redpanda.wirelessConsumerHasBacklog(allocator, io, cfg, cfg.wireless_backlog_stream_name, cfg.wireless_backlog_synced_consumer)) had_work = (try handleBacklogSynced(allocator, io, cfg, database)) or had_work;
    if (try service_redpanda.wirelessConsumerHasBacklog(allocator, io, cfg, cfg.wireless_backlog_stream_name, cfg.wireless_backlog_prune_consumer)) had_work = (try handleBacklogPrune(allocator, io, cfg, database)) or had_work;
    if (try service_redpanda.wirelessConsumerHasBacklog(allocator, io, cfg, cfg.wireless_mac_stream_name, cfg.wireless_mac_lookup_consumer)) had_work = (try handleMacLookup(allocator, io, cfg, database)) or had_work;
    if (try service_redpanda.wirelessConsumerHasBacklog(allocator, io, cfg, cfg.wireless_networks_stream_name, cfg.wireless_networks_authorized_consumer)) had_work = (try handleNetworksAuthorized(allocator, io, cfg, database)) or had_work;
    if (try service_redpanda.wirelessConsumerHasBacklog(allocator, io, cfg, cfg.wireless_probe_stream_name, cfg.wireless_probe_flush_consumer)) had_work = (try handleProbeFlush(allocator, io, cfg, database)) or had_work;
    return had_work;
}

fn handleBacklogSave(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    const msg = try service_redpanda.pullWirelessMessage(allocator, io, cfg, cfg.wireless_backlog_stream_name, cfg.wireless_backlog_save_consumer);
    defer if (msg) |m| allocator.free(m);
    if (msg) |payload| {
        db_wireless.saveBacklogEntry(database, payload) catch |err| {
            logging.err().stringSafe("event", "backlog_save").stringSafe("status", "error").err(err).log();
            return error.BacklogOperationFailed;
        };
        logging.info().stringSafe("event", "backlog_save").stringSafe("status", "ok").log();
        return true;
    }
    return false;
}

fn handleBacklogList(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    const req = try service_redpanda.pullWirelessMessage(allocator, io, cfg, cfg.wireless_backlog_stream_name, cfg.wireless_backlog_list_consumer);
    defer if (req) |m| allocator.free(m);
    if (req) |request_payload| {
        var parsed_request = parseReplyRequest(allocator, request_payload);
        defer if (parsed_request) |*parsed| parsed.deinit();
        const reply_topic = if (parsed_request) |parsed| parsed.value.reply_topic orelse cfg.wireless_backlog_list_reply_topic else cfg.wireless_backlog_list_reply_topic;
        const list = db_wireless.listPendingBacklog(database) catch |err| {
            logging.err().stringSafe("event", "backlog_list").stringSafe("status", "error").err(err).log();
            return error.BacklogOperationFailed;
        };
        defer if (list) |l| allocator.free(l);
        if (list) |payload| {
            try service_redpanda.publish(allocator, io, cfg, reply_topic, payload, error.AlertPublishFailed);
            logging.info().stringSafe("event", "backlog_list").stringSafe("status", "ok").string("reply_topic", reply_topic).int("payload_bytes", payload.len).log();
        }
        return true;
    }
    return false;
}

fn handleBacklogSynced(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    const msg = try service_redpanda.pullWirelessMessage(allocator, io, cfg, cfg.wireless_backlog_stream_name, cfg.wireless_backlog_synced_consumer);
    defer if (msg) |m| allocator.free(m);
    if (msg) |payload| {
        var parsed = std.json.parseFromSlice(struct { dedupe_key: []const u8 }, allocator, payload, .{ .ignore_unknown_fields = true }) catch |err| {
            logging.err().stringSafe("event", "backlog_synced").stringSafe("status", "error").stringSafe("error", "InvalidJson").err(err).log();
            return error.BacklogOperationFailed;
        };
        defer parsed.deinit();
        db_wireless.markBacklogSynced(database, parsed.value.dedupe_key) catch |err| {
            logging.err().stringSafe("event", "backlog_synced").stringSafe("status", "error").err(err).log();
            return error.BacklogOperationFailed;
        };
        logging.info().stringSafe("event", "backlog_synced").stringSafe("status", "ok").string("dedupe_key", parsed.value.dedupe_key).log();
        return true;
    }
    return false;
}

fn handleBacklogPrune(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    const msg = try service_redpanda.pullWirelessMessage(allocator, io, cfg, cfg.wireless_backlog_stream_name, cfg.wireless_backlog_prune_consumer);
    defer if (msg) |m| allocator.free(m);
    if (msg) |request_payload| {
        var parsed_request = parseReplyRequest(allocator, request_payload);
        defer if (parsed_request) |*parsed| parsed.deinit();
        const reply_topic = if (parsed_request) |parsed| parsed.value.reply_topic orelse cfg.wireless_backlog_prune_reply_topic else cfg.wireless_backlog_prune_reply_topic;
        const deleted = db_wireless.pruneBacklog(database) catch |err| {
            logging.err().stringSafe("event", "backlog_prune").stringSafe("status", "error").err(err).log();
            return error.BacklogOperationFailed;
        };
        defer if (deleted) |d| allocator.free(d);
        const count = if (deleted) |d| std.fmt.parseInt(i64, d, 10) catch 0 else 0;
        const reply = std.fmt.allocPrint(allocator, "{{\"pruned\":{d}}}", .{count}) catch return error.BacklogOperationFailed;
        defer allocator.free(reply);
        try service_redpanda.publish(allocator, io, cfg, reply_topic, reply, error.AlertPublishFailed);
        logging.info().stringSafe("event", "backlog_prune").stringSafe("status", "ok").string("reply_topic", reply_topic).int("deleted_count", count).log();
        return true;
    }
    return false;
}

fn handleMacLookup(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    const req = try service_redpanda.pullWirelessMessage(allocator, io, cfg, cfg.wireless_mac_stream_name, cfg.wireless_mac_lookup_consumer);
    defer if (req) |m| allocator.free(m);
    if (req) |payload| {
        var parsed = std.json.parseFromSlice(struct { mac: []const u8, reply_topic: ?[]const u8 = null }, allocator, payload, .{ .ignore_unknown_fields = true }) catch |err| {
            logging.err().stringSafe("event", "mac_lookup").stringSafe("status", "error").stringSafe("error", "InvalidMacLookupJson").err(err).log();
            return error.MacLookupFailed;
        };
        defer parsed.deinit();
        const result = db_wireless.lookupDeviceByMac(database, parsed.value.mac) catch |err| {
            logging.err().stringSafe("event", "mac_lookup").stringSafe("status", "error").err(err).log();
            return error.MacLookupFailed;
        };
        defer if (result) |r| allocator.free(r);
        const reply = result orelse "null";
        const reply_topic = parsed.value.reply_topic orelse cfg.wireless_mac_lookup_reply_topic;
        try service_redpanda.publish(allocator, io, cfg, reply_topic, reply, error.AlertPublishFailed);
        logging.info().stringSafe("event", "mac_lookup").stringSafe("status", "ok").string("mac", parsed.value.mac).string("reply_topic", reply_topic).boolean("found", result != null).log();
        return true;
    }
    return false;
}

fn handleNetworksAuthorized(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    const req = try service_redpanda.pullWirelessMessage(allocator, io, cfg, cfg.wireless_networks_stream_name, cfg.wireless_networks_authorized_consumer);
    defer if (req) |m| allocator.free(m);
    if (req) |request_payload| {
        const start_ts = std.Io.Timestamp.now(io, .awake);
        var parsed_request = parseReplyRequest(allocator, request_payload);
        defer if (parsed_request) |*parsed| parsed.deinit();
        const reply_topic = if (parsed_request) |parsed| parsed.value.reply_topic orelse cfg.wireless_networks_authorized_reply_topic else cfg.wireless_networks_authorized_reply_topic;
        logging.info().stringSafe("event", "networks_authorized_request").stringSafe("status", "received").string("reply_topic", reply_topic).log();
        const list = db_wireless.listAuthorizedNetworks(database) catch |err| {
            logging.err().stringSafe("event", "networks_authorized").stringSafe("status", "error").string("reply_topic", reply_topic).int("duration_ms", elapsedMs(start_ts, io)).err(err).log();
            return error.NetworksListFailed;
        };
        defer if (list) |l| allocator.free(l);
        if (list) |payload| {
            try service_redpanda.publish(allocator, io, cfg, reply_topic, payload, error.AlertPublishFailed);
            logging.info().stringSafe("event", "networks_authorized").stringSafe("status", "ok").string("reply_topic", reply_topic).int("payload_bytes", payload.len).int("network_count", countNetworkEntries(payload)).int("duration_ms", elapsedMs(start_ts, io)).log();
        } else {
            logging.info().stringSafe("event", "networks_authorized").stringSafe("status", "empty").string("reply_topic", reply_topic).int("duration_ms", elapsedMs(start_ts, io)).log();
        }
        return true;
    }
    return false;
}

fn handleProbeFlush(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config, database: *db.Client) !bool {
    const msg = try service_redpanda.pullWirelessMessage(allocator, io, cfg, cfg.wireless_probe_stream_name, cfg.wireless_probe_flush_consumer);
    defer if (msg) |m| allocator.free(m);
    if (msg) |payload| {
        db_wireless.flushProbeBatch(database, payload) catch |err| {
            logging.err().stringSafe("event", "probe_flush").stringSafe("status", "error").err(err).log();
            return error.ProbeFlushFailed;
        };
        logging.info().stringSafe("event", "probe_flush").stringSafe("status", "ok").int("payload_bytes", payload.len).log();
        return true;
    }
    return false;
}

fn parseReplyRequest(allocator: std.mem.Allocator, payload: []const u8) ?std.json.Parsed(ReplyRequest) {
    return std.json.parseFromSlice(ReplyRequest, allocator, payload, .{ .ignore_unknown_fields = true }) catch null;
}

fn elapsedMs(start_ts: std.Io.Timestamp, io: std.Io) u64 {
    const elapsed_ms = start_ts.untilNow(io, .awake).toMilliseconds();
    if (elapsed_ms <= 0) return 0;
    return @intCast(elapsed_ms);
}

fn countNetworkEntries(payload: []const u8) usize {
    var count: usize = 0;
    var index: usize = 0;
    while (index + 6 <= payload.len) : (index += 1) {
        if (std.mem.eql(u8, payload[index .. index + 6], "\"ssid\"")) {
            count += 1;
            index += 5;
        }
    }
    return count;
}

test "parseReplyRequest reads optional reply topic" {
    var parsed = parseReplyRequest(std.testing.allocator, "{\"operation\":\"list_pending\",\"reply_topic\":\"_INBOX.test.1\"}").?;
    defer parsed.deinit();
    try std.testing.expectEqualStrings("_INBOX.test.1", parsed.value.reply_topic.?);
}

test "parseReplyRequest tolerates legacy request payloads" {
    var parsed = parseReplyRequest(std.testing.allocator, "{\"operation\":\"list_pending\"}").?;
    defer parsed.deinit();
    try std.testing.expect(parsed.value.reply_topic == null);
}
