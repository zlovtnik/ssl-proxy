const std = @import("std");
const logging = @import("logging.zig");
const redpanda_endpoint = @import("redpanda_endpoint.zig");

const MAX_ACK_PAYLOAD_BYTES = 8 * 1024;

pub fn validateTopic(topic: []const u8) !void {
    if (topic.len == 0) return error.InvalidTopic;
    for (topic) |byte| {
        if (std.ascii.isWhitespace(byte)) return error.InvalidTopic;
    }
}

pub fn expectInfo(reader: *std.Io.net.Stream.Reader) !void {
    const line = try readLine(reader);
    if (!std.mem.startsWith(u8, line, "INFO ")) return error.ProtocolError;
}

pub fn writeConnect(writer: *std.Io.Writer, endpoint: redpanda_endpoint.Endpoint) !void {
    try writer.writeAll("CONNECT ");
    try writeConnectJson(writer, endpoint.user, endpoint.pass, endpoint.token);
    try writer.writeAll("\r\n");
    try writer.flush();
}

pub fn writeCorePublish(writer: *std.Io.Writer, topic: []const u8, payload: []const u8) !void {
    try writer.print("PUB {s} {d}\r\n", .{ topic, payload.len });
    try writer.writeAll(payload);
    try writer.writeAll("\r\n");
    try writer.flush();
}

pub fn writePing(writer: *std.Io.Writer) !void {
    try writer.writeAll("PING\r\n");
    try writer.flush();
}

pub fn makeAckInbox(io: std.Io, buffer: []u8) ![]const u8 {
    var random: [12]u8 = undefined;
    io.random(&random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    return std.fmt.bufPrint(
        buffer,
        "_INBOX.zig-coordinator.{s}",
        .{&random_hex},
    );
}

pub fn writeAckSubscription(writer: *std.Io.Writer, inbox: []const u8) !void {
    try writer.print("SUB {s} 1\r\n", .{inbox});
    try writer.flush();
}

pub fn writeAckedPublish(
    writer: *std.Io.Writer,
    topic: []const u8,
    inbox: []const u8,
    payload: []const u8,
) !void {
    try writer.print("PUB {s} {s} {d}\r\n", .{ topic, inbox, payload.len });
    try writer.writeAll(payload);
    try writer.writeAll("\r\n");
    try writer.flush();
}

pub fn waitForPong(reader: *std.Io.net.Stream.Reader, writer: *std.Io.net.Stream.Writer) !void {
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        const line = readLine(reader) catch |err| return err;
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "PING")) {
            try writer.interface.writeAll("PONG\r\n");
            try writer.interface.flush();
            continue;
        }
        if (std.mem.eql(u8, line, "+OK") or std.mem.startsWith(u8, line, "INFO ")) continue;
        if (std.mem.eql(u8, line, "PONG")) return;
        if (std.mem.startsWith(u8, line, "-ERR")) {
            logPublishAckFailure("server_error", line);
            return error.ServerError;
        }

        return error.ProtocolError;
    }

    return error.PublishAckFailed;
}

pub fn waitForPublishAck(
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    timeout_ms: u32,
) !void {
    const start_ts = std.Io.Timestamp.now(io, .awake);
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        if (elapsedMs(start_ts, io) >= timeout_ms) {
            logPublishAckFailure("ack_timeout", "timed out waiting for Redpanda publish acknowledgement");
            return error.PublishAckFailed;
        }

        const line = readLine(reader) catch |err| {
            if (err == error.Timeout) {
                logPublishAckFailure("ack_timeout", "timed out waiting for Redpanda publish acknowledgement");
                return error.PublishAckFailed;
            }
            return err;
        };
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "PING")) {
            logPublishAckProgress("publish_ack", line);
            try writer.interface.writeAll("PONG\r\n");
            try writer.interface.flush();
            continue;
        }
        if (std.mem.eql(u8, line, "+OK") or std.mem.eql(u8, line, "PONG") or std.mem.startsWith(u8, line, "INFO ")) {
            logPublishAckProgress("publish_ack", line);
            continue;
        }
        if (std.mem.startsWith(u8, line, "-ERR")) {
            logPublishAckFailure("server_error", line);
            return error.ServerError;
        }
        if (std.mem.startsWith(u8, line, "MSG ")) {
            logPublishAckProgress("publish_ack", line);
            const payload_size = try parseMessageSize(line);
            if (payload_size > MAX_ACK_PAYLOAD_BYTES) return error.PublishAckTooLarge;
            const payload = try takeBytes(reader, payload_size);
            const has_error = std.mem.indexOf(u8, payload, "\"error\"") != null;
            const terminator = try takeArray2(reader);
            if (!std.mem.eql(u8, terminator, "\r\n")) return error.ProtocolError;
            if (has_error) {
                logPublishAckFailure("ack_error", payload);
                return error.PublishAckFailed;
            }
            logPublishAckSuccess(attempts + 1);
            return;
        }

        return error.ProtocolError;
    }

    logPublishAckFailure("ack_timeout", "no Redpanda publish acknowledgement received");
    return error.PublishAckFailed;
}

pub fn readMessagePayloadAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    timeout_ms: u32,
) ![]u8 {
    const start_ts = std.Io.Timestamp.now(io, .awake);
    var attempts: usize = 0;
    while (attempts < 32) : (attempts += 1) {
        if (elapsedMs(start_ts, io) >= timeout_ms) return error.Timeout;

        const line = try readLine(reader);
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "PING")) {
            try writer.interface.writeAll("PONG\r\n");
            try writer.interface.flush();
            continue;
        }
        if (std.mem.eql(u8, line, "+OK") or std.mem.eql(u8, line, "PONG") or std.mem.startsWith(u8, line, "INFO ")) continue;
        if (std.mem.startsWith(u8, line, "-ERR")) return error.ServerError;
        if (std.mem.startsWith(u8, line, "MSG ")) {
            const payload_size = try parseMessageSize(line);
            if (payload_size > MAX_ACK_PAYLOAD_BYTES) return error.PublishAckTooLarge;
            const message = try takeBytes(reader, payload_size);
            const owned = try allocator.dupe(u8, message);
            errdefer allocator.free(owned);
            const terminator = try takeArray2(reader);
            if (!std.mem.eql(u8, terminator, "\r\n")) return error.ProtocolError;
            return owned;
        }

        return error.ProtocolError;
    }

    return error.Timeout;
}

pub fn elapsedMs(start_ts: std.Io.Timestamp, io: std.Io) u32 {
    const elapsed_ms = start_ts.untilNow(io, .awake).toMilliseconds();
    if (elapsed_ms <= 0) return 0;
    return @intCast(@min(elapsed_ms, std.math.maxInt(u32)));
}

pub fn writeConnectJson(
    writer: *std.Io.Writer,
    user: ?[]const u8,
    pass: ?[]const u8,
    token: ?[]const u8,
) !void {
    try writer.writeAll("{\"verbose\":false,\"pedantic\":false");
    if (user) |value| {
        try writer.writeAll(",\"user\":");
        try std.json.Stringify.value(value, .{}, writer);
    }
    if (pass) |value| {
        try writer.writeAll(",\"pass\":");
        try std.json.Stringify.value(value, .{}, writer);
    }
    if (token) |value| {
        try writer.writeAll(",\"auth_token\":");
        try std.json.Stringify.value(value, .{}, writer);
    }
    try writer.writeAll("}");
}

fn readLine(reader: *std.Io.net.Stream.Reader) ![]const u8 {
    const raw = reader.interface.takeDelimiterExclusive('\n') catch |err| return mapReadError(reader, err);
    return std.mem.trim(u8, raw, " \t\r");
}

fn takeBytes(reader: *std.Io.net.Stream.Reader, size: usize) ![]const u8 {
    return reader.interface.take(size) catch |err| mapReadError(reader, err);
}

fn takeArray2(reader: *std.Io.net.Stream.Reader) !*[2]u8 {
    return reader.interface.takeArray(2) catch |err| mapReadError(reader, err);
}

fn mapReadError(reader: *std.Io.net.Stream.Reader, err: anyerror) anyerror {
    if (reader.err) |read_error| {
        if (read_error == error.Timeout) return error.Timeout;
    }
    return err;
}

pub fn parseMessageSize(line: []const u8) !usize {
    var parts = std.mem.splitBackwardsScalar(u8, line, ' ');
    const size_token = parts.first();
    if (size_token.len == 0) return error.ProtocolError;
    return std.fmt.parseInt(usize, size_token, 10) catch error.ProtocolError;
}

fn logPublishAckFailure(reason: []const u8, raw: []const u8) void {
    var buffer: [1024]u8 = undefined;
    const snippet = sanitizeSnippet(&buffer, raw);
    logging.err()
        .stringSafe("event", "redpanda_publish_ack")
        .stringSafe("status", "error")
        .string("reason", reason)
        .string("payload", snippet)
        .log();
}

fn logPublishAckProgress(phase: []const u8, raw: []const u8) void {
    var buffer: [1024]u8 = undefined;
    const snippet = sanitizeSnippet(&buffer, raw);
    logging.debug()
        .stringSafe("event", "redpanda_publish_ack")
        .stringSafe("status", "observed")
        .string("phase", phase)
        .string("payload", snippet)
        .log();
}

fn logPublishAckSuccess(attempts: usize) void {
    logging.debug()
        .stringSafe("event", "redpanda_publish_ack")
        .stringSafe("status", "ok")
        .stringSafe("phase", "publish_ack")
        .int("attempts", attempts)
        .log();
}

fn sanitizeSnippet(buffer: []u8, raw: []const u8) []const u8 {
    var in_index: usize = 0;
    var out_index: usize = 0;

    while (in_index < raw.len and out_index < buffer.len) : (in_index += 1) {
        const byte = raw[in_index];
        buffer[out_index] = switch (byte) {
            '\n', '\r', '\t' => ' ',
            else => byte,
        };
        out_index += 1;
    }

    return std.mem.trim(u8, buffer[0..out_index], " ");
}

test {
    _ = @import("redpanda_protocol_test.zig");
}
