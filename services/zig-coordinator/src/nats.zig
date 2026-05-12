const std = @import("std");
const model = @import("state.zig");
const endpoint_mod = @import("nats_endpoint.zig");
const protocol = @import("nats_protocol.zig");

const NATS_IO_TIMEOUT_MS = 10_000;

pub const PublishMode = enum {
    core,
    jetstream_ack,
};

pub const Publisher = struct {
    allocator: std.mem.Allocator,
    published: std.ArrayListUnmanaged(model.Batch),

    pub fn init(allocator: std.mem.Allocator) !Publisher {
        return .{
            .allocator = allocator,
            .published = try std.ArrayListUnmanaged(model.Batch).initCapacity(allocator, 1),
        };
    }

    pub fn deinit(self: *Publisher) void {
        self.published.deinit(self.allocator);
    }

    pub fn publishBatch(self: *Publisher, batch: model.Batch) !void {
        try self.published.append(self.allocator, batch);
    }
};

pub fn publish(
    allocator: std.mem.Allocator,
    io: std.Io,
    nats_url: []const u8,
    subject: []const u8,
    payload: []const u8,
    mode: PublishMode,
    timeout_ms: u32,
) !void {
    _ = allocator;
    const effective_timeout_ms = if (timeout_ms == 0) NATS_IO_TIMEOUT_MS else timeout_ms;
    const endpoint = try endpoint_mod.Endpoint.parse(nats_url);
    if (endpoint.tls) return error.UnsupportedNatsScheme;
    try protocol.validateSubject(subject);

    switch (mode) {
        .core => try publishCore(io, endpoint, subject, payload, effective_timeout_ms),
        .jetstream_ack => try publishJetStreamAckOnce(io, endpoint, subject, payload, effective_timeout_ms),
    }
}

fn publishCore(
    io: std.Io,
    endpoint: endpoint_mod.Endpoint,
    subject: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) !void {
    var stream = try endpoint_mod.connectEndpoint(endpoint, io);
    defer stream.close(io);
    try endpoint_mod.applySocketTimeouts(stream, timeout_ms);

    var reader_buffer: [16 * 1024]u8 = undefined;
    var writer_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var writer = stream.writer(io, &writer_buffer);

    try protocol.expectInfo(&reader);
    try protocol.writeConnect(&writer.interface, endpoint);
    try protocol.writeCorePublish(&writer.interface, subject, payload);
    try protocol.writePing(&writer.interface);
    try protocol.waitForPong(&reader, &writer);
}

fn publishJetStreamAckOnce(
    io: std.Io,
    endpoint: endpoint_mod.Endpoint,
    subject: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) !void {
    var stream = try endpoint_mod.connectEndpoint(endpoint, io);
    defer stream.close(io);
    try endpoint_mod.applySocketTimeouts(stream, timeout_ms);

    var reader_buffer: [16 * 1024]u8 = undefined;
    var writer_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var writer = stream.writer(io, &writer_buffer);

    try protocol.expectInfo(&reader);
    try protocol.writeConnect(&writer.interface, endpoint);

    var inbox_buffer: [64]u8 = undefined;
    const inbox = try protocol.makeAckInbox(io, &inbox_buffer);
    try protocol.writeAckSubscription(&writer.interface, inbox);
    try protocol.writeAckedPublish(&writer.interface, subject, inbox, payload);
    try protocol.waitForPublishAck(io, &reader, &writer, timeout_ms);
}

fn requestJetStreamApi(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: endpoint_mod.Endpoint,
    api_subject: []const u8,
    payload: []const u8,
    timeout_ms: u32,
) ![]u8 {
    var stream = try endpoint_mod.connectEndpoint(endpoint, io);
    defer stream.close(io);
    try endpoint_mod.applySocketTimeouts(stream, timeout_ms);

    var reader_buffer: [16 * 1024]u8 = undefined;
    var writer_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &reader_buffer);
    var writer = stream.writer(io, &writer_buffer);

    try protocol.expectInfo(&reader);
    try protocol.writeConnect(&writer.interface, endpoint);

    var inbox_buffer: [64]u8 = undefined;
    const inbox = try protocol.makeAckInbox(io, &inbox_buffer);
    try protocol.writeAckSubscription(&writer.interface, inbox);
    try protocol.writeAckedPublish(&writer.interface, api_subject, inbox, payload);

    return protocol.readMessagePayloadAlloc(allocator, io, &reader, &writer, timeout_ms);
}

test "JetStream publish round-trip when NATS_URL is set" {
    const raw_url = if (std.c.getenv("NATS_URL")) |value| std.mem.span(value) else return error.SkipZigTest;
    const endpoint = try endpoint_mod.Endpoint.parse(raw_url);
    if (endpoint.tls) return error.SkipZigTest;

    const seed: u64 = @truncate(@as(u96, @bitCast(std.Io.Timestamp.now(std.testing.io, .awake).toNanoseconds())));
    var prng = std.Random.DefaultPrng.init(seed);
    var random_bytes: [8]u8 = undefined;
    prng.random().bytes(&random_bytes);
    const random_hex = std.fmt.bytesToHex(random_bytes, .lower);

    var stream_buffer: [64]u8 = undefined;
    const stream_name = try std.fmt.bufPrint(&stream_buffer, "NATS_RELIABILITY_TEST_{s}", .{&random_hex});
    var subject_buffer: [96]u8 = undefined;
    const subject = try std.fmt.bufPrint(&subject_buffer, "nats.reliability.test.{s}", .{&random_hex});
    const payload = "{\"ok\":true}";
    const timeout_ms: u32 = 2_000;

    const create_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"name\":\"{s}\",\"subjects\":[\"{s}\"],\"storage\":\"memory\",\"retention\":\"limits\",\"max_msgs\":100}}",
        .{ stream_name, subject },
    );
    defer std.testing.allocator.free(create_payload);

    var create_subject_buffer: [96]u8 = undefined;
    const create_subject = try std.fmt.bufPrint(&create_subject_buffer, "$JS.API.STREAM.CREATE.{s}", .{stream_name});
    const create_response = try requestJetStreamApi(std.testing.allocator, std.testing.io, endpoint, create_subject, create_payload, timeout_ms);
    defer std.testing.allocator.free(create_response);
    try std.testing.expect(std.mem.indexOf(u8, create_response, "\"error\"") == null);

    var delete_subject_buffer: [96]u8 = undefined;
    const delete_subject = try std.fmt.bufPrint(&delete_subject_buffer, "$JS.API.STREAM.DELETE.{s}", .{stream_name});
    defer {
        const delete_response = requestJetStreamApi(std.testing.allocator, std.testing.io, endpoint, delete_subject, "{}", timeout_ms) catch null;
        if (delete_response) |response| std.testing.allocator.free(response);
    }

    const publish_started_ts = std.Io.Timestamp.now(std.testing.io, .awake);
    try publish(std.testing.allocator, std.testing.io, raw_url, subject, payload, .jetstream_ack, timeout_ms);
    try std.testing.expect(protocol.elapsedMs(publish_started_ts, std.testing.io) <= timeout_ms);

    const get_payload = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"last_by_subj\":\"{s}\"}}",
        .{subject},
    );
    defer std.testing.allocator.free(get_payload);

    var get_subject_buffer: [96]u8 = undefined;
    const get_subject = try std.fmt.bufPrint(&get_subject_buffer, "$JS.API.STREAM.MSG.GET.{s}", .{stream_name});
    const get_response = try requestJetStreamApi(std.testing.allocator, std.testing.io, endpoint, get_subject, get_payload, timeout_ms);
    defer std.testing.allocator.free(get_response);

    var encoded_payload_buffer: [std.base64.standard.Encoder.calcSize(payload.len)]u8 = undefined;
    const encoded_payload = std.base64.standard.Encoder.encode(&encoded_payload_buffer, payload);
    try std.testing.expect(std.mem.indexOf(u8, get_response, subject) != null);
    try std.testing.expect(std.mem.indexOf(u8, get_response, encoded_payload) != null);
}
