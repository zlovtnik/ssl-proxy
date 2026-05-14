const std = @import("std");
const protocol = @import("redpanda_protocol.zig");

test "validate topic rejects protocol separators" {
    try protocol.validateTopic("sync.oracle.load");
    try std.testing.expectError(error.InvalidTopic, protocol.validateTopic("sync.oracle.load\r\nPING"));
}

test "write connect json escapes credentials" {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try protocol.writeConnectJson(&writer, "user", "p\nx", null);
    try std.testing.expectEqualStrings(
        "{\"verbose\":false,\"pedantic\":false,\"user\":\"user\",\"pass\":\"p\\nx\"}",
        writer.buffered(),
    );
}

test "write connect json emits auth token" {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try protocol.writeConnectJson(&writer, null, null, "token");
    try std.testing.expectEqualStrings(
        "{\"verbose\":false,\"pedantic\":false,\"auth_token\":\"token\"}",
        writer.buffered(),
    );
}

test "write core publish does not request a Redpanda ack" {
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try protocol.writeCorePublish(&writer, "wireless.backlog.list.reply", "{\"ok\":true}");
    try std.testing.expectEqualStrings(
        "PUB wireless.backlog.list.reply 11\r\n{\"ok\":true}\r\n",
        writer.buffered(),
    );
}

test "write ack subscription and publish use explicit inbox reply" {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try protocol.writeAckSubscription(&writer, "_INBOX.zig-coordinator.abc123");
    try protocol.writeAckedPublish(&writer, "sync.oracle.load", "_INBOX.zig-coordinator.abc123", "{\"batch_id\":\"b\"}");
    try std.testing.expectEqualStrings(
        "SUB _INBOX.zig-coordinator.abc123 1\r\n" ++
            "PUB sync.oracle.load _INBOX.zig-coordinator.abc123 16\r\n" ++
            "{\"batch_id\":\"b\"}\r\n",
        writer.buffered(),
    );
}

test "parse message size uses final token" {
    try std.testing.expectEqual(@as(usize, 42), try protocol.parseMessageSize("MSG _INBOX.x 1 42"));
    try std.testing.expectEqual(@as(usize, 42), try protocol.parseMessageSize("MSG _INBOX.x 1 reply.to 42"));
}
