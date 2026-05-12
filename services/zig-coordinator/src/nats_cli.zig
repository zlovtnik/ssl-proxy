const std = @import("std");

pub const Error = error{
    InvalidNatsUrl,
};

pub fn parseNatsAuthority(allocator: std.mem.Allocator, nats_url: []const u8) Error![]u8 {
    const trimmed = std.mem.trim(u8, nats_url, " \t\r\n");
    const no_scheme = if (std.mem.startsWith(u8, trimmed, "nats://")) trimmed["nats://".len..] else trimmed;
    var iterator = std.mem.splitScalar(u8, no_scheme, '/');
    const authority = iterator.first();
    if (authority.len == 0) return error.InvalidNatsUrl;

    const host_start = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| at + 1 else 0;
    const host_and_port = authority[host_start..];
    if (std.mem.lastIndexOfScalar(u8, host_and_port, ':') != null) {
        return allocator.dupe(u8, authority) catch error.InvalidNatsUrl;
    }

    return std.fmt.allocPrint(allocator, "{s}:4222", .{authority}) catch error.InvalidNatsUrl;
}

pub fn looksLikeNoMessage(stderr: []const u8) bool {
    return containsAsciiCaseInsensitive(stderr, "timeout") or
        containsAsciiCaseInsensitive(stderr, "timed out") or
        containsAsciiCaseInsensitive(stderr, "no messages");
}

pub fn consumerInfoHasBacklog(stdout: []const u8) bool {
    return labeledCountIsPositive(stdout, "Pending Messages:") or
        labeledCountIsPositive(stdout, "Unprocessed Messages:");
}

fn labeledCountIsPositive(stdout: []const u8, label: []const u8) bool {
    var lines = std.mem.splitScalar(u8, stdout, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (!std.mem.startsWith(u8, line, label)) continue;

        var digits_buffer: [32]u8 = undefined;
        var digits_len: usize = 0;
        var index: usize = label.len;
        while (index < line.len and std.ascii.isWhitespace(line[index])) : (index += 1) {}
        while (index < line.len) : (index += 1) {
            const byte = line[index];
            if (std.ascii.isDigit(byte)) {
                if (digits_len < digits_buffer.len) {
                    digits_buffer[digits_len] = byte;
                    digits_len += 1;
                }
                continue;
            }
            if (byte == ',') continue;
            break;
        }

        if (digits_len == 0) return false;
        const count = std.fmt.parseInt(u64, digits_buffer[0..digits_len], 10) catch return false;
        return count > 0;
    }

    return false;
}

fn containsAsciiCaseInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        var matched = true;
        var offset: usize = 0;
        while (offset < needle.len) : (offset += 1) {
            if (std.ascii.toLower(haystack[index + offset]) != std.ascii.toLower(needle[offset])) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }

    return false;
}

test "looksLikeNoMessage matches timeout variants" {
    try std.testing.expect(looksLikeNoMessage("Timed Out Waiting For Message"));
    try std.testing.expect(!looksLikeNoMessage("permission denied"));
}

test "consumerInfoHasBacklog parses labeled counts" {
    try std.testing.expect(consumerInfoHasBacklog("Pending Messages: 1,200\n"));
    try std.testing.expect(!consumerInfoHasBacklog("Pending Messages: 0\n"));
}
