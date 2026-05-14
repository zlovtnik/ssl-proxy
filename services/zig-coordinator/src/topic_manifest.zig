const std = @import("std");

pub fn streamNameIsConfigured(stream_names_csv: []const u8, stream_name: []const u8) bool {
    var iterator = std.mem.splitScalar(u8, stream_names_csv, ',');
    while (iterator.next()) |raw_name| {
        const configured = std.mem.trim(u8, raw_name, " \t\r\n");
        if (std.mem.eql(u8, configured, stream_name)) return true;
    }
    return false;
}

const allowed_oracle_stream_names = [_][]const u8{
    "proxy.events",
};

fn allowedOracleStreamName(stream_name: []const u8) bool {
    for (allowed_oracle_stream_names) |allowed| {
        if (std.mem.eql(u8, allowed, stream_name)) return true;
    }
    return false;
}

pub fn invalidOracleStreamName(stream_names_csv: []const u8, oracle_stream_names_csv: []const u8) ?[]const u8 {
    var iterator = std.mem.splitScalar(u8, oracle_stream_names_csv, ',');
    while (iterator.next()) |raw_name| {
        const stream_name = std.mem.trim(u8, raw_name, " \t\r\n");
        if (stream_name.len == 0) continue;
        if (!allowedOracleStreamName(stream_name)) return stream_name;
        if (!streamNameIsConfigured(stream_names_csv, stream_name)) return stream_name;
    }
    return null;
}

test "streamNameIsConfigured matches trimmed CSV entries" {
    try std.testing.expect(streamNameIsConfigured("proxy.events, wireless.audit", "proxy.events"));
    try std.testing.expect(streamNameIsConfigured("proxy.events, wireless.audit", "wireless.audit"));
    try std.testing.expect(!streamNameIsConfigured("proxy.events, wireless.audit", "unknown"));
}

test "invalidOracleStreamName accepts proxy events only" {
    try std.testing.expect(invalidOracleStreamName("proxy.events, wireless.audit", "proxy.events") == null);
    try std.testing.expect(invalidOracleStreamName("proxy.events, wireless.audit", "") == null);
}

test "invalidOracleStreamName rejects wireless audit Oracle dispatch" {
    const invalid = invalidOracleStreamName("proxy.events, wireless.audit", "proxy.events, wireless.audit").?;
    try std.testing.expectEqualStrings("wireless.audit", invalid);
}

test "invalidOracleStreamName rejects Oracle stream outside configured streams" {
    const invalid = invalidOracleStreamName("wireless.audit", "proxy.events").?;
    try std.testing.expectEqualStrings("proxy.events", invalid);
}
