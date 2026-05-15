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
    "wireless.audit",
    "audit.wireless.bandwidth",
    "wireless.alert.rogue_ap",
    "wireless.alert.deauth_flood",
    "wireless.alert.signal_anomaly",
    "wireless.alert.pmf_attack",
    "wireless.client.inventory",
    "wireless.probe.flush",
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

test "invalidOracleStreamName accepts supported Oracle streams" {
    const configured =
        "proxy.events, wireless.audit, audit.wireless.bandwidth, wireless.alert.rogue_ap, wireless.alert.deauth_flood, wireless.alert.signal_anomaly, wireless.alert.pmf_attack, wireless.client.inventory, wireless.probe.flush";
    const oracle_streams =
        "proxy.events,wireless.audit,audit.wireless.bandwidth,wireless.alert.rogue_ap,wireless.alert.deauth_flood,wireless.alert.signal_anomaly,wireless.alert.pmf_attack,wireless.client.inventory,wireless.probe.flush";
    try std.testing.expect(invalidOracleStreamName(configured, oracle_streams) == null);
    try std.testing.expect(invalidOracleStreamName(configured, "") == null);
}

test "invalidOracleStreamName rejects unsupported Oracle dispatch" {
    const invalid = invalidOracleStreamName("proxy.events, wireless.audit, wifi.alert.handshake", "proxy.events, wifi.alert.handshake").?;
    try std.testing.expectEqualStrings("wifi.alert.handshake", invalid);
}

test "invalidOracleStreamName rejects Oracle stream outside configured streams" {
    const invalid = invalidOracleStreamName("wireless.audit", "proxy.events").?;
    try std.testing.expectEqualStrings("proxy.events", invalid);
}
