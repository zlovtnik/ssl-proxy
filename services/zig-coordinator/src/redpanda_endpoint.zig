const std = @import("std");
const builtin = @import("builtin");

pub const Endpoint = struct {
    host: []const u8,
    port: u16,
    user: ?[]const u8,
    pass: ?[]const u8,
    token: ?[]const u8,
    tls: bool,

    pub fn parse(redpanda_url: []const u8) !Endpoint {
        const trimmed = std.mem.trim(u8, redpanda_url, " \t\r\n");
        if (trimmed.len == 0) return error.InvalidRedpandaUrl;

        const tls, const without_scheme = if (std.mem.startsWith(u8, trimmed, "tls://"))
            .{ true, trimmed["tls://".len..] }
        else if (std.mem.startsWith(u8, trimmed, "redpanda://"))
            .{ false, trimmed["redpanda://".len..] }
        else
            .{ false, trimmed };

        const authority = blk: {
            var iterator = std.mem.splitScalar(u8, without_scheme, '/');
            break :blk iterator.first();
        };
        if (authority.len == 0) return error.InvalidRedpandaUrl;

        var host_port = authority;
        var user: ?[]const u8 = null;
        var pass: ?[]const u8 = null;
        var token: ?[]const u8 = null;
        if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
            const userinfo = authority[0..at];
            host_port = authority[at + 1 ..];
            if (userinfo.len == 0 or host_port.len == 0) return error.InvalidRedpandaUrl;
            if (std.mem.indexOfScalar(u8, userinfo, ':')) |separator| {
                user = userinfo[0..separator];
                pass = userinfo[separator + 1 ..];
            } else {
                token = userinfo;
            }
        }

        const host, const port = try parseHostPort(host_port);
        return .{
            .host = host,
            .port = port,
            .user = user,
            .pass = pass,
            .token = token,
            .tls = tls,
        };
    }
};

pub fn applySocketTimeouts(stream: std.Io.net.Stream, timeout_ms: u32) !void {
    if (builtin.os.tag == .windows) return;

    const timeout = std.posix.timeval{
        .sec = @intCast(@divTrunc(timeout_ms, 1_000)),
        .usec = @intCast(@mod(timeout_ms, 1_000) * 1_000),
    };
    const timeout_bytes = std.mem.asBytes(&timeout);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, timeout_bytes);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, timeout_bytes);
}

pub fn connectEndpoint(endpoint: Endpoint, io: std.Io) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.parse(endpoint.host, endpoint.port)) |address| {
        return address.connect(io, .{ .mode = .stream });
    } else |_| {}

    try std.Io.net.HostName.validate(endpoint.host);
    return std.Io.net.HostName.connect(
        .{ .bytes = endpoint.host },
        io,
        endpoint.port,
        .{ .mode = .stream },
    );
}

fn parseHostPort(host_port: []const u8) !struct { []const u8, u16 } {
    if (host_port.len == 0) return error.InvalidRedpandaUrl;

    if (host_port[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host_port, ']') orelse return error.InvalidRedpandaUrl;
        const host = host_port[1..close];
        if (host.len == 0) return error.InvalidRedpandaUrl;
        if (close + 1 == host_port.len) return .{ host, 4222 };
        if (host_port[close + 1] != ':') return error.InvalidRedpandaUrl;
        return .{ host, try parsePort(host_port[close + 2 ..]) };
    }

    if (std.mem.lastIndexOfScalar(u8, host_port, ':')) |separator| {
        const host = host_port[0..separator];
        if (host.len == 0) return error.InvalidRedpandaUrl;
        return .{ host, try parsePort(host_port[separator + 1 ..]) };
    }

    return .{ host_port, 4222 };
}

fn parsePort(raw: []const u8) !u16 {
    if (raw.len == 0) return error.InvalidRedpandaUrl;
    return std.fmt.parseInt(u16, raw, 10) catch error.InvalidRedpandaUrl;
}

test "parse endpoint defaults port and extracts auth" {
    const endpoint = try Endpoint.parse("redpanda://user:pass@redpanda:4222");
    try std.testing.expectEqualStrings("redpanda", endpoint.host);
    try std.testing.expectEqual(@as(u16, 4222), endpoint.port);
    try std.testing.expectEqualStrings("user", endpoint.user.?);
    try std.testing.expectEqualStrings("pass", endpoint.pass.?);
    try std.testing.expect(endpoint.token == null);
    try std.testing.expect(!endpoint.tls);
}

test "parse endpoint treats bare userinfo as token" {
    const endpoint = try Endpoint.parse("redpanda://token@redpanda");
    try std.testing.expectEqualStrings("redpanda", endpoint.host);
    try std.testing.expectEqualStrings("token", endpoint.token.?);
    try std.testing.expect(endpoint.user == null);
    try std.testing.expect(endpoint.pass == null);
}

test "parse endpoint handles implicit port and tls scheme" {
    const endpoint = try Endpoint.parse("tls://redpanda.internal");
    try std.testing.expectEqualStrings("redpanda.internal", endpoint.host);
    try std.testing.expectEqual(@as(u16, 4222), endpoint.port);
    try std.testing.expect(endpoint.tls);
}
