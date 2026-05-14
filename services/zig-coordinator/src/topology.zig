const std = @import("std");

pub const Error = error{
    OutOfMemory,
    TopologyFileMissing,
    TopologyParseFailed,
};

pub const Stream = struct {
    key: []const u8,
    name: []const u8,
    topics_csv: []const u8,
    max_age: []const u8,
    dupe_window: []const u8,
    max_msgs: []const u8,
};

pub const Consumer = struct {
    key: []const u8,
    stream_key: []const u8,
    stream_name: []const u8,
    name: []const u8,
    filter_topic: []const u8,
};

pub const Topology = struct {
    allocator: std.mem.Allocator,
    streams: []Stream,
    consumers: []Consumer,

    pub fn deinit(self: *Topology) void {
        for (self.streams) |stream| {
            self.allocator.free(stream.key);
            self.allocator.free(stream.name);
            self.allocator.free(stream.topics_csv);
            self.allocator.free(stream.max_age);
            self.allocator.free(stream.dupe_window);
            self.allocator.free(stream.max_msgs);
        }
        self.allocator.free(self.streams);

        for (self.consumers) |consumer| {
            self.allocator.free(consumer.key);
            self.allocator.free(consumer.stream_key);
            self.allocator.free(consumer.stream_name);
            self.allocator.free(consumer.name);
            self.allocator.free(consumer.filter_topic);
        }
        self.allocator.free(self.consumers);
    }
};

pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error!Topology {
    if (path.len == 0) return error.TopologyFileMissing;
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024)) catch {
        return error.TopologyFileMissing;
    };
    defer allocator.free(content);
    return parse(allocator, content);
}

pub fn parse(allocator: std.mem.Allocator, content: []const u8) Error!Topology {
    var streams = std.ArrayList(Stream).empty;
    errdefer {
        for (streams.items) |stream| {
            allocator.free(stream.key);
            allocator.free(stream.name);
            allocator.free(stream.topics_csv);
            allocator.free(stream.max_age);
            allocator.free(stream.dupe_window);
            allocator.free(stream.max_msgs);
        }
        streams.deinit(allocator);
    }

    var raw_consumers = std.ArrayList(RawConsumer).empty;
    errdefer {
        for (raw_consumers.items) |consumer| consumer.deinit(allocator);
        raw_consumers.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r\n");
        if (line.len == 0 or line[0] == '#') continue;

        var parts = std.mem.splitScalar(u8, line, '|');
        const kind = parts.next() orelse return error.TopologyParseFailed;
        if (std.mem.eql(u8, kind, "stream")) {
            const key = parts.next() orelse return error.TopologyParseFailed;
            const env_vars = parts.next() orelse return error.TopologyParseFailed;
            const default_name = parts.next() orelse return error.TopologyParseFailed;
            const topics = parts.next() orelse return error.TopologyParseFailed;
            const max_age = parts.next() orelse return error.TopologyParseFailed;
            const dupe_window = parts.next() orelse return error.TopologyParseFailed;
            const max_msgs = parts.next() orelse return error.TopologyParseFailed;
            if (parts.next() != null) return error.TopologyParseFailed;

            const name = try resolveEnvList(allocator, env_vars, default_name);
            errdefer allocator.free(name);
            const resolved_topics = try expandTemplate(allocator, topics);
            errdefer allocator.free(resolved_topics);

            const key_copy = try allocator.dupe(u8, key);
            errdefer allocator.free(key_copy);
            const max_age_copy = try allocator.dupe(u8, max_age);
            errdefer allocator.free(max_age_copy);
            const dupe_window_copy = try allocator.dupe(u8, dupe_window);
            errdefer allocator.free(dupe_window_copy);
            const max_msgs_copy = try allocator.dupe(u8, max_msgs);
            errdefer allocator.free(max_msgs_copy);

            try streams.append(allocator, .{
                .key = key_copy,
                .name = name,
                .topics_csv = resolved_topics,
                .max_age = max_age_copy,
                .dupe_window = dupe_window_copy,
                .max_msgs = max_msgs_copy,
            });
        } else if (std.mem.eql(u8, kind, "consumer")) {
            const key = parts.next() orelse return error.TopologyParseFailed;
            const stream_key = parts.next() orelse return error.TopologyParseFailed;
            const env_vars = parts.next() orelse return error.TopologyParseFailed;
            const default_name = parts.next() orelse return error.TopologyParseFailed;
            const filter = parts.next() orelse return error.TopologyParseFailed;
            if (parts.next() != null) return error.TopologyParseFailed;

            try raw_consumers.append(allocator, .{
                .key = try allocator.dupe(u8, key),
                .stream_key = try allocator.dupe(u8, stream_key),
                .env_vars = try allocator.dupe(u8, env_vars),
                .default_name = try allocator.dupe(u8, default_name),
                .filter = try allocator.dupe(u8, filter),
            });
        } else {
            return error.TopologyParseFailed;
        }
    }

    var consumers = std.ArrayList(Consumer).empty;
    errdefer {
        for (consumers.items) |consumer| {
            allocator.free(consumer.key);
            allocator.free(consumer.stream_key);
            allocator.free(consumer.stream_name);
            allocator.free(consumer.name);
            allocator.free(consumer.filter_topic);
        }
        consumers.deinit(allocator);
    }

    for (raw_consumers.items) |raw| {
        const stream_name = findStreamName(streams.items, raw.stream_key) orelse return error.TopologyParseFailed;
        const name = try resolveEnvList(allocator, raw.env_vars, raw.default_name);
        errdefer allocator.free(name);
        const filter = try expandTemplate(allocator, raw.filter);
        errdefer allocator.free(filter);

        const key_copy = try allocator.dupe(u8, raw.key);
        errdefer allocator.free(key_copy);
        const stream_key_copy = try allocator.dupe(u8, raw.stream_key);
        errdefer allocator.free(stream_key_copy);
        const stream_name_copy = try allocator.dupe(u8, stream_name);
        errdefer allocator.free(stream_name_copy);

        try consumers.append(allocator, .{
            .key = key_copy,
            .stream_key = stream_key_copy,
            .stream_name = stream_name_copy,
            .name = name,
            .filter_topic = filter,
        });
    }

    for (raw_consumers.items) |consumer| consumer.deinit(allocator);
    raw_consumers.deinit(allocator);

    return .{
        .allocator = allocator,
        .streams = try streams.toOwnedSlice(allocator),
        .consumers = try consumers.toOwnedSlice(allocator),
    };
}

fn findStreamName(streams: []const Stream, key: []const u8) ?[]const u8 {
    for (streams) |stream| {
        if (std.mem.eql(u8, stream.key, key)) return stream.name;
    }
    return null;
}

fn resolveEnvList(allocator: std.mem.Allocator, env_vars_csv: []const u8, default_value: []const u8) Error![]u8 {
    var iterator = std.mem.splitScalar(u8, env_vars_csv, ',');
    while (iterator.next()) |raw_name| {
        const name = std.mem.trim(u8, raw_name, " \t\r\n");
        if (name.len == 0) continue;
        const name_z = try allocator.dupeZ(u8, name);
        defer allocator.free(name_z);
        if (std.c.getenv(name_z.ptr)) |value| {
            const resolved = std.mem.span(value);
            if (resolved.len > 0) return allocator.dupe(u8, resolved);
        }
    }
    return expandTemplate(allocator, default_value);
}

fn expandTemplate(allocator: std.mem.Allocator, raw: []const u8) Error![]u8 {
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);

    var index: usize = 0;
    while (index < raw.len) {
        if (index + 2 <= raw.len and raw[index] == '$' and raw[index + 1] == '{') {
            const close_offset = std.mem.indexOfScalar(u8, raw[index + 2 ..], '}') orelse return error.TopologyParseFailed;
            const expr = raw[index + 2 .. index + 2 + close_offset];
            const fallback_sep = std.mem.indexOf(u8, expr, ":-");
            const name = if (fallback_sep) |sep| expr[0..sep] else expr;
            const fallback = if (fallback_sep) |sep| expr[sep + 2 ..] else "";
            const name_z = try allocator.dupeZ(u8, name);
            defer allocator.free(name_z);
            const value = if (std.c.getenv(name_z.ptr)) |env_value| std.mem.span(env_value) else fallback;
            try output.appendSlice(allocator, value);
            index += close_offset + 3;
            continue;
        }
        try output.append(allocator, raw[index]);
        index += 1;
    }

    return output.toOwnedSlice(allocator);
}

const RawConsumer = struct {
    key: []const u8,
    stream_key: []const u8,
    env_vars: []const u8,
    default_name: []const u8,
    filter: []const u8,

    fn deinit(self: RawConsumer, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.stream_key);
        allocator.free(self.env_vars);
        allocator.free(self.default_name);
        allocator.free(self.filter);
    }
};

test "topic_manifest parser resolves streams consumers and topic templates" {
    const manifest =
        \\stream|audit|AUDIT_STREAM_NAME|AUDIT_STREAM|${SYNC_SCAN_TOPIC:-sync.scan.request},wireless.audit|720h|2m|-1
        \\consumer|scan|audit|SYNC_SCAN_CONSUMER|zig-coordinator-scan|${SYNC_SCAN_TOPIC:-sync.scan.request}
    ;

    var parsed = try parse(std.testing.allocator, manifest);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.streams.len);
    try std.testing.expectEqualStrings("audit", parsed.streams[0].key);
    try std.testing.expectEqualStrings("AUDIT_STREAM", parsed.streams[0].name);
    try std.testing.expectEqualStrings("sync.scan.request,wireless.audit", parsed.streams[0].topics_csv);
    try std.testing.expectEqual(@as(usize, 1), parsed.consumers.len);
    try std.testing.expectEqualStrings("AUDIT_STREAM", parsed.consumers[0].stream_name);
    try std.testing.expectEqualStrings("sync.scan.request", parsed.consumers[0].filter_topic);
}
