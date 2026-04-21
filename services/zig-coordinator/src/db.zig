const std = @import("std");
const state = @import("state.zig");

pub const InMemoryDb = struct {
    allocator: std.mem.Allocator,
    cursors: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) InMemoryDb {
        return .{
            .allocator = allocator,
            .cursors = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *InMemoryDb) void {
        var iterator = self.cursors.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.cursors.deinit();
    }

    pub fn loadCursor(self: *InMemoryDb, stream_name: []const u8) ?state.Cursor {
        const value = self.cursors.get(stream_name) orelse return null;
        return .{ .stream_name = stream_name, .cursor_value = value };
    }

    pub fn saveCursor(self: *InMemoryDb, stream_name: []const u8, cursor: []const u8) !void {
        // First allocate new buffers - only modify state after successful allocation
        const owned_key = try self.allocator.dupe(u8, stream_name);
        errdefer self.allocator.free(owned_key);
        const owned_value = try self.allocator.dupe(u8, cursor);
        errdefer self.allocator.free(owned_value);

        // Now it is safe to remove and free existing entry
        if (self.cursors.fetchRemove(stream_name)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
        }

        try self.cursors.put(owned_key, owned_value);
    }
};
