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
        const entry = self.cursors.getEntry(stream_name) orelse return null;
        return .{ .stream_name = entry.key_ptr.*, .cursor_value = entry.value_ptr.* };
    }

    pub fn saveCursor(self: *InMemoryDb, stream_name: []const u8, cursor: []const u8) !void {
        const owned_key = try self.allocator.dupe(u8, stream_name);
        errdefer self.allocator.free(owned_key);
        const owned_value = try self.allocator.dupe(u8, cursor);
        errdefer self.allocator.free(owned_value);

        const maybe_old = self.cursors.fetchRemove(stream_name);

        self.cursors.put(owned_key, owned_value) catch |err| {
            if (maybe_old) |old| {
                self.cursors.put(old.key, old.value) catch {
                    self.allocator.free(old.key);
                    self.allocator.free(old.value);
                };
            }
            return err;
        };

        if (maybe_old) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
    }
};
