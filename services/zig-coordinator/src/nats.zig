const std = @import("std");
const model = @import("state.zig");

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
