const std = @import("std");
const db = @import("db.zig");
const jobs = @import("jobs.zig");
const model = @import("state.zig");
const nats = @import("nats.zig");

const RetryState = struct {
    attempts: usize,
    backoff_ms: u64,
};
const MAX_RETRIES: usize = 10;

pub const Coordinator = struct {
    allocator: std.mem.Allocator,
    store: db.InMemoryDb,
    publisher: nats.Publisher,
    retry_state: std.StringHashMap(RetryState),
    retry_queue: std.ArrayList(model.WorkerResult),

    pub fn init(allocator: std.mem.Allocator) !Coordinator {
        return .{
            .allocator = allocator,
            .store = db.InMemoryDb.init(allocator),
            .publisher = try nats.Publisher.init(allocator),
            .retry_state = std.StringHashMap(RetryState).init(allocator),
            .retry_queue = try std.ArrayList(model.WorkerResult).initCapacity(allocator, 1),
        };
    }

    pub fn deinit(self: *Coordinator) void {
        var iterator = self.retry_state.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.retry_state.deinit();
        for (self.retry_queue.items) |item| {
            self.allocator.free(item.job_id);
            self.allocator.free(item.batch_id);
            self.allocator.free(item.status);
        }
        self.retry_queue.deinit(self.allocator);
        self.store.deinit();
        self.publisher.deinit();
    }

    pub fn loadCursor(self: *Coordinator, stream_name: []const u8) ?model.Cursor {
        return self.store.loadCursor(stream_name);
    }

    pub fn saveCursor(self: *Coordinator, stream_name: []const u8, cursor: []const u8) !void {
        try self.store.saveCursor(stream_name, cursor);
    }

    pub fn createJob(self: *Coordinator, stream_name: []const u8, cursor_start: []const u8, cursor_end: []const u8) !model.Job {
        return jobs.createJob(self.allocator, stream_name, cursor_start, cursor_end);
    }

    pub fn createBatches(
        self: *Coordinator,
        job_id: []const u8,
        payload_ref: []const u8,
        dedupe_key: []const u8,
        cursor_start: []const u8,
        cursor_end: []const u8,
    ) !std.ArrayList(model.Batch) {
        return jobs.createBatches(self.allocator, job_id, payload_ref, dedupe_key, cursor_start, cursor_end, 1);
    }

    pub fn publishBatch(self: *Coordinator, batch: model.Batch) !void {
        try self.publisher.publishBatch(batch);
    }

    pub fn handleWorkerResult(self: *Coordinator, result: model.WorkerResult) !void {
        if (std.mem.eql(u8, result.status, "success")) {
            return;
        }

        if (!result.retryable) {
            return error.PermanentFailure;
        }

        const removed = self.retry_state.fetchRemove(result.batch_id);
        const previous_attempts = if (removed) |entry| blk: {
            self.allocator.free(entry.key);
            break :blk entry.value.attempts;
        } else 0;

        const next_attempt = previous_attempts + 1;
        if (next_attempt > MAX_RETRIES) {
            std.log.err(
                "event=retry_exhausted batch_id={s} max_retries={d} status=permanent_failure",
                .{ result.batch_id, MAX_RETRIES },
            );
            return error.PermanentFailure;
        }

        const owned_key = try self.allocator.dupe(u8, result.batch_id);
        errdefer self.allocator.free(owned_key);
        const base_backoff_ms = @as(u64, 1000) << @intCast(@min(next_attempt - 1, @as(usize, 5)));
        const jitter_cap = @max(@as(u64, 1), base_backoff_ms / 4);
        const entropy = std.hash.Wyhash.hash(@as(u64, @intCast(next_attempt)), result.batch_id);
        const jitter = entropy % (jitter_cap + 1);
        const backoff_ms = base_backoff_ms + jitter;
        const owned_job_id = try self.allocator.dupe(u8, result.job_id);
        errdefer self.allocator.free(owned_job_id);
        const owned_batch_id = try self.allocator.dupe(u8, result.batch_id);
        errdefer self.allocator.free(owned_batch_id);
        const owned_status = try self.allocator.dupe(u8, result.status);
        errdefer self.allocator.free(owned_status);
        try self.retry_state.put(owned_key, .{
            .attempts = next_attempt,
            .backoff_ms = backoff_ms,
        });
        errdefer {
            _ = self.retry_state.remove(owned_key);
        }
        self.retry_queue.append(self.allocator, .{
            .job_id = owned_job_id,
            .batch_id = owned_batch_id,
            .status = owned_status,
            .retryable = result.retryable,
        }) catch |err| {
            _ = self.retry_state.remove(owned_key);
            return err;
        };
        std.log.info("event=retry_queued batch_id={s} attempt={d} backoff_ms={d} status=retry_scheduled", .{
            result.batch_id,
            next_attempt,
            backoff_ms,
        });
    }

    pub fn markJobDone(self: *Coordinator, job: *model.Job) void {
        _ = self;
        jobs.markJobDone(job);
    }
};

test "load and save cursor" {
    var coordinator = try Coordinator.init(std.testing.allocator);
    defer coordinator.deinit();

    try coordinator.saveCursor("proxy.events", "42");
    const cursor = coordinator.loadCursor("proxy.events").?;
    try std.testing.expectEqualStrings("42", cursor.cursor_value);
}

test "stores cursors for multiple streams" {
    var coordinator = try Coordinator.init(std.testing.allocator);
    defer coordinator.deinit();

    try coordinator.saveCursor("proxy.events", "42");
    try coordinator.saveCursor("wireless.audit", "7");

    const proxy_cursor = coordinator.loadCursor("proxy.events").?;
    const wireless_cursor = coordinator.loadCursor("wireless.audit").?;
    try std.testing.expectEqualStrings("42", proxy_cursor.cursor_value);
    try std.testing.expectEqualStrings("7", wireless_cursor.cursor_value);
}

test "create job, batch, publish, and finish" {
    var coordinator = try Coordinator.init(std.testing.allocator);
    defer coordinator.deinit();

    var job = try coordinator.createJob("proxy.events", "10", "11");
    defer jobs.deinitJob(std.testing.allocator, &job);
    var batches = try coordinator.createBatches(job.job_id, "inline://payload", "dedupe-1", "10", "11");
    defer jobs.deinitBatches(std.testing.allocator, &batches);

    try std.testing.expectEqual(@as(usize, 1), batches.items.len);
    try coordinator.publishBatch(batches.items[0]);
    try std.testing.expectEqual(@as(usize, 1), coordinator.publisher.published.items.len);

    try coordinator.handleWorkerResult(.{
        .job_id = job.job_id,
        .batch_id = batches.items[0].batch_id,
        .status = "success",
        .retryable = false,
    });
    coordinator.markJobDone(&job);
    try std.testing.expectEqualStrings("done", job.status);
}

test "retryable failure is queued" {
    var coordinator = try Coordinator.init(std.testing.allocator);
    defer coordinator.deinit();

    try coordinator.handleWorkerResult(.{
        .job_id = "job-1",
        .batch_id = "batch-1",
        .status = "failed",
        .retryable = true,
    });

    try std.testing.expectEqual(@as(usize, 1), coordinator.retry_queue.items.len);
    const retry_state = coordinator.retry_state.get("batch-1").?;
    try std.testing.expectEqual(@as(usize, 1), retry_state.attempts);
    try std.testing.expect(retry_state.backoff_ms >= 1000);
}
