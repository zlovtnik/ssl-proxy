const std = @import("std");
const model = @import("state.zig");

var next_id = std.atomic.Value(u64).init(1);

fn generateOwnedId(
    allocator: std.mem.Allocator,
    prefix: []const u8,
    disambiguator: usize,
) ![]const u8 {
    const id = next_id.fetchAdd(1, .monotonic);
    return std.fmt.allocPrint(allocator, "{s}-{d}-{d}", .{ prefix, id, disambiguator });
}

pub fn createJob(
    allocator: std.mem.Allocator,
    stream_name: []const u8,
    cursor_start: []const u8,
    cursor_end: []const u8,
) !model.Job {
    return .{
        .job_id = try generateOwnedId(allocator, "job", 0),
        .stream_name = stream_name,
        .cursor_start = cursor_start,
        .cursor_end = cursor_end,
        .status = "pending",
    };
}

pub fn createBatches(
    allocator: std.mem.Allocator,
    job_id: []const u8,
    payload_ref: []const u8,
    dedupe_key: []const u8,
    cursor_start: []const u8,
    cursor_end: []const u8,
    batch_size: usize,
) !std.ArrayList(model.Batch) {
    var batches = try std.ArrayList(model.Batch).initCapacity(allocator, batch_size);
    var batch_no: usize = 0;
    while (batch_no < batch_size) : (batch_no += 1) {
        try batches.append(allocator, .{
            .batch_id = try generateOwnedId(allocator, "batch", batch_no),
            .job_id = job_id,
            .batch_no = batch_no,
            .payload_ref = payload_ref,
            .dedupe_key = dedupe_key,
            .cursor_start = cursor_start,
            .cursor_end = cursor_end,
            .status = "pending",
        });
        if (batch_size == 1) break;
    }
    return batches;
}

pub fn markJobDone(job: *model.Job) void {
    job.status = "done";
}

pub fn deinitJob(allocator: std.mem.Allocator, job: *model.Job) void {
    allocator.free(job.job_id);
}

pub fn deinitBatches(allocator: std.mem.Allocator, batches: *std.ArrayList(model.Batch)) void {
    for (batches.items) |batch| {
        allocator.free(batch.batch_id);
    }
    batches.deinit(allocator);
}
