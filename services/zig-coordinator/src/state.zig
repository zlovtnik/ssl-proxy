const std = @import("std");

pub const Cursor = struct {
    stream_name: []const u8,
    cursor_value: []const u8,
};

pub const Job = struct {
    job_id: []const u8,
    stream_name: []const u8,
    cursor_start: []const u8,
    cursor_end: []const u8,
    status: []const u8,
};

pub const Batch = struct {
    batch_id: []const u8,
    job_id: []const u8,
    batch_no: usize,
    payload_ref: []const u8,
    dedupe_key: []const u8,
    cursor_start: []const u8,
    cursor_end: []const u8,
    status: []const u8,
};

pub const WorkerResult = struct {
    job_id: []const u8,
    batch_id: []const u8,
    status: []const u8,
    retryable: bool,
};
