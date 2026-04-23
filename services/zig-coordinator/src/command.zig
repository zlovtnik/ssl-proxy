const std = @import("std");
const logging = @import("logging.zig");

pub const Result = struct {
    stdout: []u8,
    stderr: []u8,
    term: std.process.Child.Term,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

pub fn exec(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) !Result {
    const run_result = std.process.run(allocator, io, .{
        .argv = argv,
        .expand_arg0 = .expand,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch |err| {
        const cmd_name = if (argv.len > 0) argv[0] else "<empty>";
        logging.err().stringSafe("event", "command_failure").string("command", cmd_name).err(err).log();
        return err;
    };

    return .{
        .stdout = run_result.stdout,
        .stderr = run_result.stderr,
        .term = run_result.term,
    };
}

pub fn isSuccess(result: Result) bool {
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

pub fn exitCode(result: Result) ?u8 {
    return switch (result.term) {
        .exited => |code| code,
        else => null,
    };
}

pub fn logFailure(command_name: []const u8, result: Result) void {
    var stderr_buffer: [256]u8 = undefined;
    const stderr_snippet = sanitizeSnippet(&stderr_buffer, result.stderr);

    if (exitCode(result)) |code| {
        logging.err()
            .stringSafe("event", "command_failure")
            .string("command", command_name)
            .int("exit_code", code)
            .string("stderr", stderr_snippet)
            .log();
        return;
    }

    logging.err()
        .stringSafe("event", "command_failure")
        .string("command", command_name)
        .stringSafe("error", "terminated_unexpectedly")
        .string("stderr", stderr_snippet)
        .log();
}

pub fn logOutput(command_name: []const u8, stdout: []const u8) void {
    const output = trimmedOutput(stdout);
    if (output.len == 0) return;

    var output_buffer: [256]u8 = undefined;
    const snippet = sanitizeSnippet(&output_buffer, output);
    logging.debug()
        .stringSafe("event", "command_output")
        .string("command", command_name)
        .string("stdout", snippet)
        .log();
}

pub fn trimmedOutput(stdout: []const u8) []const u8 {
    return std.mem.trim(u8, stdout, " \t\r\n");
}

fn sanitizeSnippet(buffer: []u8, raw: []const u8) []const u8 {
    var in_index: usize = 0;
    var out_index: usize = 0;

    while (in_index < raw.len and out_index < buffer.len) : (in_index += 1) {
        const byte = raw[in_index];
        buffer[out_index] = switch (byte) {
            '\n', '\r', '\t' => ' ',
            else => byte,
        };
        out_index += 1;
    }

    return std.mem.trim(u8, buffer[0..out_index], " ");
}
