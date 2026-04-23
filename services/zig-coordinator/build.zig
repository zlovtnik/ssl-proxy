const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe = addCoordinatorExecutable(b, target, optimize);
    b.installArtifact(exe);

    const unit_tests = addCoordinatorTests(b, target, optimize);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run coordinator unit tests");
    test_step.dependOn(&run_unit_tests.step);
}

fn addCoordinatorExecutable(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const logz_dep = b.dependency("logz", .{
        .target = target,
        .optimize = optimize,
    });
    if (@hasField(std.Build.ExecutableOptions, "root_module")) {
        const root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        root_module.addImport("logz", logz_dep.module("logz"));
        return b.addExecutable(.{
            .name = "zig-coordinator",
            .root_module = root_module,
        });
    }

    const exe = b.addExecutable(.{
        .name = "zig-coordinator",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe.root_module.addImport("logz", logz_dep.module("logz"));
    return exe;
}

fn addCoordinatorTests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const logz_dep = b.dependency("logz", .{
        .target = target,
        .optimize = optimize,
    });
    if (@hasField(std.Build.TestOptions, "root_module")) {
        const test_module = b.createModule(.{
            .root_source_file = b.path("src/scheduler.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_module.addImport("logz", logz_dep.module("logz"));
        return b.addTest(.{
            .root_module = test_module,
        });
    }

    const tests = b.addTest(.{
        .root_source_file = b.path("src/scheduler.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    tests.root_module.addImport("logz", logz_dep.module("logz"));
    return tests;
}
