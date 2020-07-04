const std = @import("std");
const Builder = std.build.Builder;
const Pkg = std.build.Pkg;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();

    var tests = b.addTest("src/main.zig");
    tests.setBuildMode(mode);

    tests.addPackage(.{
        .name = "hzzp",
        .path = "lib/hzzp/src/main.zig",
        .dependencies = null,
    });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);

    b.default_step.dependOn(test_step);
}
