const std = @import("std");
const Builder = std.build.Builder;
const Pkg = std.build.Pkg;

const pkgs = @import("deps.zig").pkgs;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();

    var tests = b.addTest("src/main.zig");
    tests.setBuildMode(mode);

    inline for (std.meta.fields(@TypeOf(pkgs))) |field| {
        tests.addPackage(@field(pkgs, field.name));
    }

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);

    b.default_step.dependOn(test_step);
}
