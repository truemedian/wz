const std = @import("std");
const Builder = std.build.Builder;
const Pkg = std.build.Pkg;

const packages = @import("deps.zig");

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();

    var tests = b.addTest("src/main.zig");
    tests.setBuildMode(mode);

    if (@hasDecl(packages, "addAllTo")) {
        packages.addAllTo(tests);
    } else {
        packages.pkgs.addAllTo(tests);
    }

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);
}
