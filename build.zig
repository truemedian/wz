const std = @import("std");
const Builder = std.build.Builder;
const Pkg = std.build.Pkg;

const packages = @import("deps.zig");

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();

    var tests = b.addTest("src/main.zig");
    tests.setBuildMode(mode);

    if (@hasDecl(packages, "addAllTo")) { // zigmod
        packages.addAllTo(lib_tests);
    } else { // zkg
        inline for (std.meta.fields(@TypeOf(packages.pkgs))) |field| {
            lib_tests.addPackage(@field(packages.pkgs, field.name));
        }
    }

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&tests.step);

    b.default_step.dependOn(test_step);
}
