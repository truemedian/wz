const std = @import("std");

pub const base = @import("base/base.zig");

test "refAllDecls" {
    std.testing.refAllDecls(@This());
}
