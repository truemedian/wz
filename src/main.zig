const std = @import("std");

pub const BaseClient = @import("base/client.zig");

test "refAllDecls" {
    std.meta.refAllDecls(@This());
}
